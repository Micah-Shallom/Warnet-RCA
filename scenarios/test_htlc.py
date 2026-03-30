#!/usr/bin/env python3

"""
Test scenario: Simulated HTLC output creation via 2-of-2 multisig.

Run: warnet run scenarios/test_htlc.py --debug
"""

from typing import Dict, Tuple

from commander import Commander
from test_framework.test_node import TestNode
from test_framework.key import ECKey
from test_framework.address import key_to_p2wpkh


# ---------------------------------------------------------------------------
# Helpers — wallet creation and funding
# ---------------------------------------------------------------------------

def setup_wallets(alice: TestNode, bob: TestNode, mallory: TestNode) -> None:
    """Create wallets on all three nodes. Idempotent — safe to call twice."""
    for node, name in [(alice, "alice"), (bob, "bob"), (mallory, "mallory")]:
        wallets = node.listwallets()
        if name not in wallets:
            node.createwallet(name, descriptors=True)


def fund_miner(alice: TestNode, blocks: int = 101) -> str:
    """Mine blocks so Alice has spendable coins. Returns miner address."""
    addr: str = alice.getnewaddress()
    alice.rpc.generatetoaddress(blocks, addr)
    balance: float = alice.getbalance()
    assert balance > 0, f"Alice has no balance after mining {blocks} blocks"
    return addr


def fund_participants(
    alice: TestNode,
    bob: TestNode,
    mallory: TestNode,
    miner_addr: str,
    amount: float = 10.0,
) -> Tuple[str, str]:
    """Send coins from Alice to Bob and Mallory, then confirm."""
    bob_addr: str = bob.getnewaddress()
    mallory_addr: str = mallory.getnewaddress()

    alice.sendtoaddress(bob_addr, amount)
    alice.sendtoaddress(mallory_addr, amount)

    alice.rpc.generatetoaddress(1, miner_addr)

    assert bob.getbalance() >= amount, "Bob was not funded"
    assert mallory.getbalance() >= amount, "Mallory was not funded"

    return bob_addr, mallory_addr


# ---------------------------------------------------------------------------
# Helpers — key generation
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[ECKey, str]:
    """
    Generate a fresh EC keypair.

    Returns:
        (eckey, pubkey_hex): ECKey object and compressed public key hex string
    """
    key: ECKey = ECKey()
    key.generate(compressed=True)
    pubkey_hex: str = key.get_pubkey().get_bytes().hex()
    return key, pubkey_hex


def eckey_to_wif(key: ECKey, testnet: bool = True) -> str:
    """
    Convert an ECKey to WIF (Wallet Import Format) for use with
    signrawtransactionwithkey.

    Args:
        key: ECKey with private key
        testnet: if True, use testnet/regtest prefix (0xEF), else mainnet (0x80)
    """
    import hashlib
    prefix: bytes = b'\xef' if testnet else b'\x80'
    privkey_bytes: bytes = key.get_bytes()
    # Compressed key flag
    extended: bytes = prefix + privkey_bytes + b'\x01'
    # Double SHA256 checksum
    checksum: bytes = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    import base64
    # Base58 encode
    return _base58_encode(extended + checksum)


def _base58_encode(data: bytes) -> str:
    """Base58 encode bytes."""
    alphabet: str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num: int = int.from_bytes(data, 'big')
    result: str = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        result = alphabet[remainder] + result
    # Handle leading zeros
    for byte in data:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result


# ---------------------------------------------------------------------------
# Helpers — HTLC output creation and multisig signing
# ---------------------------------------------------------------------------

def create_htlc_output(
    alice: TestNode,
    miner_addr: str,
    htlc_amount: float = 1.0,
) -> Dict[str, object]:
    """
    Create a 2-of-2 multisig UTXO representing the HTLC output.

    Generates fresh keypairs (not from any wallet) and creates the multisig
    from those keys. Signing uses signrawtransactionwithkey with the WIF
    private keys, bypassing wallet descriptor limitations entirely.

    Returns:
        dict with HTLC output details + keypairs for signing
    """
    # 1. Generate fresh keypairs for Bob and Mallory
    bob_key, bob_pubkey = generate_keypair()
    mallory_key, mallory_pubkey = generate_keypair()

    bob_wif: str = eckey_to_wif(bob_key)
    mallory_wif: str = eckey_to_wif(mallory_key)

    # 2. Create 2-of-2 multisig using any node (just needs the RPC)
    multisig: dict = alice.createmultisig(2, [bob_pubkey, mallory_pubkey])
    multisig_address: str = multisig["address"]
    redeem_script: str = multisig["redeemScript"]

    # 3. Fund the multisig from Alice
    htlc_txid: str = alice.sendtoaddress(multisig_address, htlc_amount)

    # 4. Mine to confirm
    alice.rpc.generatetoaddress(1, miner_addr)

    # 5. Find the vout and scriptPubKey
    wallet_tx: dict = alice.gettransaction(htlc_txid)
    decoded: dict = alice.decoderawtransaction(wallet_tx["hex"])
    htlc_vout: int = None
    htlc_scriptPubKey: str = None
    for vout in decoded["vout"]:
        if abs(float(vout["value"]) - htlc_amount) < 0.0001:
            htlc_vout = vout["n"]
            htlc_scriptPubKey = vout["scriptPubKey"]["hex"]
            break
    assert htlc_vout is not None, "Could not find HTLC output in funding tx"

    return {
        "htlc_txid": htlc_txid,
        "htlc_vout": htlc_vout,
        "htlc_amount": htlc_amount,
        "htlc_scriptPubKey": htlc_scriptPubKey,
        "redeem_script": redeem_script,
        "multisig_address": multisig_address,
        "bob_pubkey": bob_pubkey,
        "mallory_pubkey": mallory_pubkey,
        "bob_wif": bob_wif,
        "mallory_wif": mallory_wif,
    }


def sign_multisig_spend(
    node: TestNode,
    raw_hex: str,
    htlc: Dict[str, object],
    privkeys: list = None,
) -> str:
    """
    Sign a raw transaction spending the 2-of-2 multisig HTLC output.

    Uses signrawtransactionwithkey with both WIF private keys and the
    redeemScript in prevtxs. Any node can be used since we're providing
    the keys explicitly.

    Returns:
        Fully signed raw transaction hex.
    """
    if privkeys is None:
        privkeys = [htlc["bob_wif"], htlc["mallory_wif"]]

    prevtxs: list = [{
        "txid": htlc["htlc_txid"],
        "vout": htlc["htlc_vout"],
        "scriptPubKey": htlc["htlc_scriptPubKey"],
        "redeemScript": htlc["redeem_script"],
        "amount": htlc["htlc_amount"],
    }]

    signed: dict = node.signrawtransactionwithkey(raw_hex, privkeys, prevtxs)

    if not signed["complete"]:
        raise RuntimeError(
            f"Multisig signing not complete. Errors: {signed.get('errors')}"
        )

    return signed["hex"]


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------

class TestHTLC(Commander):

    def set_test_params(self) -> None:
        self.num_nodes = 3

    def add_options(self, parser) -> None:
        parser.description = "Test HTLC output creation via 2-of-2 multisig"
        parser.usage = "warnet run /path/to/test_htlc.py"

    def run_test(self) -> None:
        self.log.info("Waiting for L1 p2p network connections...")
        self.wait_for_tanks_connected()

        alice: TestNode = self.nodes[0]
        bob: TestNode = self.nodes[1]
        mallory: TestNode = self.nodes[2]

        # --- Setup: wallets and funding ---
        self.log.info("Setting up wallets and funding...")
        setup_wallets(alice, bob, mallory)
        miner_addr: str = fund_miner(alice, blocks=101)
        fund_participants(alice, bob, mallory, miner_addr, amount=10.0)

        # --- Create HTLC output ---
        htlc_amount: float = 1.0
        self.log.info(f"Creating HTLC output ({htlc_amount} BTC in 2-of-2 multisig)...")
        htlc: dict = create_htlc_output(alice, miner_addr, htlc_amount=htlc_amount)

        self.log.info(f"HTLC txid: {htlc['htlc_txid']}")
        self.log.info(f"HTLC vout: {htlc['htlc_vout']}")
        self.log.info(f"HTLC scriptPubKey: {htlc['htlc_scriptPubKey']}")
        self.log.info(f"Redeem script: {htlc['redeem_script']}")
        self.log.info(f"Multisig address: {htlc['multisig_address']}")

        # --- Assertions ---

        # 1. Funding tx is confirmed
        wallet_tx: dict = alice.gettransaction(htlc["htlc_txid"])
        confirmations: int = wallet_tx.get("confirmations", 0)
        self.log.info(f"HTLC funding tx confirmations: {confirmations}")
        assert confirmations >= 1, "HTLC funding tx not confirmed"

        # 2. Output amount matches
        decoded: dict = alice.decoderawtransaction(wallet_tx["hex"])
        htlc_output: dict = decoded["vout"][htlc["htlc_vout"]]
        assert abs(float(htlc_output["value"]) - htlc_amount) < 0.0001, "Amount mismatch"

        # 3. Test signing with both keys
        self.log.info("Testing multisig signing with signrawtransactionwithkey...")
        bob_dest: str = bob.getnewaddress()
        fee: float = 0.0001
        raw_hex: str = alice.createrawtransaction(
            [{"txid": htlc["htlc_txid"], "vout": htlc["htlc_vout"], "sequence": 0xFFFFFFFD}],
            {bob_dest: round(htlc_amount - fee, 8)},
        )

        signed_hex: str = sign_multisig_spend(alice, raw_hex, htlc)
        self.log.info("Multisig signing complete — both keys signed successfully")

        # 4. Test partial signing (Bob only, then Mallory completes)
        self.log.info("Testing partial signing (Bob first, Mallory completes)...")
        bob_only: dict = alice.signrawtransactionwithkey(
            raw_hex,
            [htlc["bob_wif"]],
            [{
                "txid": htlc["htlc_txid"],
                "vout": htlc["htlc_vout"],
                "scriptPubKey": htlc["htlc_scriptPubKey"],
                "redeemScript": htlc["redeem_script"],
                "amount": htlc["htlc_amount"],
            }],
        )
        self.log.info(f"Bob only: complete={bob_only['complete']}")
        assert not bob_only["complete"], "Should need both signatures"

        mallory_completes: dict = alice.signrawtransactionwithkey(
            bob_only["hex"],
            [htlc["mallory_wif"]],
            [{
                "txid": htlc["htlc_txid"],
                "vout": htlc["htlc_vout"],
                "scriptPubKey": htlc["htlc_scriptPubKey"],
                "redeemScript": htlc["redeem_script"],
                "amount": htlc["htlc_amount"],
            }],
        )
        self.log.info(f"Mallory completes: complete={mallory_completes['complete']}")
        assert mallory_completes["complete"], (
            f"Partial signing failed: {mallory_completes.get('errors')}"
        )

        self.log.info("Partial signing works — Bob signs, Mallory completes")

        # --- Summary ---
        self.log.info("========================================")
        self.log.info("  TEST HTLC — ALL ASSERTIONS PASSED")
        self.log.info("========================================")
        self.log.info(f"  HTLC output: {htlc['htlc_txid'][:16]}...:{htlc['htlc_vout']}")
        self.log.info(f"  Amount:      {htlc['htlc_amount']} BTC")
        self.log.info(f"  Confirmed:   {confirmations} blocks")
        self.log.info(f"  Full signing:    WORKS")
        self.log.info(f"  Partial signing: WORKS")
        self.log.info("========================================")


def main():
    TestHTLC().main()


if __name__ == "__main__":
    main()
