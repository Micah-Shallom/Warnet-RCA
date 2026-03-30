#!/usr/bin/env python3

"""
Test scenario: Bob's HTLC-timeout transaction.

Creates the HTLC output (2-of-2 multisig), then builds and broadcasts
Bob's timeout transaction that spends it. This is the transaction that
Mallory will later try to evict from the mempool via RBF.

Run: warnet run scenarios/test_htlc_timeout.py --debug

Assertions:
  - htlc_timeout is fully signed with both keys
  - htlc_timeout is in the mempool after broadcast
  - htlc_timeout spends the HTLC output
  - htlc_timeout signals RBF
"""

import hashlib
from typing import Dict, Tuple

from commander import Commander
from test_framework.test_node import TestNode
from test_framework.key import ECKey


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
    return addr


def fund_participants(
    alice: TestNode, bob: TestNode, mallory: TestNode,
    miner_addr: str, amount: float = 10.0,
) -> Tuple[str, str]:
    """Send coins from Alice to Bob and Mallory, then confirm."""
    bob_addr: str = bob.getnewaddress()
    mallory_addr: str = mallory.getnewaddress()
    alice.sendtoaddress(bob_addr, amount)
    alice.sendtoaddress(mallory_addr, amount)
    alice.rpc.generatetoaddress(1, miner_addr)
    return bob_addr, mallory_addr


# ---------------------------------------------------------------------------
# Helpers — key generation and WIF encoding
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[ECKey, str]:
    """Generate a fresh EC keypair. Returns (eckey, pubkey_hex)."""
    key: ECKey = ECKey()
    key.generate(compressed=True)
    pubkey_hex: str = key.get_pubkey().get_bytes().hex()
    return key, pubkey_hex


def eckey_to_wif(key: ECKey, testnet: bool = True) -> str:
    """Convert an ECKey to WIF format for signrawtransactionwithkey."""
    prefix: bytes = b'\xef' if testnet else b'\x80'
    privkey_bytes: bytes = key.get_bytes()
    extended: bytes = prefix + privkey_bytes + b'\x01'  # compressed flag
    checksum: bytes = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return _base58_encode(extended + checksum)


def _base58_encode(data: bytes) -> str:
    """Base58 encode bytes."""
    alphabet: str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num: int = int.from_bytes(data, 'big')
    result: str = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        result = alphabet[remainder] + result
    for byte in data:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result


# ---------------------------------------------------------------------------
# Helpers — HTLC output creation
# ---------------------------------------------------------------------------

def create_htlc_output(
    alice: TestNode, miner_addr: str, htlc_amount: float = 1.0,
) -> Dict[str, object]:
    """
    Create a 2-of-2 multisig UTXO (HTLC output) with fresh keypairs.
    Uses signrawtransactionwithkey for signing (no wallet involvement).
    """
    bob_key, bob_pubkey = generate_keypair()
    mallory_key, mallory_pubkey = generate_keypair()
    bob_wif: str = eckey_to_wif(bob_key)
    mallory_wif: str = eckey_to_wif(mallory_key)

    multisig: dict = alice.createmultisig(2, [bob_pubkey, mallory_pubkey])

    htlc_txid: str = alice.sendtoaddress(multisig["address"], htlc_amount)
    alice.rpc.generatetoaddress(1, miner_addr)

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
        "redeem_script": multisig["redeemScript"],
        "multisig_address": multisig["address"],
        "bob_pubkey": bob_pubkey,
        "mallory_pubkey": mallory_pubkey,
        "bob_wif": bob_wif,
        "mallory_wif": mallory_wif,
    }


# ---------------------------------------------------------------------------
# Helpers — HTLC-timeout transaction
# ---------------------------------------------------------------------------

def create_htlc_timeout(
    node: TestNode,
    htlc: Dict[str, object],
    dest_address: str,
    fee_rate_sat_vb: int = 2,
) -> Dict[str, object]:
    """
    Create Bob's HTLC-timeout transaction. Spends the HTLC output to
    Bob's address using the 2-of-2 multisig (both keys sign).

    In reality this would be pre-signed during channel setup. Here we
    simulate it by signing with both WIF keys via signrawtransactionwithkey.

    CRITICAL: Must signal RBF (nSequence < 0xFFFFFFFE).

    Returns:
        dict with htlc_timeout_hex, htlc_timeout_txid, htlc_timeout_fee
    """
    # Estimate fee (~300 vbytes for multisig input)
    tx_size_vb: int = 300
    fee_btc: float = (fee_rate_sat_vb * tx_size_vb) / 1e8

    inputs: list = [{
        "txid": htlc["htlc_txid"],
        "vout": htlc["htlc_vout"],
        "sequence": 0xFFFFFFFD,  # RBF signal
    }]
    outputs: dict = {
        dest_address: round(htlc["htlc_amount"] - fee_btc, 8)
    }

    raw_hex: str = node.createrawtransaction(inputs, outputs)

    prevtxs: list = [{
        "txid": htlc["htlc_txid"],
        "vout": htlc["htlc_vout"],
        "scriptPubKey": htlc["htlc_scriptPubKey"],
        "redeemScript": htlc["redeem_script"],
        "amount": htlc["htlc_amount"],
    }]

    # Sign with both keys (simulating pre-signed commitment)
    signed: dict = node.signrawtransactionwithkey(
        raw_hex,
        [htlc["bob_wif"], htlc["mallory_wif"]],
        prevtxs,
    )
    assert signed["complete"], f"htlc_timeout signing failed: {signed.get('errors')}"

    return {
        "htlc_timeout_hex": signed["hex"],
        "htlc_timeout_fee": fee_btc,
        "htlc_timeout_fee_rate": fee_rate_sat_vb,
    }


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------

class TestHTLCTimeout(Commander):

    def set_test_params(self) -> None:
        self.num_nodes = 3

    def add_options(self, parser) -> None:
        parser.description = "Test Bob's HTLC-timeout transaction"
        parser.usage = "warnet run /path/to/test_htlc_timeout.py"

    def run_test(self) -> None:
        self.log.info("Waiting for L1 p2p network connections...")
        self.wait_for_tanks_connected()

        alice: TestNode = self.nodes[0]
        bob: TestNode = self.nodes[1]
        mallory: TestNode = self.nodes[2]

        # --- Setup ---
        self.log.info("Setting up wallets and funding...")
        setup_wallets(alice, bob, mallory)
        miner_addr: str = fund_miner(alice, blocks=101)
        fund_participants(alice, bob, mallory, miner_addr, amount=10.0)

        # --- Create HTLC output ---
        htlc_amount: float = 1.0
        self.log.info(f"Creating HTLC output ({htlc_amount} BTC)...")
        htlc: dict = create_htlc_output(alice, miner_addr, htlc_amount=htlc_amount)
        self.log.info(f"HTLC output: {htlc['htlc_txid'][:16]}...:{htlc['htlc_vout']}")

        # --- Create and broadcast htlc_timeout ---
        bob_dest: str = bob.getnewaddress()
        self.log.info("Creating Bob's HTLC-timeout transaction...")
        timeout: dict = create_htlc_timeout(bob, htlc, bob_dest, fee_rate_sat_vb=2)
        self.log.info(f"htlc_timeout fee: {timeout['htlc_timeout_fee']} BTC ({timeout['htlc_timeout_fee_rate']} sat/vB)")

        self.log.info("Broadcasting htlc_timeout...")
        timeout_txid: str = bob.sendrawtransaction(timeout["htlc_timeout_hex"])
        self.log.info(f"htlc_timeout txid: {timeout_txid}")

        # --- Assertions ---

        # 1. htlc_timeout is in Bob's mempool
        bob_mempool: list = bob.getrawmempool()
        assert timeout_txid in bob_mempool, "htlc_timeout not in Bob's mempool"
        self.log.info("htlc_timeout is in Bob's mempool")

        # 2. Propagated to all nodes
        self.sync_all()
        alice_mempool: list = alice.getrawmempool()
        mallory_mempool: list = mallory.getrawmempool()
        assert timeout_txid in alice_mempool, "htlc_timeout not in Alice's mempool"
        assert timeout_txid in mallory_mempool, "htlc_timeout not in Mallory's mempool"
        self.log.info("htlc_timeout propagated to all nodes")

        # 3. Verify it spends the HTLC output
        decoded: dict = bob.decoderawtransaction(timeout["htlc_timeout_hex"])
        assert decoded["vin"][0]["txid"] == htlc["htlc_txid"], "Wrong input txid"
        assert decoded["vin"][0]["vout"] == htlc["htlc_vout"], "Wrong input vout"
        self.log.info("htlc_timeout spends the correct HTLC output")

        # 4. Verify RBF signaling
        sequence: int = decoded["vin"][0]["sequence"]
        assert sequence < 0xFFFFFFFE, f"htlc_timeout does not signal RBF: {hex(sequence)}"
        self.log.info(f"htlc_timeout signals RBF: nSequence={hex(sequence)}")

        # 5. Clean up: mine a block to confirm htlc_timeout
        self.log.info("Mining a block to confirm htlc_timeout...")
        alice.rpc.generatetoaddress(1, miner_addr)
        self.sync_all()
        assert len(bob.getrawmempool()) == 0, "Mempool should be empty after mining"
        self.log.info("htlc_timeout confirmed in a block")

        # --- Summary ---
        self.log.info("========================================")
        self.log.info("  TEST HTLC TIMEOUT — ALL ASSERTIONS PASSED")
        self.log.info("========================================")
        self.log.info(f"  HTLC output:    {htlc['htlc_txid'][:16]}...:{htlc['htlc_vout']}")
        self.log.info(f"  htlc_timeout:   {timeout_txid[:16]}...")
        self.log.info(f"  Fee:            {timeout['htlc_timeout_fee']} BTC")
        self.log.info(f"  RBF:            nSequence={hex(sequence)}")
        self.log.info(f"  Mempool:        propagated + confirmed")
        self.log.info("========================================")


def main():
    TestHTLCTimeout().main()


if __name__ == "__main__":
    main()
