#!/usr/bin/env python3

"""
Test scenario: Box M (planted input) and M-child creation.

Box M is a confirmed UTXO that Mallory controls. Before each attack cycle,
Mallory creates m_child (a transaction spending Box M) so that Box M is
"pre-spent" in the mempool. This is what creates the RBF conflict when
Mallory later broadcasts htlc_preimage (which also spends Box M).

Without Box M, the attack does not work.

Run: warnet run scenarios/test_box_m.py --debug

Assertions:
  - Box M is a confirmed UTXO (1+ confirmations)
  - After broadcasting m_child, it appears in all nodes' mempools
  - Box M is now "spent" in the mempool
  - m_child signals RBF (nSequence < 0xFFFFFFFE)
"""

from typing import Dict, Tuple

from commander import Commander
from test_framework.test_node import TestNode


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
# Helpers — Box M and M-child
# ---------------------------------------------------------------------------

def create_box_m(
    alice: TestNode,
    mallory: TestNode,
    miner_addr: str,
    amount: float = 0.1,
) -> Dict[str, object]:
    """
    Create a confirmed UTXO that Mallory controls (Box M).

    Box M is funded by Alice and confirmed in a block. It will later be
    used as the "planted input" in Mallory's htlc_preimage transaction.

    Returns:
        dict with box_m_txid, box_m_vout, box_m_amount, box_m_address,
        box_m_scriptPubKey
    """
    mallory_addr: str = mallory.getnewaddress()

    # Alice funds Box M
    box_m_txid: str = alice.sendtoaddress(mallory_addr, amount)

    # Confirm it
    alice.rpc.generatetoaddress(1, miner_addr)

    # Find the vout and scriptPubKey
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
        "box_m_txid": box_m_txid,
        "box_m_vout": box_m_vout,
        "box_m_amount": box_m_amount,
        "box_m_address": mallory_addr,
        "box_m_scriptPubKey": box_m_scriptPubKey,
    }


def create_m_child(
    mallory: TestNode,
    box_m: Dict[str, object],
    fee_rate_sat_vb: int = 1,
) -> Dict[str, str]:
    """
    Create and broadcast m_child — a transaction that spends Box M.
    This must be in the mempool BEFORE htlc_preimage is broadcast.

    CRITICAL: m_child must signal RBF (nSequence < 0xFFFFFFFE).

    Returns:
        dict with m_child_txid, m_child_hex
    """
    mallory_change_addr: str = mallory.getnewaddress()

    # Calculate fee (approximate — 1 input, 1 output, ~150 vbytes)
    tx_size_vb: int = 150
    fee_btc: float = (fee_rate_sat_vb * tx_size_vb) / 1e8

    # Create raw transaction with RBF signaling
    inputs: list = [{
        "txid": box_m["box_m_txid"],
        "vout": box_m["box_m_vout"],
        "sequence": 0xFFFFFFFD,  # CRITICAL: RBF signal
    }]
    outputs: dict = {
        mallory_change_addr: round(box_m["box_m_amount"] - fee_btc, 8)
    }

    raw_hex: str = mallory.createrawtransaction(inputs, outputs)
    signed: dict = mallory.signrawtransactionwithwallet(raw_hex)
    assert signed["complete"], f"m_child signing failed: {signed.get('errors')}"

    m_child_txid: str = mallory.sendrawtransaction(signed["hex"])

    return {
        "m_child_txid": m_child_txid,
        "m_child_hex": signed["hex"],
    }


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------

class TestBoxM(Commander):

    def set_test_params(self) -> None:
        self.num_nodes = 3

    def add_options(self, parser) -> None:
        parser.description = "Test Box M and M-child creation"
        parser.usage = "warnet run /path/to/test_box_m.py"

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

        # --- Create Box M ---
        self.log.info("Creating Box M (planted input for Mallory)...")
        box_m: dict = create_box_m(alice, mallory, miner_addr, amount=0.1)

        self.log.info(f"Box M txid: {box_m['box_m_txid']}")
        self.log.info(f"Box M vout: {box_m['box_m_vout']}")
        self.log.info(f"Box M amount: {box_m['box_m_amount']} BTC")
        self.log.info(f"Box M address: {box_m['box_m_address']}")

        # --- Assertions: Box M ---

        # 1. Box M is confirmed
        wallet_tx: dict = alice.gettransaction(box_m["box_m_txid"])
        confirmations: int = wallet_tx.get("confirmations", 0)
        self.log.info(f"Box M confirmations: {confirmations}")
        assert confirmations >= 1, "Box M not confirmed"

        # 2. Box M is in Mallory's unspent set
        mallory_unspent: list = mallory.listunspent()
        box_m_found: bool = any(
            u["txid"] == box_m["box_m_txid"] and u["vout"] == box_m["box_m_vout"]
            for u in mallory_unspent
        )
        assert box_m_found, "Box M not found in Mallory's unspent outputs"
        self.log.info("Box M is confirmed and in Mallory's UTXO set")

        # --- Create M-child ---
        self.log.info("Creating and broadcasting m_child (spends Box M)...")
        m_child: dict = create_m_child(mallory, box_m, fee_rate_sat_vb=1)

        self.log.info(f"m_child txid: {m_child['m_child_txid']}")

        # --- Assertions: M-child ---

        # 3. m_child is in Mallory's mempool
        mallory_mempool: list = mallory.getrawmempool()
        assert m_child["m_child_txid"] in mallory_mempool, (
            "m_child not in Mallory's mempool"
        )
        self.log.info("m_child is in Mallory's mempool")

        # 4. Wait for propagation, then check all nodes
        self.sync_all()
        alice_mempool: list = alice.getrawmempool()
        bob_mempool: list = bob.getrawmempool()
        assert m_child["m_child_txid"] in alice_mempool, "m_child not in Alice's mempool"
        assert m_child["m_child_txid"] in bob_mempool, "m_child not in Bob's mempool"
        self.log.info("m_child propagated to all nodes")

        # 5. Box M is no longer in Mallory's unspent set (spent by m_child)
        mallory_unspent_after: list = mallory.listunspent()
        box_m_still_unspent: bool = any(
            u["txid"] == box_m["box_m_txid"] and u["vout"] == box_m["box_m_vout"]
            for u in mallory_unspent_after
        )
        assert not box_m_still_unspent, "Box M should be spent by m_child but still shows as unspent"
        self.log.info("Box M is now spent in the mempool (by m_child)")

        # 6. Verify RBF signaling by decoding m_child
        decoded: dict = mallory.decoderawtransaction(m_child["m_child_hex"])
        sequence: int = decoded["vin"][0]["sequence"]
        self.log.info(f"m_child nSequence: {hex(sequence)}")
        assert sequence < 0xFFFFFFFE, (
            f"m_child does not signal RBF: nSequence={hex(sequence)}"
        )
        self.log.info("m_child signals RBF correctly")

        # --- Summary ---
        self.log.info("========================================")
        self.log.info("  TEST BOX M — ALL ASSERTIONS PASSED")
        self.log.info("========================================")
        self.log.info(f"  Box M:    {box_m['box_m_txid'][:16]}...:{box_m['box_m_vout']}")
        self.log.info(f"  Amount:   {box_m['box_m_amount']} BTC")
        self.log.info(f"  m_child:  {m_child['m_child_txid'][:16]}...")
        self.log.info(f"  RBF:      nSequence={hex(sequence)}")
        self.log.info(f"  Mempool:  propagated to all 3 nodes")
        self.log.info("========================================")


def main():
    TestBoxM().main()


if __name__ == "__main__":
    main()
