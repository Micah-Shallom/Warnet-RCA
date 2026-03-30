#!/usr/bin/env python3

"""
Test scenario: Wallet creation and funding verification.

This scenario does nothing except set up wallets and verify funding.
It validates that the Warnet network is operational and that basic
wallet operations work correctly before building attack transactions.

Run: warnet run scenarios/test_funding.py --debug

Assertions:
  - Alice has a balance > 50 BTC (from mining)
  - Bob has a balance of exactly 10 BTC
  - Mallory has a balance of exactly 10 BTC
  - All three nodes see the same block height
"""

from commander import Commander


# ---------------------------------------------------------------------------
# Helpers — wallet creation and funding
# ---------------------------------------------------------------------------

def setup_wallets(alice, bob, mallory):
    """Create wallets on all three nodes. Idempotent — safe to call twice."""
    for node, name in [(alice, "alice"), (bob, "bob"), (mallory, "mallory")]:
        wallets = node.listwallets()
        if name not in wallets:
            node.createwallet(name, descriptors=True)


def fund_miner(alice, blocks=101):
    """
    Mine blocks so Alice has spendable coins.

    Coinbase outputs require 100 blocks of maturity on regtest before
    they can be spent. Mining 101 blocks gives Alice at least one
    spendable coinbase output.

    Returns:
        miner_addr: Alice's address that received the mining rewards
    """
    addr = alice.getnewaddress()
    alice.rpc.generatetoaddress(blocks, addr)
    balance = alice.getbalance()
    assert balance > 0, f"Alice has no balance after mining {blocks} blocks"
    return addr


def fund_participants(alice, bob, mallory, miner_addr, amount=10.0):
    """
    Send coins from Alice to Bob and Mallory, then confirm.

    Returns:
        (bob_addr, mallory_addr): the funded addresses
    """
    bob_addr = bob.getnewaddress()
    mallory_addr = mallory.getnewaddress()

    alice.sendtoaddress(bob_addr, amount)
    alice.sendtoaddress(mallory_addr, amount)

    # Confirm the funding transactions
    alice.rpc.generatetoaddress(1, miner_addr)

    assert bob.getbalance() >= amount, "Bob was not funded"
    assert mallory.getbalance() >= amount, "Mallory was not funded"

    return bob_addr, mallory_addr


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------

class TestFunding(Commander):

    def set_test_params(self):
        self.num_nodes = 3

    def add_options(self, parser):
        parser.description = "Test wallet creation and funding"
        parser.usage = "warnet run /path/to/test_funding.py"

    def run_test(self):
        self.log.info("Waiting for L1 p2p network connections...")
        self.wait_for_tanks_connected()

        alice = self.nodes[0]
        bob = self.nodes[1]
        mallory = self.nodes[2]

        # --- Step 1: Create wallets ---
        self.log.info("Creating wallets on all nodes...")
        setup_wallets(alice, bob, mallory)

        # Verify wallets exist
        assert "alice" in alice.listwallets(), "Alice wallet not created"
        assert "bob" in bob.listwallets(), "Bob wallet not created"
        assert "mallory" in mallory.listwallets(), "Mallory wallet not created"
        self.log.info("All wallets created successfully")

        # --- Step 2: Mine initial coins for Alice ---
        self.log.info("Mining initial blocks for Alice...")
        miner_addr = fund_miner(alice, blocks=101)

        alice_balance = alice.getbalance()
        self.log.info(f"Alice balance after mining: {alice_balance} BTC")
        assert alice_balance >= 50, f"Alice balance too low: {alice_balance} BTC"

        # --- Step 3: Fund Bob and Mallory ---
        self.log.info("Funding Bob and Mallory with 10 BTC each...")
        bob_addr, mallory_addr = fund_participants(alice, bob, mallory, miner_addr, amount=10.0)

        bob_balance = bob.getbalance()
        mallory_balance = mallory.getbalance()
        self.log.info(f"Bob balance: {bob_balance} BTC")
        self.log.info(f"Mallory balance: {mallory_balance} BTC")

        assert bob_balance == 10.0, f"Bob balance is {bob_balance}, expected 10.0"
        assert mallory_balance == 10.0, f"Mallory balance is {mallory_balance}, expected 10.0"

        # --- Step 4: Verify all nodes see the same block height ---
        alice_height = alice.getblockcount()
        bob_height = bob.getblockcount()
        mallory_height = mallory.getblockcount()

        self.log.info(f"Block heights — Alice: {alice_height}, Bob: {bob_height}, Mallory: {mallory_height}")

        assert alice_height == bob_height, (
            f"Block height mismatch: Alice={alice_height}, Bob={bob_height}"
        )
        assert alice_height == mallory_height, (
            f"Block height mismatch: Alice={alice_height}, Mallory={mallory_height}"
        )

        # --- Summary ---
        self.log.info("========================================")
        self.log.info("  TEST FUNDING — ALL ASSERTIONS PASSED")
        self.log.info("========================================")
        self.log.info(f"  Alice balance:  {alice_balance} BTC")
        self.log.info(f"  Bob balance:    {bob_balance} BTC")
        self.log.info(f"  Mallory balance: {mallory_balance} BTC")
        self.log.info(f"  Block height:   {alice_height}")
        self.log.info("========================================")


def main():
    TestFunding().main()


if __name__ == "__main__":
    main()
