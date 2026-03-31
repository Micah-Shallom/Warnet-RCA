# Warnet Replacement Cycling Attack

A Warnet scenario that reproduces the **replacement cycling attack** (CVE-2023-40231 through CVE-2023-40234) — a real vulnerability that affects all major Lightning Network implementations (LDK, Eclair, LND, CLN). Disclosed by Antoine Riard on October 16, 2023.

The scenario runs on a regtest Bitcoin network inside a local Kubernetes cluster and demonstrates how an attacker can repeatedly evict a victim's HTLC-timeout transaction from the mempool using Bitcoin's Replace-By-Fee rules, preventing it from ever confirming and stealing the HTLC funds.

## What This Proves

Running `replacement_cycling_1.py` demonstrates:

- An attacker (Mallory) can evict the victim's (Bob) transaction from the mempool **every single cycle**
- The HTLC output becomes "orphaned" — nothing in the mempool spends it
- After enough cycles, Mallory claims the HTLC funds by broadcasting her preimage one final time
- **Total attack cost: ~38,700 sats (0.0387%) to steal 1 BTC (100,000,000 sats)**

## Prerequisites

- Python 3.9+
- [Warnet](https://github.com/bitcoin-dev-project/warnet) (`pip install warnet`)
- Kubernetes (Docker Desktop or Minikube)
- kubectl and helm

See [docs/setup.md](docs/setup.md) for detailed installation instructions.

## Quick Start

```bash
# Deploy the 3-node regtest network
warnet deploy networks/3_node_core

# Run the attack scenario
warnet run scenarios/replacement_cycling_1.py --debug

# Run with more cycles
warnet run scenarios/replacement_cycling_1.py --cycles 5 --debug

# Tear down
warnet down
```

## Sample Output

```
[SETUP] Creating HTLC output (1.0 BTC in 2-of-2 multisig)...
[SETUP] Block height: 103

[CYCLE 1/3] Broadcasting m_child...
[CYCLE 1/3] Bob broadcasts htlc_timeout...
[CYCLE 1/3] Mallory broadcasts htlc_preimage (10 sat/vB)...
[CYCLE 1/3] ✓ htlc_timeout EVICTED from mempool
[CYCLE 1/3] ✓ m_child EVICTED from mempool
[CYCLE 1/3] Mallory broadcasts cycle_out (31 sat/vB)...
[CYCLE 1/3] ✓ htlc_preimage EVICTED from mempool
[CYCLE 1/3] ✓ htlc_output is ORPHANED — no spender in mempool

[CYCLE 2/3] ...
[CYCLE 3/3] ...

[RESOLUTION] Mallory broadcasts final htlc_preimage (no cycle-out)...
[RESOLUTION] ✓ Mallory's preimage CONFIRMED in block 111

========================================
  ATTACK COMPLETE
========================================
  Cycles executed:     3
  HTLC amount:         1.0 BTC (100000000 sats)
  Total attacker cost: ~38700 sats
  Cost/stolen ratio:   0.0387%
  ✓ Mallory claimed the HTLC funds
  ✓ Bob did NOT receive the HTLC funds
========================================
```

## How the Attack Works

Three actors on a regtest Bitcoin network:

| Actor | Role |
|-------|------|
| **Alice** | Miner and funder (neutral) |
| **Bob** | Honest routing node (victim) |
| **Mallory** | Attacker |

The HTLC output is a 2-of-2 multisig between Bob and Mallory, simulating a Lightning channel. Both parties can sign spending transactions.

### Each attack cycle

1. **Mallory broadcasts m_child** — spends her "planted input" (Box M), placing it in the mempool
2. **Bob broadcasts htlc_timeout** — his claim on the HTLC funds, enters the mempool
3. **Mallory broadcasts htlc_preimage** — spends BOTH the HTLC output AND Box M. Because it pays a higher fee than htlc_timeout + m_child combined, RBF rules evict both
4. **Mallory broadcasts cycle_out** — spends only Box M with an even higher fee, evicting her own htlc_preimage. Now **nothing in the mempool spends the HTLC output**

The HTLC output is "orphaned." Bob rebroadcasts. Mallory repeats.

### Why it's cheap

Each cycle costs only the incremental RBF fee difference — roughly 8,000-17,000 sats per cycle. Against a node that rebroadcasts once per block, one cycle per block suffices. The attack cost scales linearly with the number of cycles, not with the HTLC value.

## Scope and Limitations

### What Scenario 1 models

- The **outbound side** of a forwarded HTLC (Bob→Mallory channel)
- The complete cycling mechanics: replacement, eviction, orphaning
- Multiple cycles with fresh planted inputs
- Final claim by the attacker

### What Scenario 1 does NOT model

- **The inbound HTLC (Alice→Bob)**: In a real attack, Alice (or Mallory's second node) would reclaim the inbound HTLC from Bob after its timelock expires. This means Bob loses the full routed amount — he paid Mallory on the outbound side but can't recover from Alice on the inbound side. Modeling this two-channel loss is Scenario 2 scope.
- **Real Lightning nodes**: The HTLC is simulated with a 2-of-2 multisig, not a real LN channel
- **Fee market dynamics**: The mempool is empty except for attack transactions
- **Realistic timing**: Blocks are mined on demand, not at 10-minute intervals

### Scenario 2 (future)

Will use real Lightning nodes (LND via Warnet's LN support) with actual channel opens, HTLC routing, and the full two-channel attack demonstrating Bob's economic loss.

## Project Structure

```
scenarios/
  replacement_cycling_1.py    # The main attack scenario
  test_funding.py             # Step 2: wallet + funding verification
  test_htlc.py                # Step 3: HTLC output + multisig signing
  test_box_m.py               # Step 4: planted input + m_child
  test_htlc_timeout.py        # Step 5: Bob's timeout transaction
  test_preimage_replacement.py # Step 6: the core RBF replacement
  test_single_cycle.py        # Step 7: one complete cycle
  test_multi_cycle.py         # Step 8: multiple cycles
  commander.py                # Warnet Commander base class
  test_framework/             # Vendored Bitcoin Core test framework

networks/3_node_core/
  network.yaml                # 3-node topology (Alice, Bob, Mallory)
  node-defaults.yaml          # Bitcoin Core config (regtest, ZMQ, txindex)

reference/
  riard_replacement_cycling_*.py  # Antoine Riard's original PoC scripts
```

## Technical Details

- **Bitcoin Core**: v27.0 (descriptor wallets only, no BDB)
- **Signing**: ECKey keypair generation + WIF encoding + `signrawtransactionwithkey` for multisig; `signrawtransactionwithwallet` for single-key operations
- **RBF signaling**: All replaceable transactions use `nSequence=0xFFFFFFFD`
- **nSequence rotation**: Bob's timeout uses decreasing nSequence values (0xFFFFFFFD, 0xFFFFFFFC, ...) each cycle to produce a new txid and bypass p2p duplicate filtering

## Companion Project

This scenario is designed to work alongside [anticycle-go](https://github.com/your-repo/anticycle-go) — a Go daemon that detects and defends against replacement cycling attacks by monitoring ZMQ mempool events. Bob's node has ZMQ enabled for this purpose.

## References

- Antoine Riard: ["All your mempool are belong to us"](https://gnusha.org/pi/bitcoindev/CALZpt+GdyfDotdhrrVkjTALg5DbxJyiS8ruO2S7Ggmi9Ra5B9g@mail.gmail.com/) (October 16, 2023)
- [Bitcoin Optech: Replacement Cycling](https://bitcoinops.org/en/topics/replacement-cycling/)
- [Gregory Sanders: anticycle.py](https://github.com/instagibbs/anticycle)
- [Warnet](https://github.com/bitcoin-dev-project/warnet)
- [BIP 125 (RBF)](https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki)
