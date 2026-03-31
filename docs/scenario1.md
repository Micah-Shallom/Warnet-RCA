# Scenario 1 — Raw Transaction Replacement Cycling

## Overview

Scenario 1 demonstrates the replacement cycling attack using only Bitcoin Core nodes and manually constructed transactions. No Lightning nodes, no real channels. The HTLC is simulated with a 2-of-2 multisig.

## Actors

| Actor | Node | Role |
|-------|------|------|
| Alice | `nodes[0]` | Miner and funder. Does not participate in the attack. |
| Bob | `nodes[1]` | Victim. Tries to claim the HTLC via timeout. |
| Mallory | `nodes[2]` | Attacker. Cycles Bob's timeout out of the mempool. |

## Transaction Map

```
                    ┌─────────────┐
                    │ Alice funds  │
                    │ multisig     │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ HTLC Output  │  (2-of-2 multisig, confirmed)
                    │ 1.0 BTC      │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │                         │
     ┌────────▼────────┐     ┌─────────▼─────────┐
     │ htlc_timeout     │     │ htlc_preimage      │
     │ (Bob's claim)    │     │ (Mallory's claim)   │
     │ Spends: HTLC out │     │ Spends: HTLC out   │
     │ Fee: 2 sat/vB    │     │       + Box M       │
     └─────────────────┘     │ Fee: 10+ sat/vB     │
                              └─────────┬──────────┘
                                        │ conflicts with
                    ┌───────────────────┘
                    │
     ┌──────────────▼──────────────┐
     │ Box M (planted input)        │  (confirmed UTXO Mallory controls)
     └──────────────┬──────────────┘
                    │
         ┌──────────┼──────────┐
         │                     │
    ┌────▼────┐          ┌────▼────────┐
    │ m_child  │          │ cycle_out    │
    │ Fee: 1   │          │ Fee: 30+     │
    └─────────┘          └─────────────┘
```

## Step-by-Step Breakdown

### Setup Phase

1. **Alice mines 101 blocks** — coinbase maturity, Alice gets spendable coins
2. **Alice funds Bob and Mallory** — 10 BTC each, confirmed in a block
3. **HTLC output created** — Alice funds a 2-of-2 multisig (Bob + Mallory keys) with 1.0 BTC, confirmed

At this point:
- HTLC output is a confirmed UTXO at `htlc_txid:htlc_vout`
- Both Bob and Mallory have the keys to sign spending transactions
- The multisig keys are generated in Python (ECKey), not from any wallet

### Attack Cycle (repeated N times)

**Phase 1 — Plant the conflict:**

4. **Alice creates Box M** — sends 0.1 BTC to a Mallory wallet address, confirms it
5. **Mallory broadcasts m_child** — spends Box M to herself, fee 1 sat/vB, signals RBF
   - Box M is now "pre-spent" in the mempool

**Phase 2 — Bob's timeout enters:**

6. **Bob broadcasts htlc_timeout** — spends the HTLC output to his address, fee 2 sat/vB, signals RBF
   - Mempool now has: m_child + htlc_timeout

**Phase 3 — Mallory replaces:**

7. **Mallory broadcasts htlc_preimage** — spends TWO inputs:
   - Input 0: HTLC output (conflicts with htlc_timeout)
   - Input 1: Box M (conflicts with m_child)
   - Fee: 10+ sat/vB (higher than htlc_timeout + m_child combined)
   - RBF evicts both htlc_timeout and m_child
   - Mempool now has: htlc_preimage only

**Phase 4 — Mallory cycles out her own preimage:**

8. **Mallory broadcasts cycle_out** — spends Box M only, fee 30+ sat/vB
   - Conflicts with htlc_preimage (both spend Box M)
   - Fee exceeds htlc_preimage's absolute fee
   - RBF evicts htlc_preimage
   - **Mempool now has: cycle_out only. HTLC output is ORPHANED.**

**Phase 5 — Reset:**

9. **Mine a block** — confirms cycle_out, clears mempool
10. **Bob rebroadcasts** — with incremented nSequence (new txid to bypass p2p filter)
11. Go to Phase 1 with a fresh Box M

### Resolution Phase

After N cycles, Mallory broadcasts htlc_preimage one final time **without** broadcasting cycle_out. The preimage sits in the mempool. A block is mined. Mallory's preimage confirms. She claims the 1.0 BTC.

## RBF Rules Satisfied at Each Step

### htlc_preimage replaces htlc_timeout + m_child

| RBF Rule | Requirement | How it's satisfied |
|----------|-------------|--------------------|
| Rule 2 | Must conflict with at least one unconfirmed tx | Conflicts with htlc_timeout (both spend HTLC output) and m_child (both spend Box M) |
| Rule 3 | Must pay higher absolute fee than all evicted txs combined | htlc_preimage fee (4000 sats) > htlc_timeout fee (600 sats) + m_child fee (150 sats) |
| Rule 6 | Must pay higher feerate than directly conflicting txs | 10 sat/vB > 2 sat/vB (htlc_timeout) and > 1 sat/vB (m_child) |

### cycle_out replaces htlc_preimage

| RBF Rule | Requirement | How it's satisfied |
|----------|-------------|--------------------|
| Rule 2 | Must conflict with at least one unconfirmed tx | Conflicts with htlc_preimage (both spend Box M) |
| Rule 3 | Must pay higher absolute fee | cycle_out fee (4650 sats) > htlc_preimage fee (4000 sats) |
| Rule 6 | Must pay higher feerate | 31 sat/vB > 10 sat/vB |

## Fee Escalation Across Cycles

| Cycle | htlc_timeout | htlc_preimage | cycle_out | Cycle cost |
|-------|-------------|---------------|-----------|------------|
| 1 | 2 sat/vB (600 sats) | 10 sat/vB (4000 sats) | 31 sat/vB (4650 sats) | ~8,650 sats |
| 2 | 2 sat/vB (600 sats) | 15 sat/vB (6000 sats) | 46 sat/vB (6900 sats) | ~12,900 sats |
| 3 | 2 sat/vB (600 sats) | 20 sat/vB (8000 sats) | 61 sat/vB (9150 sats) | ~17,150 sats |

**Total for 3 cycles: ~38,700 sats (0.0387% of 1 BTC stolen)**

## Signing Approach

Bitcoin Core 27.0 uses descriptor wallets only (no BDB/legacy wallet support). This affects how we sign the multisig:

- **Multisig keys** are generated in Python using `test_framework.key.ECKey`, converted to WIF format manually
- **Multisig signing** uses `signrawtransactionwithkey` with explicit WIF private keys and `prevtxs` containing the `redeemScript` — no wallet involvement
- **Single-key signing** (Box M, m_child, cycle_out) uses `signrawtransactionwithwallet` on Mallory's node
- **nSequence rotation**: Bob's htlc_timeout uses decreasing nSequence values each cycle (0xFFFFFFFD, 0xFFFFFFFC, ...) to change the txid and bypass Bitcoin Core's p2p duplicate transaction filter

## What This Scenario Does NOT Model

**The inbound HTLC (Alice→Bob channel):** In a real Lightning forwarding attack, the payment path is Alice→Bob→Mallory. Bob forwards the HTLC from Alice to Mallory. When Mallory's cycling attack succeeds:

1. Mallory claims the outbound HTLC (Bob→Mallory) via preimage — **modeled in Scenario 1**
2. The inbound HTLC (Alice→Bob) times out, and Alice reclaims her funds — **NOT modeled**
3. Bob loses the full routed amount: he paid Mallory but can't recover from Alice — **NOT modeled**

In Scenario 1, the HTLC output is funded directly by Alice (the miner), not from Bob's balance. Bob's wallet balance stays at 10 BTC throughout. The scenario proves the **cycling mechanics** (eviction, orphaning, final claim) but not the **economic loss path** that requires two channels.

Modeling the full two-channel attack with real Lightning nodes is Scenario 2 scope.
