# AgentFence

**Give an AI agent a wallet without giving it the keys to everything.**

Built for the [NEAR HACKATHON](https://nearhackathon.com) (2026-11-01 → 2026-11-14).

| Field | Value |
| --- | --- |
| Tracks | `security` (AI Security & Defense), `agents` (Agent Economy) |
| Network | NEAR **testnet** (WASM + unit tests included; mainnet not required) |
| Team size | Solo |
| License | MIT |

## Other projects by this builder

Per hackathon rule Q-015 (one person, up to 2 independent projects, each README must name the other): this builder's other entry is **NEAR Usage Thesis** (Investment Thesis track, `thesis`), built by teammate Genie and submitted separately. The two projects do not share code or scope.

## Problem

AI agents that can spend crypto are one prompt-injection away from draining a wallet. A full-access key in an agent runtime is an all-or-nothing trust decision. Humans need **spending limits**, **counterparty checks**, and **keys that physically cannot transfer NEAR or add new keys**.

## What it does

AgentFence is an on-chain **policy purse** plus an **agent-side wrapper**:

1. The human owner deposits NEAR into the AgentFence contract and sets `per_tx_limit` / `daily_limit`.
2. The agent receives only a **function-call access key** scoped to this contract's methods (`pay`, `evaluate_receiver`, `report_receiver`, views). It **cannot** `Transfer` NEAR, `AddKey`, or call any other contract ([NEAR access keys](https://docs.near.org/protocol/accounts-contracts/access-keys)).
3. Before signing, the wrapper calls `evaluate_receiver` → `Allow` / `Warn` / `Block` with reasons and a risk score.
4. `pay` re-checks the same policy on-chain. `Block` always refuses. `Warn` refuses unless a human sets `force_warn`.
5. Agents can `report_receiver` into a shared on-chain reputation feed (evidence = content hash, never PII).

### Signals scored today (on-chain MVP)

| Signal | Source | Effect |
| --- | --- | --- |
| Owner blocklist | contract state | hard `Block` (risk 100) |
| Owner allowlist | contract state | hard `Allow` (risk 0) |
| Implicit account id | account id shape (64 hex) | +20 risk |
| No prior payments to receiver | payment history | +15 risk |
| Community reports | `report_receiver` feed | +25 risk each (cap 3) |

**Off-chain sources we'd add next** (listed for judges; not required to run the demo): NEAR Explorer account age / first-seen, contract code hash changes via RPC `view_code` + archival history, known-scam lists from community feeds, OutLayer / TEE attestation of the agent runtime.

Risk bands: `≥80` Block · `≥35` Warn · else Allow.

## How to try it (do X → see Y)

### 1. Attack demo (no wallet needed)

```bash
node demo/attack-demo.mjs
```

- **Do:** run the script.
- **See:** a legitimate 0.05 NEAR payment to an allowlisted merchant succeeds; a prompt-injected payment to a blocklisted scam sink is **refused and not signed**; an unknown implicit receiver returns **Warn** and needs a human.

### 2. Unit tests (contract logic)

```bash
cd contract
cargo test
```

- **Do:** run tests.
- **See:** 6/6 pass — blocklist blocks, allowlist allows, per-tx limit enforced, injection-style pay panics, reports raise risk to Warn, successful pay is recorded.

### 3. Build WASM

```bash
./scripts/build-wasm.sh
# → contract/res/agent_fence.wasm
```

### 4. Deploy to testnet (optional, free faucet)

Requires a NEAR testnet account and [`near-cli-rs`](https://github.com/near/near-cli-rs) or `cargo near`. Use **only** the free testnet faucet. Never put a seed phrase in this repo.

```bash
# after creating agent-fence.<you>.testnet and funding via https://near-faucet.io/
near contract deploy agent-fence.<you>.testnet \
  use-file contract/res/agent_fence.wasm \
  with-init-call new \
  json-args '{"per_tx_limit":"100000000000000000000000","daily_limit":"500000000000000000000000"}' \
  prepaid-gas '100.0 Tgas' \
  attached-deposit '0 NEAR' \
  network-config testnet
```

Then call `authorize_agent`, `allow` / `block`, `deposit`, and have the agent call `pay` with its function-call key.

## Function-call key limits (read this)

A function-call key on the purse account:

- **Can** call only the methods listed when the key was added (we use `pay,evaluate_receiver,report_receiver,get_policy,get_day_spend,get_balance`).
- **Cannot** transfer NEAR directly, stake, delete the account, or add keys.
- **Allowance** caps gas the key may burn; if it hits zero the key dies. We set a finite allowance so a runaway loop cannot burn the account forever.
- If an account has **only** FC keys and they all exhaust allowance, the account can lock itself out — the owner must keep a full-access key offline.

So even if the agent is fully prompt-injected, the worst it can attempt is `pay` into AgentFence, and AgentFence still enforces limits + counterparty verdict.

## Repository layout

```
contract/          Rust NEAR contract (near-sdk 5) + unit tests + WASM
agent-wrapper/     Pure-JS pre-chain guard (Allow/Warn/Block)
demo/              Attack demo + happy path
scripts/           build-wasm.sh
assets/            Demo GIF / screenshots for the X post
```

## Demo assets for the X post

See `assets/` and `assets/X_POST.txt`. The human publishes the X post (required by the hackathon). This repo does not post anything.

## Judging notes

- Reproducible without mainnet or paid APIs.
- Original: policy purse + FC-key sandbox + shared report feed + attack demo.
- Sustainability: MIT, no proprietary lock-in; extend signals via RPC without changing the agent key model.

## Disclaimer

Testnet / local demo only in this repository. No mainnet keys, no seed phrases, no KYC. Prize payout address is provided at submission time by the team (Genie holds the NEAR prize account).
