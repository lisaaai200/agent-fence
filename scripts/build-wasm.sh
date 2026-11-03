#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../contract"
source "$HOME/.cargo/env" 2>/dev/null || true
cargo test
cargo build --target wasm32-unknown-unknown --release
mkdir -p res
cp target/wasm32-unknown-unknown/release/agent_fence.wasm res/agent_fence.wasm
echo "Wrote res/agent_fence.wasm ($(wc -c < res/agent_fence.wasm) bytes)"
