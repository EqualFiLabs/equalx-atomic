# EqualX EVM<>XMR Atomic Swap
<img
src="./eth-xmr.png"
alt="diagram"
style="display:block;margin:0 auto;">

This repository hosts the Rust SDK, CLI, FFI bindings, Monero adapters, and supporting tools used for Ethereum <> Monero atomic swaps.

## Repo layout

- `crates/` Rust workspace crates (SDK, CLI, Monero RPC/wallet core, adaptor CLSAG, mailbox/presig envelopes, watcher, etc.)
- `tools/` Standalone Rust binaries (e.g. swap tx builder/exporter)
- `evm/` Solidity contracts and build artifacts
- `flutter/` Dart/Flutter FFI bindings
- `vectors/` Test vectors and fixtures
- `docs/` Design/spec documentation

## Dependencies

Minimum (build + core tests):
- Rust toolchain (stable, edition 2021) with `cargo`

Optional (only needed for specific targets/tests):
- Foundry (`anvil`, `forge`, `cast`) for EVM/CLI integration tests and local desk flows
- Monero daemon (`monerod`) for wallet examples and scripts that talk to a daemon RPC
- `python3` and `curl` for `script/run_atomic_local.sh`
- WASM target for `ffi-wasm` builds: `rustup target add wasm32-unknown-unknown`

## Install dependencies (examples)

Rust (via rustup):

```bash
rustup install stable
rustup default stable
```

Optional WASM target:

```bash
rustup target add wasm32-unknown-unknown
```

Foundry (required for EVM/CLI integration tests): ensure `anvil`, `forge`, and `cast` are on your `PATH`.

Monero daemon (required for Monero RPC examples/scripts): run a local node, e.g. `monerod --stagenet` or `monerod --regtest`.

## Build

From the repo root:

```bash
cargo build --workspace
```

## Run tests

All workspace tests (includes CLI integration tests):

```bash
cargo test --workspace
```

Notes:
- `crates/cli` has integration tests that launch `anvil` (Foundry). If Foundry is not installed, those tests will fail to spawn.
- To run tests without Foundry, exclude the CLI crate:

```bash
cargo test --workspace --exclude cli
```

Run a single crate's tests:

```bash
cargo test -p adaptor-clsag
```

Run the adaptor CLSAG tests with real Monero primitives (requires the `moxide` feature):

```bash
cargo test -p adaptor-clsag --features moxide
```

## Local atomic-desk flow (optional)

The `script/run_atomic_local.sh` script exercises a full local flow and requires:
- Foundry (`anvil`, `forge`, `cast`)
- a Monero daemon RPC (`MONERO_RPC`)
- `python3` and `curl`

```bash
./script/run_atomic_local.sh
```
