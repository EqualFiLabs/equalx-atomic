# EqualX SDK

`equalx-sdk` is the canonical Rust implementation of the EqualX integration layer.
It binds Monero adaptor workflows to the EqualX Atomic Desk contracts (see
`docs/ATOMICDESKS.md`), enforces deterministic settlement contexts, and produces structured
error codes that clients can act upon.

## Modules

- `settlement`: creates canonical `SettlementCtx` instances and exposes the transcript
  binding utility that every other module reuses.
- `key_management`: deterministic helpers for generating Monero/EVM key material using
  `monero-oxide` derivations plus Alloy’s secp256k1 signer, covering subaddresses, key images,
  and message signatures.
- `adaptor`: wraps the `adaptor-clsag` crate to build, complete, verify, and extract adaptor
  signatures against real CLSAG contexts.
- `refund`: prepares refund transactions for the Monero leg while validating the timing
  envelope against the EVM expiry.
- `contracts`: Alloy-generated bindings for the EqualX contracts (`DeskVault`,
  `AuctionHouse`, `Router`, `SettlementEscrow`, `AtomicDesk`, and `Mailbox`) plus thin clients that encode
  and decode typed calls/events using a shared `EvmTransport`.
- `escrow`: legacy helpers for the pre-EqualX escrow; kept for historical compatibility
  but superseded by the `contracts::settlement_escrow` client.
- `transport`: provides the `EvmTransport` abstraction plus an Alloy-backed HTTP implementation
  that signs and submits JSON-RPC transactions.
- `tx_hash`: implements ADR-001 publication of the Monero transaction hash. The old
  QuoteBoard-specific helpers remain for backwards compatibility while new integrations
  should migrate to the Router + Mailbox flow.
- `automation`: ties the Monero watcher into the escrow client so swaps can auto-settle once τ
  is extracted.
- `error`: shared numeric error taxonomy that is reused across all modules.

Every public function returns `Result<T, ErrorCode>` so that downstream callers can map
failures directly to protocol-defined recovery strategies. Deterministic transcript binding
is implemented once inside `SettlementCtx::binding` and reused by adaptor, escrow, refund,
 and ADR-001 helpers to guarantee consistent transcripts. The EVM bindings mirror the
 contracts and events defined in `docs/ATOMICDESKS.md` so SDK consumers can interact with
 DeskVault, AuctionHouse, Router, SettlementEscrow, and Mailbox using type-safe calls.

## Testing

Unit tests live in `src/lib.rs` and exercise every public function. Run them with:

```bash
cargo test -p equalx-sdk
```

Formatting and linting follow the workspace defaults.
