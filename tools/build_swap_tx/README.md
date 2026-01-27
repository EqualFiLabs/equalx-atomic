Build Swap Transaction (scaffold)

Summary
- Builds a deterministic swap spend plan from owned outputs and daemon data.
- Constructs unsigned Monero transaction with real encrypted amounts, pseudo-outs, and bulletproofs.
- Optionally generates an adaptor CLSAG pre-signature for one input and injects it.
- Optionally finalizes that input’s response scalar to produce a final_tx.bin artifact.
- Can relay the finalized transaction via `--broadcast` once a full CLSAG is present.

Key Capabilities
- Scan owned outputs via daemon RPC or load from a JSON fixture.
- Plan inputs, fee estimate, and optional change using monero-wallet-core.
- Derive rings from global indices and fetch ring member keys via /get_outs.
- Assemble signed RingCT transactions ready for relay once CLSAGs are finalized.
- Make adaptor pre‑signature bound to message, swap_id, and settlement context.
- Finalize a designated input’s CLSAG using finalize_tx (and optionally broadcast).

Inputs (selected)
- --daemon-url: Monero RPC base URL (http://host:port)
- --auth: Optional basic auth user:pass
- --view-key-hex, --spend-key-hex: 32‑byte hex keys
- --network: mainnet|stagenet|testnet
- --subaddr: repeatable account:index to include
- --dest ADDRESS:AMOUNT: repeatable transfer destinations
- --target-amount, --tip: planning targets in piconeros
- --ring-size: CLSAG ring size (default 16)
- --owned-json path: provide pre‑captured owned outputs for deterministic runs
- --out-dir dir: where artifacts are written (default out/)
- --dry-run: do not write artifacts
- --verbose: print detailed diagnostics (fee, change, rings, key images, settle_digest)
- Adaptor pre‑sig: --make-pre-sig, --message-hex, --input-index, --chain-tag, --position-key-hex,
  --settle-digest-hex, --swap-id-hex
- Finalization & relay: --finalize (requires non‑dry‑run and pre‑sig context), --broadcast

Artifacts
- out/plan.json: Spend plan produced by monero-wallet-core (inputs, fee_estimate, change, settle_digest)
- out/pre_sig_tx.bin: Unsigned tx blob with the designated CLSAG region replaced by PreSig bytes
- out/pre_sig.json: Sanitized pre-signature (ring indices, settlement context, CLSAG bytes). Safe to share.
- out/pre_sig.debug.json: Private diagnostics (witness secrets, i_star, τ). **Do not share.**
- out/final_tx.bin: Tx blob containing fully formed CLSAG(s); broadcastable as-is

Constraints and Notes
- --broadcast requires either a non-adaptor transaction or `--make-pre-sig --finalize` so the blob
  contains unbiased responses and refreshed pseudo-outs.
- Dry‑run: with --dry-run, no files are written; logging shows intended actions and targets.
- Determinism: the tool supports a deterministic RNG for stable test vectors when selecting decoys and
  generating scaffolding.

Settlement Digest Contract
- The spend plan carries SpendPlan::settle_digest (32 bytes). When producing an adaptor pre‑signature,
  the SettlementCtx.settle_digest used by the adaptor MUST byte‑equal the plan’s settle_digest.
- This binding is required for adaptor correctness; mismatches will invalidate the pre‑signature/finalization.

Related Crates
- monero-wallet-core: planning and wallet domain types
- tx_builder: assembly of inputs/outputs/RingCT with full bulletproof+CLSAG support
- adaptor-clsag: adaptor pre‑signature, finalize_tx, and serialization helpers

Example
  cargo run -p build_swap_tx -- \
    --daemon-url http://127.0.0.1:38081 \
    --view-key-hex <hex32> --spend-key-hex <hex32> \
    --network stagenet --subaddr 0:0 \
    --dest <address>:1000000000 --target-amount 1000000000 \
    --ring-size 16 --out-dir out --verbose --dry-run
