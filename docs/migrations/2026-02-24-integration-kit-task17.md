# Migration Notes - 0.0.1

- Release: `0.0.1`
- Date: `2026-02-24`
- Scope: `ABI`, `error taxonomy`, `CLI reference harness`, `CI compatibility gates`

## Breaking Changes
- None.

## Deprecated APIs
- None.

## Required Adapter Updates
- None for existing trait signatures.
- Integrators can now use the `mock-adapter` and `conformance` crates as reference validation tooling.

## ABI / Compatibility Notes
- `eswp_wire_version` and `CapabilityDescriptor.version_*` now derive from stable constants in `equalx-error`.
- New CI gates enforce:
  - additive-only header changes vs previous-minor baseline,
  - no removals/reassignments in numeric `ErrorCode` mappings,
  - smoke compile/run with previous-minor header against current `ffi-c`.
