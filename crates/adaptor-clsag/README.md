# adaptor-clsag

This crate provides the CLSAG adaptor implementation.

## Features

- `stub` (default): lightweight stub math for CI and quick testing.
- `moxide`: enable the real `monero-oxide` backend for transaction assembly and CLSAG signing.

To build with the real Monero primitives:

```bash
cargo build -p adaptor-clsag --features moxide
```
