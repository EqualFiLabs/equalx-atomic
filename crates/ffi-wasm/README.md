# ffi-wasm

WASM bindings for the EqualX SDK used by browser and Node.js callers.

## Memory Ownership

All exported functions copy their inputs and return freshly allocated `Uint8Array`/`Vec<u8>` buffers. Once a function returns, the WASM side no longer references the caller-provided slices and the JavaScript garbage collector owns any returned arrays. No buffers need to be manually freed. The cross-binding matrix in `../../docs/FFI-OWNERSHIP.md` summarizes how these guarantees compare to the C and Flutter/Dart layers.

## Settlement Context Encoding

Several APIs expect a canonical settlement context buffer:

```
| chain_tag_len | chain_tag bytes | position_key_len | position_key bytes | 0x20 | settle_digest (32B) |
```

`chain_tag_len` and `position_key_len` are single-byte lengths; `position_key_len` must be `0x20`. `settle_digest` must always be 32 bytes and encodes the binding digest from the SDK spec. Providing any other layout results in a `JsValue` error describing the mismatch.
