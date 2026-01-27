# equalx_ffi (Flutter)

Flutter/Dart bindings that wrap the EqualX C ABI (`crates/ffi-c`). The package
loads the native library via `EqualXLibrary`, exposes typed helpers through
`EqualXApi`, and surfaces native error codes as `EqualXException`s so mobile
wallets can react programmatically.

## Memory & Error Semantics

All `Uint8List` inputs are copied into arena-managed native buffers before
calling into C, and outputs are copied back into fresh Dart objects before the
arena is released. Callers never receive borrowed pointers – instead they
control buffer sizing via the optional `outputCapacity`/`maxEvents` arguments on
API methods.

## Building & Testing

```sh
cargo build -p ffi-c  # produces libffi_c.{so,dylib,dll}
EQUALX_FFI_LIB=../target/debug/libffi_c.so flutter test
```

Set `EQUALX_FFI_LIB` to the compiled shared library before running `flutter
test` or integrating into an app bundle.
