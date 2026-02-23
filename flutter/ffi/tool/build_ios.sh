#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
OUT_DIR="$REPO_ROOT/flutter/ffi/native/ios"
HEADER_DIR="$REPO_ROOT/crates/ffi-c/include"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: iOS XCFramework build must run on macOS" >&2
  exit 1
fi
if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "error: xcodebuild is required" >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required" >&2
  exit 1
fi
if ! command -v rustup >/dev/null 2>&1; then
  echo "error: rustup is required" >&2
  exit 1
fi

echo "==> Ensuring Rust iOS targets"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios

echo "==> Building ffi-c static libraries"
(
  cd "$REPO_ROOT"
  cargo build -p ffi-c --release --target aarch64-apple-ios
  cargo build -p ffi-c --release --target aarch64-apple-ios-sim
  cargo build -p ffi-c --release --target x86_64-apple-ios
)

mkdir -p "$OUT_DIR"
rm -rf "$OUT_DIR/EqualXFFI.xcframework"

echo "==> Creating EqualXFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$REPO_ROOT/target/aarch64-apple-ios/release/libffi_c.a" -headers "$HEADER_DIR" \
  -library "$REPO_ROOT/target/aarch64-apple-ios-sim/release/libffi_c.a" -headers "$HEADER_DIR" \
  -library "$REPO_ROOT/target/x86_64-apple-ios/release/libffi_c.a" -headers "$HEADER_DIR" \
  -output "$OUT_DIR/EqualXFFI.xcframework"

echo "==> iOS artifact written to: $OUT_DIR/EqualXFFI.xcframework"
