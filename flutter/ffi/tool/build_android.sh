#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
OUT_DIR="$REPO_ROOT/flutter/ffi/native/android"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required" >&2
  exit 1
fi
if ! command -v rustup >/dev/null 2>&1; then
  echo "error: rustup is required" >&2
  exit 1
fi

sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}}"
ndk_root="${ANDROID_NDK_HOME:-}"
if [[ -z "$ndk_root" ]]; then
  if [[ -d "$sdk_root/ndk" ]]; then
    ndk_root="$(ls -1d "$sdk_root"/ndk/* 2>/dev/null | sort -V | tail -n 1 || true)"
  fi
fi
if [[ -z "$ndk_root" || ! -d "$ndk_root" ]]; then
  echo "error: Android NDK not found. Set ANDROID_NDK_HOME (or install under $sdk_root/ndk)." >&2
  exit 1
fi
export ANDROID_NDK_HOME="$ndk_root"

if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "==> Installing cargo-ndk"
  cargo install cargo-ndk --locked
fi

echo "==> Ensuring Rust Android targets"
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

echo "==> Building ffi-c for Android ABIs"
mkdir -p "$OUT_DIR/jniLibs"
(
  cd "$REPO_ROOT"
  cargo ndk \
    -t arm64-v8a \
    -t armeabi-v7a \
    -t x86_64 \
    -o "$OUT_DIR/jniLibs" \
    build -p ffi-c --release
)

echo "==> Android artifacts written to: $OUT_DIR/jniLibs"
