#!/usr/bin/env bash
set -euo pipefail

baseline_header="${1:-ci/baselines/previous-minor/eswp.h}"

if [[ ! -f "$baseline_header" ]]; then
  echo "Baseline header not found: $baseline_header" >&2
  exit 1
fi

cargo build -p ffi-c >/dev/null

os="$(uname -s)"
case "$os" in
  Linux*)
    lib_name="libffi_c.so"
    lib_path_var="LD_LIBRARY_PATH"
    ;;
  Darwin*)
    lib_name="libffi_c.dylib"
    lib_path_var="DYLD_LIBRARY_PATH"
    ;;
  *)
    echo "Unsupported OS for smoke test: $os" >&2
    exit 1
    ;;
esac

target_dir="target/debug"
lib_path="$target_dir/$lib_name"
if [[ ! -f "$lib_path" ]]; then
  echo "Built library missing: $lib_path" >&2
  exit 1
fi

work_dir="$(mktemp -d)"
cat > "$work_dir/smoke_prev_minor.cpp" <<'CPP'
#include "eswp.h"

int main() {
  if (eswp_wire_version() == 0) {
    return 10;
  }

  CapabilityDescriptor cap{};
  if (eswp_capability_query(&cap) != 0) {
    return 11;
  }
  if (cap.wire_version == 0) {
    return 12;
  }

  unsigned char priv[32] = {0};
  unsigned char addr[20] = {0};
  if (eswp_generate_evm_keypair(priv, addr) != 0) {
    return 13;
  }

  return 0;
}
CPP

c++ -std=c++17 \
  "$work_dir/smoke_prev_minor.cpp" \
  -I"$(dirname "$baseline_header")" \
  -L"$target_dir" \
  -Wl,-rpath,"$(pwd)/$target_dir" \
  -lffi_c \
  -o "$work_dir/smoke_prev_minor"

"$work_dir/smoke_prev_minor"

echo "Previous-minor smoke test passed."
