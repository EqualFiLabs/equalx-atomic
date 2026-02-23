#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"

cat <<'EOT'
The Dart bindings in lib/src/equalx_bindings.dart are maintained to match
crates/ffi-c/include/eswp.h. If you change the C ABI, update bindings and run:

  flutter test

If you want to use ffigen, first generate a C-compatible header and configure
ffigen for your local clang setup.
EOT

( cd "$REPO_ROOT/flutter/ffi" && ${FLUTTER_BIN:-$HOME/development/flutter/bin/flutter} analyze )
