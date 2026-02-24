#!/usr/bin/env bash
set -euo pipefail

baseline="${1:-ci/baselines/previous-minor/eswp.h}"
current="${2:-crates/ffi-c/include/eswp.h}"

if [[ ! -f "$baseline" ]]; then
  echo "Baseline header not found: $baseline" >&2
  exit 1
fi
if [[ ! -f "$current" ]]; then
  echo "Current header not found: $current" >&2
  exit 1
fi

normalize() {
  sed -E 's,//.*$,,' "$1" \
    | sed -E 's,/\*([^*]|\*+[^*/])*\*/,,g' \
    | sed '/^[[:space:]]*$/d' \
    | sed -E 's/[[:space:]]+/ /g' \
    | sed -E 's/^ //; s/ $//'
}

baseline_norm="$(mktemp)"
current_norm="$(mktemp)"
normalize "$baseline" > "$baseline_norm"
normalize "$current" > "$current_norm"

missing=0
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if ! grep -Fqx "$line" "$current_norm"; then
    echo "Missing baseline ABI declaration: $line" >&2
    missing=1
  fi
done < "$baseline_norm"

if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

echo "Header additivity check passed."
