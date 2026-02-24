#!/usr/bin/env bash
set -euo pipefail

baseline="${1:-ci/baselines/previous-minor/error_codes.csv}"
source_file="${2:-crates/equalx-error/src/lib.rs}"

if [[ ! -f "$baseline" ]]; then
  echo "Baseline error manifest not found: $baseline" >&2
  exit 1
fi

current="$(mktemp)"
"$(dirname "$0")/export_error_manifest.sh" "$source_file" "$current"

fail=0
while IFS=, read -r name value; do
  [[ -z "${name:-}" ]] && continue
  current_value="$(awk -F, -v n="$name" '$1==n {print $2}' "$current")"
  if [[ -z "$current_value" ]]; then
    echo "Removed error code from baseline: $name" >&2
    fail=1
    continue
  fi
  if [[ "$current_value" != "$value" ]]; then
    echo "Reassigned error code: $name baseline=$value current=$current_value" >&2
    fail=1
  fi
done < "$baseline"

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "Error-code compatibility check passed."
