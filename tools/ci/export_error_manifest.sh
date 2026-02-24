#!/usr/bin/env bash
set -euo pipefail

src_file="${1:-crates/equalx-error/src/lib.rs}"
out_file="${2:-}"

tmp_out="$(mktemp)"

awk '
  /pub enum ErrorCode/ {in_enum=1; next}
  in_enum && /^}/ {in_enum=0}
  in_enum {
    if ($0 ~ /^[[:space:]]*[A-Za-z0-9_]+[[:space:]]*=[[:space:]]*0x[0-9A-Fa-f]+,?[[:space:]]*$/) {
      line=$0
      gsub(/^[[:space:]]+/, "", line)
      gsub(/,/, "", line)
      split(line, parts, "=")
      name=parts[1]
      value=parts[2]
      gsub(/[[:space:]]+/, "", name)
      gsub(/[[:space:]]+/, "", value)
      print name "," value
    }
  }
' "$src_file" > "$tmp_out"

if [[ -n "$out_file" ]]; then
  mkdir -p "$(dirname "$out_file")"
  cp "$tmp_out" "$out_file"
else
  cat "$tmp_out"
fi
