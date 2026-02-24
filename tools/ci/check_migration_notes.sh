#!/usr/bin/env bash
set -euo pipefail

base_ref="${BASE_REF:-}"

if [[ -z "$base_ref" && -n "${GITHUB_BASE_REF:-}" ]]; then
  git fetch --no-tags --depth=1 origin "${GITHUB_BASE_REF}" >/dev/null 2>&1 || true
  base_ref="origin/${GITHUB_BASE_REF}"
fi

if [[ -z "$base_ref" ]]; then
  base_ref="HEAD~1"
fi

if ! git rev-parse --verify "$base_ref" >/dev/null 2>&1; then
  echo "Base ref $base_ref not found; skipping migration-notes gate."
  exit 0
fi

changed_files="$(git diff --name-only "$base_ref"...HEAD || true)"
if [[ -z "$changed_files" ]]; then
  echo "No changed files detected."
  exit 0
fi

needs_notes=0
if echo "$changed_files" | grep -Eq '^(crates/ffi-c/(src/lib.rs|include/eswp.h|build.rs)|crates/equalx-error/src/lib.rs|crates/host-adapter/src/lib.rs)'; then
  needs_notes=1
fi

if [[ "$needs_notes" -eq 1 ]]; then
  if ! echo "$changed_files" | grep -Eq '^docs/migrations/.+\.md$'; then
    echo "Migration notes entry required: ABI/error/adapter contract changed without docs/migrations/*.md update." >&2
    exit 1
  fi
fi

echo "Migration-notes check passed."
