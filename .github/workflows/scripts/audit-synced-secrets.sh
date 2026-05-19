#!/usr/bin/env bash
# Audit synced workflow files and scripts for private-visibility secrets.
#
# .github/workflows/ (minus sync_exclude_paths) is synced to all TARGET_ORGS.
# Org secrets with `private` visibility in Gridltd-DevOps cannot be resolved
# in other orgs, so referencing them in a synced workflow or script silently
# breaks sync.

set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || echo ".")}"
cd "${REPO_ROOT}"

DENY_LIST=(
  "ENTERPRISE_ADMIN_TOKEN"
)

COMMON_JSON=".github/workflows/config/sync-org-rules/common.json"
if [[ ! -f "${COMMON_JSON}" ]]; then
  echo "OK: ${COMMON_JSON} not present; this repo is not the sync source of truth."
  exit 0
fi

if ! SYNC_EXCLUDE_OUTPUT="$(
  python3 - "${COMMON_JSON}" <<'PY'
import json
import sys

try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
except Exception as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    sys.exit(1)

for p in d.get("sync_exclude_paths", []):
    print(p)
PY
)"; then
  echo "ERROR: failed to parse ${COMMON_JSON}." >&2
  exit 1
fi

SYNC_EXCLUDE_PATTERNS=()
while IFS= read -r pattern; do
  [[ -n "${pattern}" ]] || continue
  SYNC_EXCLUDE_PATTERNS+=("${pattern}")
done <<< "${SYNC_EXCLUDE_OUTPUT}"

is_excluded() {
  local file="$1"
  if [[ "${#SYNC_EXCLUDE_PATTERNS[@]}" -eq 0 ]]; then
    return 1
  fi

  for pattern in "${SYNC_EXCLUDE_PATTERNS[@]}"; do
    if [[ "${file}" == "${pattern}" || "${file}" == "${pattern}/"* ]]; then
      return 0
    fi
  done
  return 1
}

matches_secret() {
  local file="$1" secret="$2"
  local dotted_re="secrets\\.${secret}\\b"
  local sq_re="secrets\\['${secret}'\\]"
  local dq_re="secrets\\[\"${secret}\"\\]"

  if grep -qP "${dotted_re}|${sq_re}|${dq_re}" "${file}" 2>/dev/null; then
    return 0
  fi

  grep -qE "secrets\\.${secret}\\b" "${file}" 2>/dev/null && return 0
  grep -qF "secrets['${secret}']" "${file}" 2>/dev/null && return 0
  grep -qF "secrets[\"${secret}\"]" "${file}" 2>/dev/null && return 0
  return 1
}

VIOLATIONS=0
CHECKED=0

while IFS= read -r wf_file; do
  wf_file="${wf_file#./}"
  is_excluded "${wf_file}" && continue
  CHECKED=$((CHECKED + 1))

  for secret in "${DENY_LIST[@]}"; do
    if matches_secret "${wf_file}" "${secret}"; then
      echo "VIOLATION: ${wf_file} references ${secret}"
      echo "  This secret has private visibility in Gridltd-DevOps."
      echo "  It is inaccessible when the workflow/script runs in a non-DevOps org."
      VIOLATIONS=$((VIOLATIONS + 1))
    fi
  done
done < <(find ".github/workflows" \( -name "*.yml" -o -name "*.yaml" -o -name "*.sh" -o -name "*.bash" \) -type f | sort)

echo ""
echo "Scanned ${CHECKED} synced file(s) (yml + yaml + sh + bash). Deny-listed secrets: ${DENY_LIST[*]}."

if [[ "${VIOLATIONS}" -gt 0 ]]; then
  echo ""
  echo "ERROR: ${VIOLATIONS} violation(s) found in synced workflows."
  exit 1
fi

echo "OK: no private-visibility secret violations found."
