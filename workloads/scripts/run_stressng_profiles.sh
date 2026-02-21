#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/profiles/stress-ng/fork-vm.conf"
OUT="$ROOT_DIR/results/stress-ng-$(date +%Y%m%d-%H%M%S).log"

if ! command -v stress-ng >/dev/null 2>&1; then
    echo "stress-ng not found. Run workloads/scripts/check_tools.sh" >&2
    exit 127
fi

{
    echo "profile=fork-vm"
    echo "duration_sec=$DURATION_SEC timeout_sec=$TIMEOUT_SEC"
    echo "args=${ARGS[*]}"
    timeout "$TIMEOUT_SEC" stress-ng --timeout "${DURATION_SEC}s" "${ARGS[@]}" --metrics-brief
} | tee "$OUT"

echo "wrote $OUT"
