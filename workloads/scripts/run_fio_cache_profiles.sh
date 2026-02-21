#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT_DIR/results/fio-cache-$(date +%Y%m%d-%H%M%S).log"
JOB="$ROOT_DIR/profiles/fio/cache-churn.fio"

if ! command -v fio >/dev/null 2>&1; then
    echo "fio not found. Run workloads/scripts/check_tools.sh" >&2
    exit 127
fi

fio "$JOB" | tee "$OUT"

echo "wrote $OUT"
