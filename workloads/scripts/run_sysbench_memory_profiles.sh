#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/profiles/sysbench/memory_seq.conf"
OUT="$ROOT_DIR/results/sysbench-memory-$(date +%Y%m%d-%H%M%S).log"

if ! command -v sysbench >/dev/null 2>&1; then
    echo "sysbench not found. Run workloads/scripts/check_tools.sh" >&2
    exit 127
fi

{
    echo "profile=memory_seq"
    echo "total_size=$TOTAL_SIZE block_size=$BLOCK_SIZE threads=$THREADS scope=$SCOPE time_sec=$TIME_SEC op=$OP"
    sysbench memory \
      --memory-total-size="$TOTAL_SIZE" \
      --memory-block-size="$BLOCK_SIZE" \
      --threads="$THREADS" \
      --memory-scope="$SCOPE" \
      --time="$TIME_SEC" \
      --memory-oper="$OP" run
} | tee "$OUT"

echo "wrote $OUT"
