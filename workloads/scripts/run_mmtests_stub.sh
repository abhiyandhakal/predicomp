#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT_DIR/results/mmtests-$(date +%Y%m%d-%H%M%S).log"
MMTESTS_DIR="${MMTESTS_DIR:-$HOME/mmtests}"

if [ ! -d "$MMTESTS_DIR" ]; then
    {
      echo "mmtests directory not found at $MMTESTS_DIR"
      echo "Install/source: https://github.com/gormanm/mmtests"
      echo "Then set MMTESTS_DIR=/path/to/mmtests"
    } | tee "$OUT"
    exit 127
fi

{
    echo "mmtests integration stub"
    echo "mmtests_dir=$MMTESTS_DIR"
    echo "Run an mmtests config from inside mmtests, then capture alongside workloads/results"
    echo "Example: cd $MMTESTS_DIR && ./run-mmtests.sh configs/config-workload-..."
} | tee "$OUT"

echo "wrote $OUT"
