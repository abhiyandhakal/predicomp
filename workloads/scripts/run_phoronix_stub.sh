#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT_DIR/results/phoronix-$(date +%Y%m%d-%H%M%S).log"

if ! command -v phoronix-test-suite >/dev/null 2>&1; then
    {
      echo "phoronix-test-suite not found"
      echo "Install docs: https://www.phoronix-test-suite.com/documentation/"
    } | tee "$OUT"
    exit 127
fi

{
    echo "phoronix integration stub"
    echo "Example baseline invocation:"
    echo "  phoronix-test-suite batch-run compress-7zip"
    echo "Use this wrapper to keep logs under workloads/results"
} | tee "$OUT"

echo "wrote $OUT"
