#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKLOAD_BIN_DIR="$ROOT_DIR/workloads/bin"

usage() {
    cat <<USAGE
usage: $0 [--profile readback|burst] [--duration-sec <n>]
USAGE
}

PROFILE="readback"
DURATION_SEC=30

while [ "$#" -gt 0 ]; do
    case "$1" in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --duration-sec)
            DURATION_SEC="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ ! -x "$WORKLOAD_BIN_DIR/interactive_burst" ] || [ ! -x "$WORKLOAD_BIN_DIR/random_touch_heap" ]; then
    echo "error: workloads binaries not built. Run: make -C workloads" >&2
    exit 1
fi

run_cmd() {
    echo "+ $*"
    "$@"
}

case "$PROFILE" in
    readback)
        run_cmd "$WORKLOAD_BIN_DIR/interactive_burst" --duration-sec "$DURATION_SEC" --region-mb 512 --active-ms 150 --idle-ms 50
        ;;
    burst)
        run_cmd "$WORKLOAD_BIN_DIR/interactive_burst" --duration-sec "$DURATION_SEC" --region-mb 1024 --active-ms 300 --idle-ms 25
        run_cmd "$WORKLOAD_BIN_DIR/random_touch_heap" --duration-sec "$DURATION_SEC" --region-mb 768 --ops-per-sec 300000
        ;;
    *)
        echo "error: invalid profile '$PROFILE'" >&2
        usage >&2
        exit 2
        ;;
esac

"$SCRIPT_DIR/status_zram_pool.sh"
