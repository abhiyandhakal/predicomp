#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORKLOAD_BIN_DIR="$ROOT_DIR/workloads/bin"

usage() {
    cat <<USAGE
usage: $0 [--profile light|medium|heavy] [--duration-sec <n>]
USAGE
}

PROFILE="medium"
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

if [ ! -x "$WORKLOAD_BIN_DIR/anon_streamer" ] || [ ! -x "$WORKLOAD_BIN_DIR/fork_touch_exit" ]; then
    echo "error: workloads binaries not built. Run: make -C workloads" >&2
    exit 1
fi

run_cmd() {
    echo "+ $*"
    "$@"
}

case "$PROFILE" in
    light)
        run_cmd "$WORKLOAD_BIN_DIR/anon_streamer" --duration-sec "$DURATION_SEC" --region-mb 256 --idle-ms 100
        ;;
    medium)
        run_cmd "$WORKLOAD_BIN_DIR/anon_streamer" --duration-sec "$DURATION_SEC" --region-mb 768 --idle-ms 50
        run_cmd "$WORKLOAD_BIN_DIR/fork_touch_exit" --duration-sec "$DURATION_SEC" --workers 2 --fork-rate 10 --touch-pages 256
        ;;
    heavy)
        run_cmd "$WORKLOAD_BIN_DIR/anon_streamer" --duration-sec "$DURATION_SEC" --region-mb 1536 --idle-ms 10
        run_cmd "$WORKLOAD_BIN_DIR/fork_touch_exit" --duration-sec "$DURATION_SEC" --workers 4 --fork-rate 20 --touch-pages 512
        run_cmd "$WORKLOAD_BIN_DIR/mmap_churn" --duration-sec "$DURATION_SEC" --map-kb 1024 --ops-per-sec 1000
        ;;
    *)
        echo "error: invalid profile '$PROFILE'" >&2
        usage >&2
        exit 2
        ;;
esac

"$SCRIPT_DIR/status_zram_pool.sh"
