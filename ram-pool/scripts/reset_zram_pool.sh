#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

usage() {
    cat <<USAGE
usage: $0 [--device <zramN>] [--unload-module]
USAGE
}

parse_common_args "$@"
if [ "${PARSE_COMMON_HELP:-0}" -eq 1 ]; then
    usage
    exit 0
fi
set -- "${REM_ARGS[@]}"

UNLOAD=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --unload-module)
            UNLOAD=1
            shift
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

require_root

SYS_DIR="$(zram_sysfs_dir "$DEVICE")"
DEV_PATH="$(zram_dev_path "$DEVICE")"

if [ ! -d "$SYS_DIR" ]; then
    echo "error: $SYS_DIR does not exist" >&2
    exit 1
fi

if is_swap_active "$DEV_PATH"; then
    swapoff "$DEV_PATH"
fi

if [ -f "$SYS_DIR/reset" ]; then
    echo 1 > "$SYS_DIR/reset"
fi

if [ "$UNLOAD" -eq 1 ]; then
    if ls /sys/block | grep -q '^zram'; then
        echo "zram devices still present; skipping module unload" >&2
    else
        modprobe -r zram || true
    fi
fi

echo "reset complete for $DEVICE"
