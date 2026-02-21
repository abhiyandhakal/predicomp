#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

usage() {
    cat <<USAGE
usage: $0 [options]

options:
  --device <zramN>        zram device (default from config)
  --algo <name>           compression algo (default lz4)
  --size <bytes|1G|...>   zram disk size (default 2G)
  --mem-limit <bytes>     zram memory limit (default 1G)
  --streams <n>           max_comp_streams (default 4)
  --priority <n>          swap priority (default 100)
  --force                 reset/swapoff existing device state
USAGE
}

parse_common_args "$@"
if [ "${PARSE_COMMON_HELP:-0}" -eq 1 ]; then
    usage
    exit 0
fi
set -- "${REM_ARGS[@]}"

ALGO="${RAM_POOL_ALGO:-lz4}"
SIZE="${RAM_POOL_SIZE:-2G}"
MEM_LIMIT="${RAM_POOL_MEM_LIMIT:-1G}"
STREAMS="${RAM_POOL_STREAMS:-4}"
PRIORITY="${RAM_POOL_SWAP_PRIORITY:-100}"
FORCE=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --algo)
            ALGO="$2"
            shift 2
            ;;
        --size)
            SIZE="$2"
            shift 2
            ;;
        --mem-limit)
            MEM_LIMIT="$2"
            shift 2
            ;;
        --streams)
            STREAMS="$2"
            shift 2
            ;;
        --priority)
            PRIORITY="$2"
            shift 2
            ;;
        --force)
            FORCE=1
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
ensure_zram_module
ensure_device_exists "$DEVICE"

SYS_DIR="$(zram_sysfs_dir "$DEVICE")"
DEV_PATH="$(zram_dev_path "$DEVICE")"

if is_swap_active "$DEV_PATH"; then
    if [ "$FORCE" -ne 1 ]; then
        echo "error: $DEV_PATH is already active swap; pass --force to reset" >&2
        exit 1
    fi
    swapoff "$DEV_PATH"
fi

if [ -f "$SYS_DIR/disksize" ] && [ "$(cat "$SYS_DIR/disksize")" != "0" ]; then
    if [ "$FORCE" -ne 1 ]; then
        echo "error: $DEVICE already configured; pass --force to reset" >&2
        exit 1
    fi
fi

if [ "$FORCE" -eq 1 ] && [ -f "$SYS_DIR/reset" ]; then
    echo 1 > "$SYS_DIR/reset"
fi

if [ -f "$SYS_DIR/comp_algorithm" ]; then
    if ! grep -qw "$ALGO" "$SYS_DIR/comp_algorithm"; then
        echo "error: algorithm '$ALGO' not supported by $DEVICE" >&2
        echo "available: $(cat "$SYS_DIR/comp_algorithm")" >&2
        exit 1
    fi
    echo "$ALGO" > "$SYS_DIR/comp_algorithm"
fi

echo "$SIZE" > "$SYS_DIR/disksize"

if [ -f "$SYS_DIR/mem_limit" ]; then
    echo "$MEM_LIMIT" > "$SYS_DIR/mem_limit"
fi

if [ -f "$SYS_DIR/max_comp_streams" ]; then
    echo "$STREAMS" > "$SYS_DIR/max_comp_streams"
fi

mkswap "$DEV_PATH" >/dev/null
swapon --priority "$PRIORITY" "$DEV_PATH"

"$SCRIPT_DIR/status_zram_pool.sh" --device "$DEVICE"
