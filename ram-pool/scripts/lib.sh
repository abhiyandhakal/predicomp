#!/usr/bin/env bash
set -euo pipefail

RAM_POOL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_ENV="$RAM_POOL_ROOT/config/default.env"

if [ -f "$DEFAULT_ENV" ]; then
    # shellcheck disable=SC1090
    source "$DEFAULT_ENV"
fi

require_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        echo "error: this command requires root" >&2
        exit 1
    fi
}

script_dir() {
    cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
}

parse_common_args() {
    DEVICE="${RAM_POOL_DEVICE:-zram0}"
    PARSE_COMMON_HELP=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --device)
                DEVICE="$2"
                shift 2
                ;;
            --help|-h)
                PARSE_COMMON_HELP=1
                shift
                ;;
            *)
                break
                ;;
        esac
    done
    REM_ARGS=("$@")
}

zram_sysfs_dir() {
    local device="$1"
    echo "/sys/block/$device"
}

zram_dev_path() {
    local device="$1"
    echo "/dev/$device"
}

ensure_zram_module() {
    if [ ! -e /sys/class/zram-control ] && [ ! -e /sys/block/zram0 ]; then
        modprobe zram
    fi
}

ensure_device_exists() {
    local device="$1"
    if [ -e "/sys/block/$device" ] && [ -b "/dev/$device" ]; then
        return
    fi

    if [ -e /sys/class/zram-control/hot_add ]; then
        local new_idx
        new_idx="$(cat /sys/class/zram-control/hot_add)"
        if [ "zram$new_idx" != "$device" ]; then
            echo "error: requested $device but kernel hot_add created zram$new_idx" >&2
            echo "hint: rerun with --device zram$new_idx or pre-create the target device" >&2
            exit 1
        fi
        return
    fi

    echo "error: device /dev/$device not present and no zram-control hot_add support" >&2
    exit 1
}

is_swap_active() {
    local dev_path="$1"
    awk 'NR > 1 {print $1}' /proc/swaps | grep -qx "$dev_path"
}

read_sysfs_u64() {
    local path="$1"
    if [ -f "$path" ]; then
        cat "$path"
    else
        echo 0
    fi
}
