#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib.sh"

usage() {
    cat <<USAGE
usage: $0 [--device <zramN>] [--json]
USAGE
}

parse_common_args "$@"
if [ "${PARSE_COMMON_HELP:-0}" -eq 1 ]; then
    usage
    exit 0
fi
set -- "${REM_ARGS[@]}"

JSON=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --json)
            JSON=1
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

SYS_DIR="$(zram_sysfs_dir "$DEVICE")"
DEV_PATH="$(zram_dev_path "$DEVICE")"

if [ ! -d "$SYS_DIR" ]; then
    echo "error: $SYS_DIR does not exist" >&2
    exit 1
fi

orig_data_size="$(read_sysfs_u64 "$SYS_DIR/orig_data_size")"
compr_data_size="$(read_sysfs_u64 "$SYS_DIR/compr_data_size")"
mem_used_total="$(read_sysfs_u64 "$SYS_DIR/mem_used_total")"
num_reads="$(read_sysfs_u64 "$SYS_DIR/num_reads")"
num_writes="$(read_sysfs_u64 "$SYS_DIR/num_writes")"
zero_pages="$(read_sysfs_u64 "$SYS_DIR/zero_pages")"

swap_active=0
if is_swap_active "$DEV_PATH"; then
    swap_active=1
fi

ratio="$(awk -v o="$orig_data_size" -v c="$compr_data_size" 'BEGIN { if (o == 0) { printf "0.000000" } else { printf "%.6f", c / o } }')"
overhead_bytes="$(awk -v m="$mem_used_total" -v c="$compr_data_size" 'BEGIN { v = m - c; if (v < 0) v = 0; printf "%.0f", v }')"

if [ "$JSON" -eq 1 ]; then
    printf '{'
    printf '"device":"%s",' "$DEVICE"
    printf '"swap_active":%s,' "$swap_active"
    printf '"orig_data_size":%s,' "$orig_data_size"
    printf '"compr_data_size":%s,' "$compr_data_size"
    printf '"mem_used_total":%s,' "$mem_used_total"
    printf '"num_reads":%s,' "$num_reads"
    printf '"num_writes":%s,' "$num_writes"
    printf '"zero_pages":%s,' "$zero_pages"
    printf '"compression_ratio":%s,' "$ratio"
    printf '"overhead_bytes":%s' "$overhead_bytes"
    printf '}\n'
else
    echo "zram_status device=$DEVICE swap_active=$swap_active"
    echo "orig_data_size=$orig_data_size"
    echo "compr_data_size=$compr_data_size"
    echo "mem_used_total=$mem_used_total"
    echo "num_reads=$num_reads"
    echo "num_writes=$num_writes"
    echo "zero_pages=$zero_pages"
    echo "compression_ratio=$ratio"
    echo "overhead_bytes=$overhead_bytes"
fi
