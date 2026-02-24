#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

CONFIG=""
FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --help)
      cat <<USAGE
usage: $0 [--config vm/config/default.env] [--force]
Creates the qcow2 disk image for the predicomp VM lab.
USAGE
      exit 0
      ;;
    *)
      vm_die "unknown arg: $1"
      ;;
  esac
done

vm_load_config "${CONFIG:-$DEFAULT_CONFIG}"

if [[ -e "$VM_DISK_PATH_ABS" && $FORCE -ne 1 ]]; then
  vm_die "disk already exists: $VM_DISK_PATH_ABS (use --force to recreate)"
fi
if [[ -e "$VM_DISK_PATH_ABS" && $FORCE -eq 1 ]]; then
  rm -f -- "$VM_DISK_PATH_ABS"
fi

"$QEMU_IMG_BIN" create -f qcow2 "$VM_DISK_PATH_ABS" "${VM_DISK_SIZE_GB}G"
echo "created_disk=$VM_DISK_PATH_ABS"
