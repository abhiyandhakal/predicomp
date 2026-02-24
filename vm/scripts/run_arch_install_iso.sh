#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

CONFIG=""
USE_VNC=0
EXTRA_ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG="$2"
      shift 2
      ;;
    --vnc)
      USE_VNC=1
      shift
      ;;
    --)
      shift
      EXTRA_ARGS=("$@")
      break
      ;;
    --help)
      cat <<USAGE
usage: $0 [--config vm/config/default.env] [--vnc] [-- <extra qemu args>]
Boots the Arch installer ISO with QEMU/KVM for the predicomp VM lab.
USAGE
      exit 0
      ;;
    *)
      vm_die "unknown arg: $1"
      ;;
  esac
done

vm_load_config "${CONFIG:-$DEFAULT_CONFIG}"
[[ -n "${VM_ISO_PATH:-}" ]] || vm_die "VM_ISO_PATH is empty in config"
VM_ISO_PATH_ABS="$(vm_resolve_path "$VM_ISO_PATH")"
[[ -f "$VM_ISO_PATH_ABS" ]] || vm_die "ISO not found: $VM_ISO_PATH_ABS"
[[ -f "$VM_DISK_PATH_ABS" ]] || vm_die "disk image not found: $VM_DISK_PATH_ABS (run create_disk.sh)"

readarray -t COMMON_ARGS < <(vm_qemu_common_args)

QEMU_ARGS=(
  "$QEMU_BIN"
  "${COMMON_ARGS[@]}"
  -boot order=d
  -cdrom "$VM_ISO_PATH_ABS"
)

if [[ $USE_VNC -eq 1 ]]; then
  QEMU_ARGS+=( -display default )
else
  QEMU_ARGS+=( -nographic -serial mon:stdio )
fi

QEMU_ARGS+=("${EXTRA_ARGS[@]}")

printf 'Launching installer VM. SSH (after guest install): %s\n' "$(vm_print_ssh_hint)"
exec "${QEMU_ARGS[@]}"
