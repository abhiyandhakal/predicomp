#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

CONFIG=""
USE_VNC=0
DAEMONIZE=0
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
    --daemonize)
      DAEMONIZE=1
      shift
      ;;
    --)
      shift
      EXTRA_ARGS=("$@")
      break
      ;;
    --help)
      cat <<USAGE
usage: $0 [--config vm/config/default.env] [--vnc] [--daemonize] [-- <extra qemu args>]
Boots the installed predicomp Arch VM with repo shared via 9p.
USAGE
      exit 0
      ;;
    *)
      vm_die "unknown arg: $1"
      ;;
  esac
done

vm_load_config "${CONFIG:-$DEFAULT_CONFIG}"
[[ -f "$VM_DISK_PATH_ABS" ]] || vm_die "disk image not found: $VM_DISK_PATH_ABS"
[[ -d "$VM_REPO_HOST_PATH_ABS" ]] || vm_die "repo path not found: $VM_REPO_HOST_PATH_ABS"

readarray -t COMMON_ARGS < <(vm_qemu_common_args)

QEMU_ARGS=( "$QEMU_BIN" "${COMMON_ARGS[@]}" )

if [[ $DAEMONIZE -eq 1 ]]; then
  PIDFILE="$VM_RUN_DIR_ABS/${VM_NAME}.pid"
  QEMU_ARGS+=( -daemonize -pidfile "$PIDFILE" )
fi

if [[ $USE_VNC -eq 1 ]]; then
  QEMU_ARGS+=( -display default )
elif [[ $DAEMONIZE -eq 1 ]]; then
  QEMU_ARGS+=( -display none -serial none )
else
  QEMU_ARGS+=( -nographic -serial mon:stdio )
fi

QEMU_ARGS+=("${EXTRA_ARGS[@]}")

echo "boot_vm=$VM_NAME"
echo "disk=$VM_DISK_PATH_ABS"
echo "repo_share=$VM_REPO_HOST_PATH_ABS -> tag=${VM_REPO_MOUNT_TAG}"
echo "ssh_hint=$(vm_print_ssh_hint)"
exec "${QEMU_ARGS[@]}"
