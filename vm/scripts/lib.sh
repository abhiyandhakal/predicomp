#!/usr/bin/env bash
set -euo pipefail

VM_SCRIPTS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="$(cd -- "$VM_SCRIPTS_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$VM_DIR/.." && pwd)"
DEFAULT_CONFIG="$VM_DIR/config/default.env"

vm_die() {
  echo "error: $*" >&2
  exit 1
}

vm_resolve_path() {
  local p="$1"
  if [[ "$p" = /* ]]; then
    printf '%s\n' "$p"
  else
    printf '%s/%s\n' "$REPO_ROOT" "$p"
  fi
}

vm_load_config() {
  local cfg_path="${1:-$DEFAULT_CONFIG}"
  cfg_path="$(vm_resolve_path "$cfg_path")"
  [[ -f "$cfg_path" ]] || vm_die "config not found: $cfg_path"
  # shellcheck disable=SC1090
  source "$cfg_path"

  : "${VM_NAME:?}" "${VM_RAM_MB:?}" "${VM_VCPUS:?}" "${VM_DISK_PATH:?}" "${QEMU_BIN:?}" "${QEMU_IMG_BIN:?}"
  : "${VM_SSH_FWD_PORT:?}" "${VM_REPO_HOST_PATH:?}" "${VM_REPO_MOUNT_TAG:?}" "${VM_REPO_GUEST_PATH:?}"

  VM_DISK_PATH_ABS="$(vm_resolve_path "$VM_DISK_PATH")"
  VM_REPO_HOST_PATH_ABS="$(vm_resolve_path "$VM_REPO_HOST_PATH")"
  VM_RUN_DIR_ABS="$(vm_resolve_path "vm/run")"
  mkdir -p "$(dirname "$VM_DISK_PATH_ABS")" "$VM_RUN_DIR_ABS"
}

vm_print_ssh_hint() {
  local user="${VM_GUEST_USER:-root}"
  echo "ssh -p ${VM_SSH_FWD_PORT} ${user}@127.0.0.1"
}

vm_qemu_common_args() {
  cat <<ARGS
-enable-kvm
-machine q35,accel=kvm
-cpu host
-smp ${VM_VCPUS}
-m ${VM_RAM_MB}
-device virtio-rng-pci
-drive
if=virtio,file=${VM_DISK_PATH_ABS},format=qcow2
-netdev
user,id=net0,hostfwd=tcp::${VM_SSH_FWD_PORT}-:22
-device
virtio-net-pci,netdev=net0
-virtfs
local,path=${VM_REPO_HOST_PATH_ABS},mount_tag=${VM_REPO_MOUNT_TAG},security_model=none,id=${VM_REPO_MOUNT_TAG}
ARGS
}
