#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

CONFIG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      CONFIG="$2"
      shift 2
      ;;
    --help)
      cat <<USAGE
usage: $0 [--config vm/config/default.env]
Checks host prerequisites for the predicomp QEMU/KVM VM lab.
USAGE
      exit 0
      ;;
    *)
      vm_die "unknown arg: $1"
      ;;
  esac
done

vm_load_config "${CONFIG:-$DEFAULT_CONFIG}"

fail=0

check_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "FAIL: missing binary: $bin" >&2
    fail=1
  else
    echo "PASS: found $bin -> $(command -v "$bin")"
  fi
}

check_bin "$QEMU_BIN"
check_bin "$QEMU_IMG_BIN"
check_bin bash

if [[ ! -e /dev/kvm ]]; then
  echo "FAIL: /dev/kvm not found (KVM acceleration unavailable)" >&2
  fail=1
else
  echo "PASS: /dev/kvm exists"
fi

if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo "WARN: current user may not be able to access /dev/kvm (group membership?)" >&2
else
  echo "PASS: current user can read/write /dev/kvm"
fi

if [[ ! -d "$VM_REPO_HOST_PATH_ABS" ]]; then
  echo "FAIL: repo path not found: $VM_REPO_HOST_PATH_ABS" >&2
  fail=1
else
  echo "PASS: repo path exists: $VM_REPO_HOST_PATH_ABS"
fi

if [[ $fail -ne 0 ]]; then
  exit 1
fi

echo "Host looks ready for VM lab setup."
