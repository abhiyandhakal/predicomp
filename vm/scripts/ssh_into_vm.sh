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
usage: $0 [--config vm/config/default.env] [ssh args...]
Convenience wrapper for SSH into the predicomp VM.
USAGE
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

vm_load_config "${CONFIG:-$DEFAULT_CONFIG}"
exec ssh -p "$VM_SSH_FWD_PORT" "${VM_GUEST_USER:-root}@127.0.0.1" "$@"
