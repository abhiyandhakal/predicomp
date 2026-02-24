#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "$0")/.." && pwd)"
PKG_FILE="$ROOT_DIR/config/guest-packages.txt"

if [[ ! -f "$PKG_FILE" ]]; then
  echo "missing package list: $PKG_FILE" >&2
  exit 1
fi

mapfile -t PKGS < <(grep -v '^[[:space:]]*#' "$PKG_FILE" | sed '/^[[:space:]]*$/d')

sudo pacman -Sy --needed "${PKGS[@]}"

sudo systemctl enable --now sshd

echo "Guest package install complete."
echo "Record package versions for pinning:" 
echo "  pacman -Q linux linux-headers clang llvm bpftool libbpf lz4 gcc make | tee $PKG_FILE"
echo "Optional: configure IgnorePkg=linux linux-headers in /etc/pacman.conf for kernel pinning."
