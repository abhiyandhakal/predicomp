#!/usr/bin/env bash
set -euo pipefail

MOUNT_TAG="${1:-predicomp_repo}"
MOUNT_POINT="${2:-/mnt/predicomp}"

sudo mkdir -p "$MOUNT_POINT"
if mountpoint -q "$MOUNT_POINT"; then
  echo "already_mounted=$MOUNT_POINT"
  mount | grep " on $MOUNT_POINT " || true
  exit 0
fi

sudo mount -t 9p -o trans=virtio,version=9p2000.L "$MOUNT_TAG" "$MOUNT_POINT"

echo "mounted_9p_tag=$MOUNT_TAG"
echo "mounted_at=$MOUNT_POINT"
