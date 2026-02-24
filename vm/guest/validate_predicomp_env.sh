#!/usr/bin/env bash
set -euo pipefail

fail=0
warn=0

pass() { echo "PASS: $*"; }
warnf() { echo "WARN: $*" >&2; warn=1; }
failf() { echo "FAIL: $*" >&2; fail=1; }

check_bin() {
  local b="$1"
  if command -v "$b" >/dev/null 2>&1; then
    pass "binary $b -> $(command -v "$b")"
  else
    failf "missing binary: $b"
  fi
}

check_bin make
check_bin gcc
check_bin clang
check_bin bpftool
check_bin lz4

[[ -e /sys/kernel/btf/vmlinux ]] && pass "BTF present: /sys/kernel/btf/vmlinux" || failf "missing /sys/kernel/btf/vmlinux"
[[ -d /sys/kernel/mm/damon/admin ]] && pass "DAMON admin present" || failf "missing /sys/kernel/mm/damon/admin"

if [[ -d /sys/kernel/debug/tracing || -d /sys/kernel/tracing ]]; then
  pass "tracefs/debugfs tracing path present"
else
  warnf "no tracing path visible yet; mount debugfs/tracefs if needed"
fi

if mount | grep -q ' on /sys/kernel/debug '; then
  pass "debugfs mounted"
else
  warnf "debugfs not mounted (some probes/debug workflows may need it)"
fi

if [[ $fail -ne 0 ]]; then
  exit 1
fi

echo "Environment validation complete."
if [[ $warn -ne 0 ]]; then
  exit 0
fi
