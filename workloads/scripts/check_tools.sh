#!/usr/bin/env bash
set -euo pipefail

TOOLS=(stress-ng mmtests phoronix-test-suite sysbench fio)

echo "tool availability:"
for t in "${TOOLS[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
        printf "  [ok] %s -> %s\n" "$t" "$(command -v "$t")"
    else
        printf "  [missing] %s\n" "$t"
    fi
done

cat <<'EOT'

Install hints:

Ubuntu/Debian:
  sudo apt-get update
  sudo apt-get install -y stress-ng fio sysbench phoronix-test-suite
  # mmtests is usually source-based:
  # git clone https://github.com/gormanm/mmtests.git

Arch Linux:
  sudo pacman -S --needed stress-ng fio sysbench phoronix-test-suite
  # mmtests is typically AUR/source-based:
  # git clone https://github.com/gormanm/mmtests.git

Generic/source:
  stress-ng: https://github.com/ColinIanKing/stress-ng
  mmtests: https://github.com/gormanm/mmtests
  Phoronix Test Suite: https://www.phoronix-test-suite.com/documentation/
  sysbench: https://github.com/akopytov/sysbench
  fio: https://github.com/axboe/fio
EOT
