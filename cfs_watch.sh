#!/usr/bin/env bash

# ==============================
# Commonly Fair Scheduler Simulator
# Goal:
# 1. Create two processes, 
# 2. Update its NICE Value (One higher priority and another low priority
# 3. Observe its vruntime
# ==============================

set -e

echo "Starting two CPU-bound processes..."

yes > /dev/null &
P1=$!

yes > /dev/null &
P2=$!

echo "P1=$P1"
echo "P2=$P2"

# cleanup on exit
cleanup() {
    echo
    echo "Cleaning up..."
    kill $P1 $P2 2>/dev/null || true
    exit
}

trap cleanup INT TERM EXIT

sleep 1

echo
echo "Setting priorities..."
echo "P1 → high priority (-10)"
echo "P2 → low priority (+10)"

sudo renice -10 -p $P1 >/dev/null
renice 10 -p $P2 >/dev/null

sleep 1

# ==============================
# Choose what fields to watch
# Add/remove fields here
# ==============================

FIELDS=(
    "se.vruntime"
    "se.sum_exec_runtime"
    "se.load.weight"
    "nr_switches"
)

get_fields() {
    local pid=$1
    for f in "${FIELDS[@]}"; do
        grep "$f" /proc/$pid/sched | sed 's/^[ \t]*//'
    done
}

# ==============================
# Live display
# ==============================

echo "Watching scheduler stats (Ctrl+C to stop)..."

while true
do
    clear
    echo "========================================"
    echo " CFS Scheduler Observation"
    echo "========================================"
    echo

    printf "P1 (PID=%s, nice=%s)\n" "$P1" "$(ps -o ni= -p $P1)"
    echo "----------------------------------------"
    get_fields $P1 || echo "process ended"
    echo

    printf "P2 (PID=%s, nice=%s)\n" "$P2" "$(ps -o ni= -p $P2)"
    echo "----------------------------------------"
    get_fields $P2 || echo "process ended"
    echo

    echo "CPU usage:"
    ps -o pid,ni,pcpu,comm -p $P1,$P2

    sleep 1
done
