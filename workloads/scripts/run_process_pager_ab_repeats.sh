#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
SINGLE_RUNNER="$ROOT_DIR/workloads/scripts/run_process_pager_ab.sh"
AGGREGATOR="$ROOT_DIR/workloads/scripts/aggregate_process_pager_ab.py"
PLOTTER="$ROOT_DIR/workloads/scripts/plot_process_pager_ab.py"
RESULTS_BASE_DEFAULT="$ROOT_DIR/workloads/results/process-pager-ab-repeats"

runs=5
duration_sec=10
results_dir=""
only_csv=""
build_first=1
plot_enabled=1

usage() {
    cat <<EOF
usage: $0 [options]

Run repeated baseline vs process-pager A/B experiments and aggregate/plot results.

options:
  --runs <n>             number of repeated A/B runs (default: ${runs})
  --duration-sec <n>     workload duration per run (default: ${duration_sec})
  --results-dir <path>   results root (default: workloads/results/process-pager-ab-repeats/<timestamp>)
  --only <csv>           workload subset (forwarded to single-run runner)
  --no-build             skip build steps on each run (forwarded)
  --plot                 run plotting after aggregation (default)
  --no-plot              skip plotting
  --help                 show this help

notes:
  - Run inside the VM as root.
  - Per-run raw outputs are preserved under runs/run-XXX/.
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "run as root inside the VM for process-pager/DAMON experiments"
    fi
}

timestamp_utc() {
    date -u +"%Y%m%d-%H%M%S"
}

json_escape() {
    python3 - "$1" <<'PY'
import json, sys
print(json.dumps(sys.argv[1]))
PY
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs)
            runs="$2"
            shift 2
            ;;
        --duration-sec)
            duration_sec="$2"
            shift 2
            ;;
        --results-dir)
            results_dir="$2"
            shift 2
            ;;
        --only)
            only_csv="$2"
            shift 2
            ;;
        --no-build)
            build_first=0
            shift
            ;;
        --plot)
            plot_enabled=1
            shift
            ;;
        --no-plot)
            plot_enabled=0
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            die "unknown arg: $1"
            ;;
    esac
done

require_root
[[ "$runs" =~ ^[0-9]+$ ]] || die "--runs must be a positive integer"
[[ "$runs" -ge 1 ]] || die "--runs must be >= 1"

if [[ -z "$results_dir" ]]; then
    results_dir="$RESULTS_BASE_DEFAULT/$(timestamp_utc)"
fi
mkdir -p "$results_dir/runs"

manifest_json="$results_dir/manifest.json"
all_long_csv="$results_dir/all_runs_long.csv"
agg_csv="$results_dir/aggregate.csv"
agg_summary="$results_dir/aggregate_summary.txt"
plots_dir="$results_dir/plots"

run_inputs=()
for ((i = 1; i <= runs; i++)); do
    run_dir="$results_dir/runs/run-$(printf '%03d' "$i")"
    mkdir -p "$run_dir"
    echo "[repeat] run $(printf '%03d' "$i")/$runs"

    cmd=("$SINGLE_RUNNER" "--duration-sec" "$duration_sec" "--results-dir" "$run_dir")
    if [[ -n "$only_csv" ]]; then
        cmd+=("--only" "$only_csv")
    fi
    if [[ "$build_first" -eq 0 ]]; then
        cmd+=("--no-build")
    fi
    "${cmd[@]}"

    [[ -f "$run_dir/comparison.csv" ]] || die "missing comparison.csv in $run_dir"
    run_inputs+=("$run_dir/comparison.csv")
done

python3 "$AGGREGATOR" \
    --inputs "${run_inputs[@]}" \
    --out-long "$all_long_csv" \
    --out-agg "$agg_csv" \
    --out-summary "$agg_summary"

if [[ "$plot_enabled" -eq 1 ]]; then
    mkdir -p "$plots_dir"
    if ! python3 "$PLOTTER" --long "$all_long_csv" --agg "$agg_csv" --out-dir "$plots_dir"; then
        echo "warn: plotting failed (matplotlib may be missing); aggregates are still available" >&2
    fi
fi

{
    echo "{"
    echo "  \"generated_utc\": $(json_escape "$(date -u +%FT%TZ)"),"
    echo "  \"hostname\": $(json_escape "$(hostname)"),"
    echo "  \"uname\": $(json_escape "$(uname -srvmo 2>/dev/null || uname -a)"),"
    echo "  \"runs\": $runs,"
    echo "  \"duration_sec\": $duration_sec,"
    echo "  \"only\": $(json_escape "$only_csv"),"
    echo "  \"plot_enabled\": $plot_enabled,"
    echo "  \"single_runner\": $(json_escape "$SINGLE_RUNNER"),"
    echo "  \"aggregate_csv\": $(json_escape "$agg_csv"),"
    echo "  \"all_runs_long_csv\": $(json_escape "$all_long_csv"),"
    echo "  \"aggregate_summary\": $(json_escape "$agg_summary")"
    echo "}"
} >"$manifest_json"

echo "results_dir=$results_dir"
echo "all_runs_long_csv=$all_long_csv"
echo "aggregate_csv=$agg_csv"
echo "aggregate_summary=$agg_summary"
if [[ "$plot_enabled" -eq 1 ]]; then
    echo "plots_dir=$plots_dir"
fi
