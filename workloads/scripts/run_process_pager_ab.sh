#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_BASE_DEFAULT="$ROOT_DIR/workloads/results/process-pager-ab"

duration_sec=10
results_dir=""
only_csv=""
sock_prefix="/tmp/predicomp-pager-ab"
build_first=1
time_bin=""

usage() {
    cat <<EOF
usage: $0 [options]

Run baseline vs cooperative process-pager A/B comparisons for pager-supported workloads.

options:
  --duration-sec <n>      workload duration for both runs (default: ${duration_sec})
  --results-dir <path>    results directory (default: workloads/results/process-pager-ab/<timestamp>)
  --only <csv>            comma-separated subset: interactive_burst,anon_streamer,random_touch_heap,mmap_churn
  --sock-prefix <path>    UNIX socket prefix for pager daemon (default: ${sock_prefix})
  --no-build              skip build steps
  --help                  show this help

notes:
  - Run inside the VM as root for the pager runs (DAMON + userfaultfd path).
  - This script runs two passes per workload:
      1) baseline (no pager)
      2) pager (process-pager enabled)
  - Outputs:
      * per-run workload stdout
      * GNU time -v metrics
      * pager daemon log/csv (pager run only)
      * comparison.csv + summary.txt
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "run as root (recommended inside VM) for process-pager/DAMON experiments"
    fi
}

timestamp_utc() {
    date -u +"%Y%m%d-%H%M%S"
}

sanitize_name() {
    echo "$1" | tr -c 'A-Za-z0-9._-' '_'
}

kv_get() {
    local file="$1"
    local key="$2"
    awk -v k="$key" '
        {
            for (i = 1; i <= NF; i++) {
                n = split($i, a, "=");
                if (n >= 2 && a[1] == k) {
                    sub(/^[^=]*=/, "", $i);
                    print $i;
                    exit;
                }
            }
        }
    ' "$file"
}

timev_get() {
    local file="$1"
    local prefix="$2"
    awk -F: -v p="$prefix" 'index($0, p) == 1 { sub(/^[^:]*:[[:space:]]*/, "", $0); print $0; exit }' "$file"
}

timev_cpu_pct() {
    local file="$1"
    awk -F: '/^Percent of CPU this job got:/ { gsub(/^[[:space:]]+|%$/, "", $2); print $2; exit }' "$file"
}

csv_get() {
    local csv="$1"
    local key="$2"
    awk -F, -v k="$key" '
        NR==1 {
            for (i = 1; i <= NF; i++) {
                if ($i == k) {
                    idx = i;
                    break;
                }
            }
            next
        }
        { last = $0 }
        END {
            if (idx == 0 || last == "") {
                exit 1;
            }
            n = split(last, a, ",");
            if (idx > n) {
                exit 1;
            }
            print a[idx];
        }
    ' "$csv"
}

build_bins() {
    local w="$1"
    if [[ "$build_first" -eq 0 ]]; then
        return 0
    fi
    make -C "$ROOT_DIR/process-pager" predicomp_pager >/dev/null
    make -C "$ROOT_DIR/workloads" "bin/$w" >/dev/null
}

detect_time_bin() {
    if [[ -x /usr/bin/time ]]; then
        time_bin="/usr/bin/time"
        return 0
    fi
    if [[ -x /bin/time ]]; then
        time_bin="/bin/time"
        return 0
    fi
    time_bin=""
    return 1
}

run_with_timev() {
    local timefile="$1"
    shift
    if [[ -n "$time_bin" ]]; then
        "$time_bin" -v -o "$timefile" "$@"
    else
        "$@" 
        : >"$timefile"
    fi
}

workload_cmd_args() {
    local w="$1"
    local mode="$2" # baseline|pager
    local -n out_ref="$3"

    out_ref=("$ROOT_DIR/workloads/bin/$w" "--duration-sec" "$duration_sec")
    case "$w" in
        interactive_burst)
            out_ref+=("--region-mb" "256" "--active-ms" "100" "--idle-ms" "400")
            ;;
        anon_streamer)
            out_ref+=("--region-mb" "512" "--idle-ms" "300")
            ;;
        random_touch_heap)
            out_ref+=("--region-mb" "512" "--ops-per-sec" "200000")
            ;;
        mmap_churn)
            out_ref+=("--map-kb" "512" "--ops-per-sec" "300")
            ;;
        *)
            return 1
            ;;
    esac
    if [[ "$mode" == "pager" ]]; then
        out_ref+=("--use-process-pager" "--pager-sock" "$pager_sock")
    fi
}

work_unit_key_for() {
    case "$1" in
        interactive_burst) echo "touches" ;;
        anon_streamer) echo "passes" ;;
        random_touch_heap|mmap_churn) echo "ops" ;;
        *) echo "ops" ;;
    esac
}

run_baseline() {
    local w="$1"
    local run_dir="$2"
    local outfile="$run_dir/baseline.workload.out"
    local timefile="$run_dir/baseline.timev.txt"
    local -a cmd

    workload_cmd_args "$w" baseline cmd
    run_with_timev "$timefile" "${cmd[@]}" >"$outfile" 2>&1
}

start_pager_daemon() {
    local run_dir="$1"
    pager_sock="$sock_prefix-$(sanitize_name "$workload")-$$.sock"
    pager_daemon_log="$run_dir/pager.daemon.log"
    pager_daemon_csv="$run_dir/pager.daemon.csv"

    rm -f "$pager_sock" "$pager_daemon_log" "$pager_daemon_csv"
    "$ROOT_DIR/process-pager/predicomp_pager" -s "$pager_sock" --csv "$pager_daemon_csv" >"$pager_daemon_log" 2>&1 &
    pager_daemon_pid=$!

    for _ in $(seq 1 100); do
        if [[ -S "$pager_sock" ]]; then
            return 0
        fi
        if ! kill -0 "$pager_daemon_pid" 2>/dev/null; then
            return 1
        fi
        sleep 0.1
    done
    return 1
}

stop_pager_daemon() {
    if [[ -n "${pager_daemon_pid:-}" ]]; then
        kill -INT "$pager_daemon_pid" 2>/dev/null || true
        wait "$pager_daemon_pid" || true
    fi
    rm -f "${pager_sock:-}"
}

run_pager() {
    local w="$1"
    local run_dir="$2"
    local outfile="$run_dir/pager.workload.out"
    local timefile="$run_dir/pager.timev.txt"
    local -a cmd

    start_pager_daemon "$run_dir" || die "pager daemon failed to start for $w (see $run_dir/pager.daemon.log)"
    workload_cmd_args "$w" pager cmd
    set +e
    run_with_timev "$timefile" "${cmd[@]}" >"$outfile" 2>&1
    pager_workload_rc=$?
    set -e
    sleep 1
    stop_pager_daemon
    if [[ "$pager_workload_rc" -ne 0 ]]; then
        die "pager workload failed for $w (see $outfile)"
    fi
    [[ -f "$pager_daemon_csv" ]] || die "missing pager daemon csv for $w"
}

write_compare_header() {
    cat >"$1" <<'EOF'
workload,work_unit_key,baseline_units,baseline_elapsed_ms,baseline_units_per_sec,baseline_cpu_pct,baseline_minor_faults,baseline_major_faults,baseline_maxrss_kb,pager_units,pager_elapsed_ms,pager_units_per_sec,pager_cpu_pct,pager_minor_faults,pager_major_faults,pager_maxrss_kb,units_per_sec_ratio_pager_vs_baseline,elapsed_ms_ratio_pager_vs_baseline,pager_daemon_cpu_pct_total,pager_bg_cpu_pct,pager_fault_cpu_pct,pager_compress_success,pager_faults_missing,pager_restore_success,pager_fault_missing_p95_ns,pager_fault_missing_p99_ns,pager_restore_wall_p95_ns,pager_restore_wall_p99_ns,pager_client_evict_success,pager_range_add_msgs,pager_range_del_msgs,pager_pages_tracked_peak,pager_process_madvise_unsupported
EOF
}

append_compare_row() {
    local csv="$1"
    local w="$2"
    local run_dir="$3"
    local work_key="$4"
    local b_out="$run_dir/baseline.workload.out"
    local b_time="$run_dir/baseline.timev.txt"
    local p_out="$run_dir/pager.workload.out"
    local p_time="$run_dir/pager.timev.txt"
    local p_csv="$run_dir/pager.daemon.csv"

    local b_units b_elapsed p_units p_elapsed
    local b_cpu p_cpu b_minflt b_majflt p_minflt p_majflt b_rss p_rss
    local b_ups p_ups ratio_ups ratio_elapsed

    b_units="$(kv_get "$b_out" "$work_key")"
    b_elapsed="$(kv_get "$b_out" "elapsed_ms")"
    p_units="$(kv_get "$p_out" "$work_key")"
    p_elapsed="$(kv_get "$p_out" "elapsed_ms")"

    b_cpu="$(timev_cpu_pct "$b_time")"
    p_cpu="$(timev_cpu_pct "$p_time")"
    b_minflt="$(timev_get "$b_time" "Minor (reclaiming a frame) page faults")"
    b_majflt="$(timev_get "$b_time" "Major (requiring I/O) page faults")"
    p_minflt="$(timev_get "$p_time" "Minor (reclaiming a frame) page faults")"
    p_majflt="$(timev_get "$p_time" "Major (requiring I/O) page faults")"
    b_rss="$(timev_get "$b_time" "Maximum resident set size (kbytes)")"
    p_rss="$(timev_get "$p_time" "Maximum resident set size (kbytes)")"

    b_ups="$(awk -v u="${b_units:-0}" -v ms="${b_elapsed:-0}" 'BEGIN{ if (ms <= 0) print 0; else printf "%.6f", (u*1000.0)/ms; }')"
    p_ups="$(awk -v u="${p_units:-0}" -v ms="${p_elapsed:-0}" 'BEGIN{ if (ms <= 0) print 0; else printf "%.6f", (u*1000.0)/ms; }')"
    ratio_ups="$(awk -v a="${b_ups:-0}" -v b="${p_ups:-0}" 'BEGIN{ if (a <= 0) print 0; else printf "%.6f", b/a; }')"
    ratio_elapsed="$(awk -v a="${b_elapsed:-0}" -v b="${p_elapsed:-0}" 'BEGIN{ if (a <= 0) print 0; else printf "%.6f", b/a; }')"

    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" \
        "$w" "$work_key" \
        "${b_units:-0}" "${b_elapsed:-0}" "$b_ups" "${b_cpu:-0}" "${b_minflt:-0}" "${b_majflt:-0}" "${b_rss:-0}" \
        "${p_units:-0}" "${p_elapsed:-0}" "$p_ups" "${p_cpu:-0}" "${p_minflt:-0}" "${p_majflt:-0}" "${p_rss:-0}" \
        "$ratio_ups" "$ratio_elapsed" >>"$csv"

    for key in \
        daemon_cpu_pct_total bg_thread_cpu_pct fault_thread_cpu_pct \
        compress_success faults_missing_total restore_success \
        fault_missing_p95_ns fault_missing_p99_ns \
        restore_wall_p95_ns restore_wall_p99_ns \
        client_evict_success range_add_msgs range_del_msgs pages_tracked_peak process_madvise_unsupported
    do
        printf ",%s" "$(csv_get "$p_csv" "$key" 2>/dev/null || echo 0)" >>"$csv"
    done
    printf "\n" >>"$csv"
}

write_summary_txt() {
    local csv="$1"
    local out="$2"
    {
        echo "process-pager A/B summary"
        echo "source_csv=$csv"
        echo
        column -s, -t "$csv" || cat "$csv"
    } >"$out"
}

workloads=(interactive_burst anon_streamer random_touch_heap mmap_churn)

while [[ $# -gt 0 ]]; do
    case "$1" in
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
        --sock-prefix)
            sock_prefix="$2"
            shift 2
            ;;
        --no-build)
            build_first=0
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
detect_time_bin || echo "warn: GNU time not found; skipping /usr/bin/time -v metrics" >&2

if [[ -n "$only_csv" ]]; then
    IFS=, read -r -a workloads <<<"$only_csv"
fi

if [[ -z "$results_dir" ]]; then
    results_dir="$RESULTS_BASE_DEFAULT/$(timestamp_utc)"
fi
mkdir -p "$results_dir"

compare_csv="$results_dir/comparison.csv"
summary_txt="$results_dir/summary.txt"
write_compare_header "$compare_csv"

for workload in "${workloads[@]}"; do
    case "$workload" in
        interactive_burst|anon_streamer|random_touch_heap|mmap_churn) ;;
        *) die "unsupported workload for process-pager A/B: $workload" ;;
    esac

    run_dir="$results_dir/$workload"
    mkdir -p "$run_dir"
    echo "[run] $workload baseline"
    build_bins "$workload"
    run_baseline "$workload" "$run_dir"
    echo "[run] $workload pager"
    run_pager "$workload" "$run_dir"

    work_key="$(work_unit_key_for "$workload")"
    append_compare_row "$compare_csv" "$workload" "$run_dir" "$work_key"
done

write_summary_txt "$compare_csv" "$summary_txt"

echo "results_dir=$results_dir"
echo "comparison_csv=$compare_csv"
echo "summary_txt=$summary_txt"
