#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
RESULTS_BASE_DEFAULT="$ROOT_DIR/workloads/results/controller-matrix"

delay_sec=10
duration_sec=20
results_dir=""
only_csv=""
quiet_controller=0

usage() {
    cat <<EOF
usage: $0 [options]
  --results-dir <path>   results root (default workloads/results/controller-matrix/<timestamp>)
  --delay-sec <n>        controller compression trigger delay in seconds (default: ${delay_sec})
  --duration-sec <n>     per-workload duration (default: ${duration_sec})
  --only <csv>           run only selected workloads (comma-separated names)
  --quiet-controller     pass --quiet to workload_controller

Notes:
  - Run this script as root (recommended) so controller and workloads can share the UDS cleanly.
  - A fresh controller is started for each workload run.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --results-dir)
            results_dir="$2"
            shift 2
            ;;
        --delay-sec)
            delay_sec="$2"
            shift 2
            ;;
        --duration-sec)
            duration_sec="$2"
            shift 2
            ;;
        --only)
            only_csv="$2"
            shift 2
            ;;
        --quiet-controller)
            quiet_controller=1
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ $(id -u) -ne 0 ]]; then
    echo "run as root so controller and workloads share the controller socket without permission issues" >&2
    exit 1
fi

if [[ -z "$results_dir" ]]; then
    ts=$(date +%Y%m%d-%H%M%S)
    results_dir="${RESULTS_BASE_DEFAULT}/${ts}"
fi

mkdir -p "$results_dir"

CONTROLLER_BIN="$ROOT_DIR/workload_controller"
if [[ ! -x "$CONTROLLER_BIN" ]]; then
    echo "missing $CONTROLLER_BIN (build with: make workload_controller)" >&2
    exit 1
fi

declare -a ALL_WORKLOADS=(
    anon_streamer
    interactive_burst
    random_touch_heap
    mmap_churn
    fork_exit_storm
    fork_touch_exit
    fork_exec_storm
)

is_triggerable_workload() {
    case "$1" in
        anon_streamer|interactive_burst|random_touch_heap|mmap_churn) return 0 ;;
        *) return 1 ;;
    esac
}

is_selected_workload() {
    local name="$1"
    if [[ -z "$only_csv" ]]; then
        return 0
    fi
    IFS=',' read -r -a _sel <<<"$only_csv"
    local item
    for item in "${_sel[@]}"; do
        if [[ "$item" == "$name" ]]; then
            return 0
        fi
    done
    return 1
}

build_workload_cmd() {
    local name="$1"
    local -n out_ref="$2"
    out_ref=("$ROOT_DIR/workloads/bin/$name" "--duration-sec" "$duration_sec")

    case "$name" in
        anon_streamer)
            out_ref+=("--region-mb" "512" "--idle-ms" "300" "--use-mem-arena" "--arena-cap-mb" "256" "--controller-enroll" "--compress-policy" "external")
            ;;
        interactive_burst)
            out_ref+=("--region-mb" "256" "--active-ms" "100" "--idle-ms" "400" "--use-mem-arena" "--arena-cap-mb" "128" "--controller-enroll" "--compress-policy" "external")
            ;;
        random_touch_heap)
            out_ref+=("--region-mb" "512" "--ops-per-sec" "400000" "--use-mem-arena" "--arena-cap-mb" "256" "--controller-enroll" "--compress-policy" "external")
            ;;
        mmap_churn)
            out_ref+=("--map-kb" "512" "--ops-per-sec" "500" "--use-mem-arena" "--arena-region-mb" "128" "--arena-cap-mb" "128" "--controller-enroll" "--compress-policy" "external")
            ;;
        fork_exit_storm)
            out_ref+=("--workers" "4" "--fork-rate" "20")
            ;;
        fork_touch_exit)
            out_ref+=("--workers" "4" "--fork-rate" "20" "--touch-pages" "64")
            ;;
        fork_exec_storm)
            out_ref+=("--workers" "2" "--fork-rate" "10" "--exec-path" "/bin/true")
            ;;
        *)
            echo "unknown workload in build_workload_cmd: $name" >&2
            return 1
            ;;
    esac

    out_ref+=("--json")
}

write_summary_json() {
    local csv_path="$1"
    local summary_path="$2"
    local workload="$3"
    local target_pid="$4"
    local target_class="$5"

    awk -F, -v workload="$workload" -v target_pid="$target_pid" -v target_class="$target_class" '
        NR == 1 {
            for (i = 1; i <= NF; i++) {
                h[$i] = i;
            }
            next;
        }
        {
            rows_total++;
            pid = $(h["pid"]) + 0;
            lineage_root_pid = 0;
            if ("lineage_root_pid" in h) {
                lineage_root_pid = $(h["lineage_root_pid"]) + 0;
            }
            is_target = (pid == target_pid || lineage_root_pid == target_pid);
            if (is_target) {
                target_tree_rows++;
                if ($(h["enrolled"]) + 0 == 1) {
                    target_enrolled_rows++;
                }
                if ($(h["compress_sent"]) + 0 == 1) {
                    target_triggered_rows++;
                }
                if ($(h["compress_ack"]) + 0 == 1) {
                    target_acked_rows++;
                }
                if ($(h["missed_due_to_no_enroll"]) + 0 == 1) {
                    target_missed_no_enroll_rows++;
                }

                exit_ns = ("exit_event_ns" in h) ? ($(h["exit_event_ns"]) + 0) : 0;
                deadline_ns = ("deadline_ns" in h) ? ($(h["deadline_ns"]) + 0) : 0;
                compress_sent = $(h["compress_sent"]) + 0;
                exited = $(h["exited"]) + 0;
                if (target_class == "observe_only") {
                    skipped_ineligible_rows++;
                } else if (exited == 1 && compress_sent == 0 && exit_ns > 0 && deadline_ns > 0 && exit_ns < deadline_ns) {
                    skipped_ineligible_rows++;
                }
            } else {
                background_rows++;
            }

            if ($(h["compress_sent"]) + 0 == 1) {
                rows_compress_sent++;
            }
            if ($(h["compress_ack"]) + 0 == 1) {
                rows_compress_ack++;
            }
        }
        END {
            printf("{\n");
            printf("  \"workload\": \"%s\",\n", workload);
            printf("  \"target_pid\": %d,\n", target_pid);
            printf("  \"target_class\": \"%s\",\n", target_class);
            printf("  \"rows_total\": %d,\n", rows_total + 0);
            printf("  \"target_tree_rows\": %d,\n", target_tree_rows + 0);
            printf("  \"background_rows\": %d,\n", background_rows + 0);
            printf("  \"target_enrolled_rows\": %d,\n", target_enrolled_rows + 0);
            printf("  \"target_triggered_rows\": %d,\n", target_triggered_rows + 0);
            printf("  \"target_acked_rows\": %d,\n", target_acked_rows + 0);
            printf("  \"target_missed_no_enroll_rows\": %d,\n", target_missed_no_enroll_rows + 0);
            printf("  \"skipped_ineligible_rows\": %d,\n", skipped_ineligible_rows + 0);
            printf("  \"rows_compress_sent\": %d,\n", rows_compress_sent + 0);
            printf("  \"rows_compress_ack\": %d\n", rows_compress_ack + 0);
            printf("}\n");
        }
    ' "$csv_path" >"$summary_path"
}

manifest_csv="$results_dir/manifest.csv"
echo "workload,target_class,target_pid,workload_exit_code,run_dir" >"$manifest_csv"

for workload in "${ALL_WORKLOADS[@]}"; do
    if ! is_selected_workload "$workload"; then
        continue
    fi

    run_dir="$results_dir/$workload"
    mkdir -p "$run_dir"

    controller_log="$run_dir/controller.log"
    controller_csv="$run_dir/controller.csv"
    workload_stdout="$run_dir/workload.stdout"
    summary_json="$run_dir/summary.json"
    controller_sock="/tmp/predicomp-controller-${workload}-$$.sock"

    controller_cmd=("$CONTROLLER_BIN" "--delay-sec" "$delay_sec" "--sock-path" "$controller_sock" "--csv" "$controller_csv")
    if [[ "$quiet_controller" -eq 1 ]]; then
        controller_cmd+=("--quiet")
    fi

    echo "[run] controller -> $workload" | tee -a "$results_dir/runner.log"
    "${controller_cmd[@]}" >"$controller_log" 2>&1 &
    controller_pid=$!
    sleep 1
    if ! kill -0 "$controller_pid" 2>/dev/null; then
        echo "controller failed to start for $workload (see $controller_log)" >&2
        wait "$controller_pid" || true
        exit 1
    fi

    declare -a workload_cmd
    build_workload_cmd "$workload" workload_cmd
    workload_cmd+=("--controller-sock" "$controller_sock")

    echo "[run] workload $workload" | tee -a "$results_dir/runner.log"
    "${workload_cmd[@]}" >"$workload_stdout" 2>&1 &
    workload_pid=$!
    wait "$workload_pid"
    workload_rc=$?

    kill -INT "$controller_pid" 2>/dev/null || true
    wait "$controller_pid" || true

    if is_triggerable_workload "$workload"; then
        target_class="triggerable"
    else
        target_class="observe_only"
    fi

    if [[ -f "$controller_csv" ]]; then
        write_summary_json "$controller_csv" "$summary_json" "$workload" "$workload_pid" "$target_class"
    else
        cat >"$summary_json" <<EOF
{
  "workload": "$workload",
  "target_pid": $workload_pid,
  "target_class": "$target_class",
  "error": "missing controller.csv"
}
EOF
    fi

    echo "$workload,$target_class,$workload_pid,$workload_rc,$run_dir" >>"$manifest_csv"
done

echo "results_dir=$results_dir"
