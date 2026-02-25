#!/usr/bin/env python3
import argparse
import csv
import math
import os
import sys
from typing import Dict, List, Tuple


NUMERIC_METRICS = [
    "baseline_units",
    "baseline_elapsed_ms",
    "baseline_units_per_sec",
    "baseline_cpu_pct",
    "baseline_minor_faults",
    "baseline_major_faults",
    "baseline_maxrss_kb",
    "pager_units",
    "pager_elapsed_ms",
    "pager_units_per_sec",
    "pager_cpu_pct",
    "pager_minor_faults",
    "pager_major_faults",
    "pager_maxrss_kb",
    "units_per_sec_ratio_pager_vs_baseline",
    "elapsed_ms_ratio_pager_vs_baseline",
    "pager_daemon_cpu_pct_total",
    "pager_bg_cpu_pct",
    "pager_fault_cpu_pct",
    "pager_compress_success",
    "pager_faults_missing",
    "pager_restore_success",
    "pager_fault_missing_p95_ns",
    "pager_fault_missing_p99_ns",
    "pager_restore_wall_p95_ns",
    "pager_restore_wall_p99_ns",
    "pager_client_evict_success",
    "pager_range_add_msgs",
    "pager_range_del_msgs",
    "pager_pages_tracked_peak",
    "pager_process_madvise_unsupported",
]


SUMMARY_METRICS = [
    "units_per_sec_ratio_pager_vs_baseline",
    "elapsed_ms_ratio_pager_vs_baseline",
    "pager_daemon_cpu_pct_total",
    "pager_bg_cpu_pct",
    "pager_fault_cpu_pct",
    "pager_fault_missing_p99_ns",
    "pager_restore_wall_p99_ns",
    "pager_compress_success",
    "pager_faults_missing",
    "pager_restore_success",
]


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Aggregate repeated process-pager A/B comparison.csv files"
    )
    ap.add_argument(
        "--inputs",
        nargs="+",
        required=True,
        help="comparison.csv files (from repeated runs)",
    )
    ap.add_argument("--out-long", required=True, help="Output long-form CSV path")
    ap.add_argument("--out-agg", required=True, help="Output aggregate CSV path")
    ap.add_argument("--out-summary", required=True, help="Output summary text path")
    return ap.parse_args()


def to_float(s: str):
    if s is None or s == "":
        return None
    try:
        return float(s)
    except ValueError:
        return None


def nearest_rank(values: List[float], p: float) -> float:
    if not values:
        return 0.0
    if p <= 0:
        return values[0]
    if p >= 100:
        return values[-1]
    rank = math.ceil((p / 100.0) * len(values))
    idx = max(1, rank) - 1
    return values[idx]


def pop_stddev(values: List[float], mean: float) -> float:
    if not values:
        return 0.0
    return math.sqrt(sum((x - mean) ** 2 for x in values) / len(values))


def load_rows(input_paths: List[str]) -> Tuple[List[Dict[str, str]], List[str]]:
    all_rows: List[Dict[str, str]] = []
    expected_header: List[str] = []

    for idx, path in enumerate(input_paths, start=1):
        with open(path, newline="") as fp:
            reader = csv.DictReader(fp)
            header = reader.fieldnames or []
            if not expected_header:
                expected_header = header
            elif header != expected_header:
                raise RuntimeError(f"schema mismatch in {path}")
            for row in reader:
                row = dict(row)
                row["run_id"] = f"run-{idx:03d}"
                row["source_csv"] = path
                all_rows.append(row)
    return all_rows, expected_header


def write_long_csv(path: str, rows: List[Dict[str, str]], base_header: List[str]) -> None:
    header = ["run_id", "source_csv"] + base_header
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=header)
        writer.writeheader()
        for row in rows:
            out = {k: row.get(k, "") for k in header}
            writer.writerow(out)


def aggregate(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    groups: Dict[Tuple[str, str], List[Dict[str, str]]] = {}
    for row in rows:
        key = (row.get("workload", ""), row.get("work_unit_key", ""))
        groups.setdefault(key, []).append(row)

    out_rows: List[Dict[str, str]] = []
    for (workload, work_unit_key), grows in sorted(groups.items()):
        out: Dict[str, str] = {
            "workload": workload,
            "work_unit_key": work_unit_key,
            "runs_n": str(len(grows)),
        }
        for metric in NUMERIC_METRICS:
            vals = [to_float(r.get(metric, "")) for r in grows]
            vals = [v for v in vals if v is not None]
            vals.sort()
            prefix = metric
            out[f"{prefix}__n"] = str(len(vals))
            if not vals:
                for suffix in ["min", "p50", "p95", "max", "mean", "stddev", "iqr"]:
                    out[f"{prefix}__{suffix}"] = "0"
                continue
            mean = sum(vals) / len(vals)
            q1 = nearest_rank(vals, 25)
            q3 = nearest_rank(vals, 75)
            out[f"{prefix}__min"] = f"{vals[0]:.6f}"
            out[f"{prefix}__p50"] = f"{nearest_rank(vals, 50):.6f}"
            out[f"{prefix}__p95"] = f"{nearest_rank(vals, 95):.6f}"
            out[f"{prefix}__max"] = f"{vals[-1]:.6f}"
            out[f"{prefix}__mean"] = f"{mean:.6f}"
            out[f"{prefix}__stddev"] = f"{pop_stddev(vals, mean):.6f}"
            out[f"{prefix}__iqr"] = f"{(q3 - q1):.6f}"
        out_rows.append(out)
    return out_rows


def write_agg_csv(path: str, rows: List[Dict[str, str]]) -> None:
    if not rows:
        raise RuntimeError("no rows to aggregate")
    keys = ["workload", "work_unit_key", "runs_n"]
    metric_keys = []
    for k in rows[0].keys():
        if k in keys:
            continue
        metric_keys.append(k)
    header = keys + sorted(metric_keys)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as fp:
        writer = csv.DictWriter(fp, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in header})


def write_summary(path: str, rows: List[Dict[str, str]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fp:
        fp.write("process-pager A/B aggregate summary\n\n")
        if not rows:
            fp.write("(no rows)\n")
            return
        cols = ["workload", "runs_n"]
        for m in SUMMARY_METRICS:
            cols.extend([f"{m}__p50", f"{m}__p95"])

        # compute widths
        widths = {c: len(c) for c in cols}
        for row in rows:
            for c in cols:
                widths[c] = max(widths[c], len(row.get(c, "")))

        def write_row(values: Dict[str, str]):
            fp.write("  ".join(values.get(c, "").ljust(widths[c]) for c in cols) + "\n")

        write_row({c: c for c in cols})
        write_row({c: "-" * widths[c] for c in cols})
        for row in rows:
            write_row(row)


def main() -> int:
    args = parse_args()
    rows, header = load_rows(args.inputs)
    if not rows:
        raise RuntimeError("no data rows found in inputs")
    write_long_csv(args.out_long, rows, header)
    agg_rows = aggregate(rows)
    write_agg_csv(args.out_agg, agg_rows)
    write_summary(args.out_summary, agg_rows)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        raise
