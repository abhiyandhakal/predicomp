#!/usr/bin/env python3
import argparse
import csv
import os
import sys
from typing import Dict, List, Optional


WORKLOAD_ORDER = [
    "interactive_burst",
    "anon_streamer",
    "random_touch_heap",
    "mmap_churn",
]

WORKLOAD_COLORS = {
    "interactive_burst": "#1f77b4",
    "anon_streamer": "#2ca02c",
    "random_touch_heap": "#d62728",
    "mmap_churn": "#9467bd",
}


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Plot process-pager A/B aggregate results")
    ap.add_argument("--long", required=True, help="all_runs_long.csv")
    ap.add_argument("--agg", required=True, help="aggregate.csv")
    ap.add_argument("--out-dir", required=True, help="output plots directory")
    return ap.parse_args()


def read_csv(path: str) -> List[Dict[str, str]]:
    with open(path, newline="") as fp:
        return list(csv.DictReader(fp))


def to_float(v: Optional[str]) -> Optional[float]:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except ValueError:
        return None


def ordered_rows(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    order = {w: i for i, w in enumerate(WORKLOAD_ORDER)}
    return sorted(rows, key=lambda r: (order.get(r.get("workload", ""), 999), r.get("workload", "")))


def save(fig, out_dir: str, name: str) -> None:
    png = os.path.join(out_dir, f"{name}.png")
    svg = os.path.join(out_dir, f"{name}.svg")
    fig.savefig(png, dpi=140, bbox_inches="tight")
    fig.savefig(svg, bbox_inches="tight")


def paired_metric_rows(
    rows: List[Dict[str, str]],
    metric_p95: str,
    metric_p99: str,
) -> List[Dict[str, float]]:
    out = []
    for r in ordered_rows(rows):
        v95 = to_float(r.get(f"{metric_p95}__p50"))
        v99 = to_float(r.get(f"{metric_p99}__p50"))
        if v95 is None and v99 is None:
            continue
        out.append(
            {
                "workload": r.get("workload", ""),
                "p95": v95 or 0.0,
                "p99": v99 or 0.0,
            }
        )
    return out


def plot_bar_ratio(rows, plt, out_dir: str, metric: str, title: str, ylabel: str, filename: str):
    rows = ordered_rows(rows)
    names = [r["workload"] for r in rows]
    vals = [to_float(r.get(f"{metric}__p50")) or 0.0 for r in rows]
    mins = [to_float(r.get(f"{metric}__min")) or 0.0 for r in rows]
    maxs = [to_float(r.get(f"{metric}__max")) or 0.0 for r in rows]

    x = list(range(len(names)))
    colors = [WORKLOAD_COLORS.get(n, "#666666") for n in names]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(x, vals, color=colors)
    err_low = [max(0.0, v - mn) for v, mn in zip(vals, mins)]
    err_high = [max(0.0, mx - v) for v, mx in zip(vals, maxs)]
    ax.errorbar(x, vals, yerr=[err_low, err_high], fmt="none", ecolor="#333333", capsize=4, linewidth=1)
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right")
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.axhline(1.0, color="#555555", linestyle="--", linewidth=1)
    for i, v in enumerate(vals):
        ax.text(i, v, f"{v:.2f}", ha="center", va="bottom", fontsize=8)
    save(fig, out_dir, filename)
    plt.close(fig)


def plot_cpu_breakdown(rows, plt, out_dir: str):
    rows = ordered_rows(rows)
    names = [r["workload"] for r in rows]
    bg = [to_float(r.get("pager_bg_cpu_pct__p50")) or 0.0 for r in rows]
    fault = [to_float(r.get("pager_fault_cpu_pct__p50")) or 0.0 for r in rows]
    total = [to_float(r.get("pager_daemon_cpu_pct_total__p50")) or 0.0 for r in rows]
    ctrl = [max(0.0, t - b - f) for t, b, f in zip(total, bg, fault)]
    x = list(range(len(names)))

    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.bar(x, bg, label="bg", color="#1f77b4")
    ax.bar(x, fault, bottom=bg, label="fault", color="#d62728")
    ax.bar(x, ctrl, bottom=[b + f for b, f in zip(bg, fault)], label="control/other", color="#7f7f7f")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right")
    ax.set_title("Pager Daemon CPU Breakdown (median)")
    ax.set_ylabel("CPU % of session wall time")
    ax.legend()
    save(fig, out_dir, "pager_daemon_cpu_breakdown")
    plt.close(fig)


def plot_latency_groups(rows, plt, out_dir: str, metric_p95: str, metric_p99: str, title: str, filename: str):
    trips = paired_metric_rows(rows, metric_p95, metric_p99)
    if not trips:
        return
    names = [t["workload"] for t in trips]
    p95 = [t["p95"] for t in trips]
    p99 = [t["p99"] for t in trips]
    x = list(range(len(names)))
    width = 0.36
    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.bar([i - width / 2 for i in x], p95, width=width, label="p95", color="#2ca02c")
    ax.bar([i + width / 2 for i in x], p99, width=width, label="p99", color="#d62728")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right")
    ax.set_title(title)
    ax.set_ylabel("nanoseconds")
    ax.set_yscale("log")
    ax.legend()
    save(fig, out_dir, filename)
    plt.close(fig)


def plot_activity_counts(rows, plt, out_dir: str):
    rows = ordered_rows(rows)
    names = [r["workload"] for r in rows]
    comp = [to_float(r.get("pager_compress_success__p50")) or 0.0 for r in rows]
    miss = [to_float(r.get("pager_faults_missing__p50")) or 0.0 for r in rows]
    rest = [to_float(r.get("pager_restore_success__p50")) or 0.0 for r in rows]
    x = list(range(len(names)))
    width = 0.25
    fig, ax = plt.subplots(figsize=(8.4, 4.8))
    ax.bar([i - width for i in x], comp, width=width, label="compress_success", color="#1f77b4")
    ax.bar(x, miss, width=width, label="faults_missing", color="#ff7f0e")
    ax.bar([i + width for i in x], rest, width=width, label="restore_success", color="#2ca02c")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=20, ha="right")
    ax.set_title("Pager Activity Counts (median)")
    ax.set_ylabel("count")
    ax.legend()
    save(fig, out_dir, "pager_activity_counts")
    plt.close(fig)


def plot_mmap_churn_special(rows, plt, out_dir: str):
    row = None
    for r in rows:
        if r.get("workload") == "mmap_churn":
            row = r
            break
    if row is None:
        return
    labels = ["range_add", "range_del", "faults_missing", "compress_success"]
    vals = [
        to_float(row.get("pager_range_add_msgs__p50")) or 0.0,
        to_float(row.get("pager_range_del_msgs__p50")) or 0.0,
        to_float(row.get("pager_faults_missing__p50")) or 0.0,
        to_float(row.get("pager_compress_success__p50")) or 0.0,
    ]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    ax.bar(labels, vals, color=["#1f77b4", "#17becf", "#ff7f0e", "#2ca02c"])
    ax.set_title("mmap_churn Dynamic Range Ops vs Faults (median)")
    ax.set_ylabel("count")
    ax.set_yscale("log")
    for i, v in enumerate(vals):
        ax.text(i, v if v > 0 else 1, f"{int(v)}", ha="center", va="bottom", fontsize=8)
    save(fig, out_dir, "mmap_churn_range_ops_vs_faults")
    plt.close(fig)


def plot_cpu_vs_throughput(rows, plt, out_dir: str):
    rows = ordered_rows(rows)
    xs = []
    ys = []
    labels = []
    for r in rows:
        x = to_float(r.get("pager_daemon_cpu_pct_total__p50"))
        y = to_float(r.get("units_per_sec_ratio_pager_vs_baseline__p50"))
        if x is None or y is None:
            continue
        xs.append(x)
        ys.append(y)
        labels.append(r["workload"])
    if not xs:
        return
    fig, ax = plt.subplots(figsize=(6.8, 4.8))
    for x, y, label in zip(xs, ys, labels):
        ax.scatter([x], [y], s=60, color=WORKLOAD_COLORS.get(label, "#666666"), label=label)
        ax.text(x, y, f" {label}", va="center", fontsize=8)
    ax.set_xlabel("Pager daemon CPU % (median)")
    ax.set_ylabel("Throughput ratio pager/baseline (median)")
    ax.axhline(1.0, color="#555555", linestyle="--", linewidth=1)
    ax.set_title("Pager CPU vs Throughput Impact")
    save(fig, out_dir, "pager_cpu_vs_throughput_ratio")
    plt.close(fig)


def main() -> int:
    args = parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    agg_rows = read_csv(args.agg)
    _ = read_csv(args.long)  # ensure file exists/parsable; plots currently use aggregate rows

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as e:
        print(f"error: matplotlib unavailable: {e}", file=sys.stderr)
        return 2

    plot_bar_ratio(
        agg_rows,
        plt,
        args.out_dir,
        "units_per_sec_ratio_pager_vs_baseline",
        "Throughput Ratio by Workload (median, min/max bars)",
        "ratio (pager / baseline)",
        "throughput_ratio_by_workload",
    )
    plot_bar_ratio(
        agg_rows,
        plt,
        args.out_dir,
        "elapsed_ms_ratio_pager_vs_baseline",
        "Elapsed Time Ratio by Workload (median, min/max bars)",
        "ratio (pager / baseline)",
        "elapsed_ratio_by_workload",
    )
    plot_cpu_breakdown(agg_rows, plt, args.out_dir)
    plot_latency_groups(
        agg_rows,
        plt,
        args.out_dir,
        "pager_fault_missing_p95_ns",
        "pager_fault_missing_p99_ns",
        "Missing-Fault Service Latency (median p95/p99 across runs)",
        "fault_missing_latency_p95_p99",
    )
    plot_latency_groups(
        agg_rows,
        plt,
        args.out_dir,
        "pager_restore_wall_p95_ns",
        "pager_restore_wall_p99_ns",
        "Restore Wall Latency (median p95/p99 across runs)",
        "restore_latency_p95_p99",
    )
    plot_activity_counts(agg_rows, plt, args.out_dir)
    plot_mmap_churn_special(agg_rows, plt, args.out_dir)
    plot_cpu_vs_throughput(agg_rows, plt, args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
