# workload_controller: 10s post-exec compression controller (research prototype)

Status: archived/secondary for now. This prototype is kept in-repo for
reference and observability experiments, while current `mem-arena` work focuses
on internal autoloops (`interactive_burst`).

This controller is the first end-to-end bridge between:

- eBPF process lifecycle observation (`sched_process_exec`, `sched_process_exit`, `sched_process_fork`)
- mem-arena-backed workloads (`anon_streamer`, `interactive_burst`, `random_touch_heap`, `mmap_churn`)
- a simple external compression policy (`exec + 10s`)

## What it does

1. Attaches a lifecycle eBPF probe and receives `exec` / `exit` / `fork` events over a ring buffer.
2. Tracks PIDs in userspace with:
   - hash table (PID -> state)
   - min-heap timer queue (deadline ordering)
3. When an enrolled workload reaches `exec + delay`, sends `SIGUSR1`.
4. Workload compresses its mem-arena region at a safe point and sends an ACK + stats snapshot over a Unix datagram socket.

This is intentionally narrow: only mem-arena-aware workloads are controller-triggerable in this phase. Fork/exec churn workloads are still useful as observe-only signal tests.

## Build

From repo root:

```bash
make proc_lifecycle workload_controller
make -C workloads bin/anon_streamer bin/interactive_burst bin/random_touch_heap bin/mmap_churn
```

## Run (10s post-exec policy)

Terminal 1 (controller, needs root for BPF attach):

```bash
sudo ./workload_controller --delay-sec 10 --csv /tmp/workload_controller.csv
```

Terminal 2 (example workload, external-only compression):

```bash
./workloads/bin/anon_streamer \
  --duration-sec 30 \
  --region-mb 512 \
  --use-mem-arena \
  --arena-cap-mb 256 \
  --controller-enroll \
  --compress-policy external
```

Or:

```bash
./workloads/bin/interactive_burst \
  --duration-sec 30 \
  --region-mb 256 \
  --active-ms 100 \
  --idle-ms 400 \
  --use-mem-arena \
  --arena-cap-mb 128 \
  --controller-enroll \
  --compress-policy external
```

Additional triggerable workloads:

```bash
./workloads/bin/random_touch_heap \
  --duration-sec 30 \
  --region-mb 512 \
  --ops-per-sec 400000 \
  --use-mem-arena \
  --arena-cap-mb 256 \
  --controller-enroll \
  --compress-policy external

./workloads/bin/mmap_churn \
  --duration-sec 30 \
  --map-kb 512 \
  --ops-per-sec 500 \
  --use-mem-arena \
  --arena-region-mb 128 \
  --arena-cap-mb 128 \
  --controller-enroll \
  --compress-policy external
```

## Important notes

- `--controller-enroll` requires `--use-mem-arena`.
- `--compress-policy external` disables the workload's internal compression calls.
- `--compress-policy both` keeps internal compression and also reacts to controller `SIGUSR1`.
- The controller uses `CLOCK_MONOTONIC` and BPF `ktime_ns` to schedule deadlines.
- If a process exits before the deadline, the controller records exit and does not signal it.
- If the controller sees `exec` but never receives enrollment, it records a miss (`missed_due_to_no_enroll`).

## Controller CSV fields (high level)

- lifecycle: `pid`, `generation`, `comm`, `exec_event_ns`, `deadline_ns`, `exit_event_ns`, `exited`
- lineage: `parent_pid_last_seen`, `lineage_root_pid` (derived from fork events for process-tree attribution)
- policy result: `compress_sent`, `compress_ack`, `missed_due_to_no_enroll`
- timing: `compress_request_ns`, `compress_ack_ns`, `compress_latency_ms`
- workload config: `workload_name`, `arena_cap_mb`, `arena_min_savings_pct`, `region_mb`
- mem-arena snapshot: attempted/admitted bytes, pool usage, compactions, compress/decompress ops, incompressible count

## Current limitations (expected)

- Fork workloads are observe-only under the fixed `exec + 10s` policy in this phase:
  - `fork_exit_storm`
  - `fork_touch_exit`
  - `fork_exec_storm`
- No adaptive policy yet (fixed delay only).
- No kernel-side process tracking state; controller is authoritative.

## Full Workload Matrix Runner

Run the full workload suite (triggerable + observe-only) with a fresh controller per workload:

```bash
sudo ./workloads/scripts/run_controller_workload_matrix.sh --delay-sec 10 --duration-sec 20
```

Per-workload outputs include:

- `controller.log`
- `controller.csv`
- `workload.stdout`
- `summary.json`
