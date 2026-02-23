# workload_controller: 10s post-exec compression controller (research prototype)

This controller is the first end-to-end bridge between:

- eBPF process lifecycle observation (`sched_process_exec`, `sched_process_exit`)
- mem-arena-backed workloads (`anon_streamer`, `interactive_burst`)
- a simple external compression policy (`exec + 10s`)

## What it does

1. Attaches a lifecycle eBPF probe and receives `exec` / `exit` events over a ring buffer.
2. Tracks PIDs in userspace with:
   - hash table (PID -> state)
   - min-heap timer queue (deadline ordering)
3. When an enrolled workload reaches `exec + delay`, sends `SIGUSR1`.
4. Workload compresses its mem-arena region at a safe point and sends an ACK + stats snapshot over a Unix datagram socket.

This is intentionally narrow: only mem-arena-aware workloads are controlled in this phase.

## Build

From repo root:

```bash
make proc_lifecycle workload_controller
make -C workloads bin/anon_streamer bin/interactive_burst
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

## Important notes

- `--controller-enroll` requires `--use-mem-arena`.
- `--compress-policy external` disables the workload's internal compression calls.
- `--compress-policy both` keeps internal compression and also reacts to controller `SIGUSR1`.
- The controller uses `CLOCK_MONOTONIC` and BPF `ktime_ns` to schedule deadlines.
- If a process exits before the deadline, the controller records exit and does not signal it.
- If the controller sees `exec` but never receives enrollment, it records a miss (`missed_due_to_no_enroll`).

## Controller CSV fields (high level)

- lifecycle: `pid`, `generation`, `comm`, `exec_event_ns`, `deadline_ns`, `exited`
- policy result: `compress_sent`, `compress_ack`, `missed_due_to_no_enroll`
- timing: `compress_request_ns`, `compress_ack_ns`, `compress_latency_ms`
- workload config: `workload_name`, `arena_cap_mb`, `arena_min_savings_pct`, `region_mb`
- mem-arena snapshot: attempted/admitted bytes, pool usage, compactions, compress/decompress ops, incompressible count

## Current limitations (expected)

- Only two workloads implement enrollment + external ACK today:
  - `anon_streamer`
  - `interactive_burst`
- No adaptive policy yet (fixed delay only).
- No kernel-side process tracking state; controller is authoritative.
