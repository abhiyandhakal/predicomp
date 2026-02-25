# eBPF probes for process and memory research

This repository currently contains two small eBPF programs:

- `proc_create`: prints `hello world <PID>` on process fork
- `page_fault`: prints page fault events with PID, command name, user/kernel type, fault address, and instruction pointer
- `swap_probe`: prints 1s swap/reclaim pressure deltas from `vmscan` tracepoints
- `proc_lifecycle` (used by `workload_controller`): emits process `exec`/`exit` events over a ring buffer for userspace control logic

`proc_create` and `page_fault` use `bpf_printk`, so output is read from `trace_pipe`.
`swap_probe` prints periodic summaries to stdout. `workload_controller` consumes
`proc_lifecycle` events directly via libbpf ring buffer (no `trace_pipe`).

## Compression Fairness Policy

For RAM compression experiments, use this default decision policy:

- Baseline codec: `LZ4 fast`
- Compress only if estimated savings are at least `5%`
- Rank candidate settings by:
  `fair_score = bytes_saved / (compress_cpu_ms + readback_factor * decompress_cpu_ms)`
- For high-readback memory, use a larger `readback_factor` so decode cost is weighted more heavily
- Prefer `zstd` only for colder pages where read probability is low and ratio dominates

Detailed formula and benchmark application guidance live in `compressor-monitor/README.md`.

## Requirements

- Linux kernel with BTF support (`/sys/kernel/btf/vmlinux` exists)
- `clang`, `bpftool`, `libbpf`, `pkg-config`, `make`
- root privileges to load/attach BPF

## VM Lab (Recommended for Measurements)

For reproducible eBPF/DAMON/mem-arena experiments, use the dedicated QEMU/KVM
Arch guest lab in `vm/` instead of the host machine.

See `vm/README.md` for:

- QEMU/KVM VM setup scripts
- Arch guest bootstrap steps
- 9p repo sharing
- guest environment validation (BTF/DAMON/tracefs)
- canonical `interactive_burst --arena-autoloops` runs inside the guest

## Build all

```bash
make
```

## Run process-fork monitor

Terminal 1:

```bash
sudo ./proc_create
```

Terminal 2:

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

You should see lines like:

```text
hello world 12345
```

## Run page-fault monitor

Terminal 1:

```bash
sudo ./page_fault
```

Terminal 2:

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

You should see lines like:

```text
page_fault pid=12345 comm=bash type=user addr=0x7f2ea77f4b90 ip=0x555f82b2f123
page_fault pid=12345 comm=bash type=kernel addr=0xffff9a1f01234000 ip=0xffffffff81234567
```

If `/sys/kernel/tracing/trace_pipe` does not exist, mount tracefs:

```bash
sudo mount -t tracefs tracefs /sys/kernel/tracing
```

## Run swap/reclaim monitor

This kernel does not expose direct `swapin/swapout` tracepoints, so `swap_probe`
uses `vmscan` events as a practical proxy for swap pressure.

Terminal 1:

```bash
sudo ./swap_probe
```

You should see lines like:

```text
swap_probe ts=1739983562 kswapd_wake=1 kswapd_sleep=0 direct_begin=3 direct_end=3 reclaim_pages=2 write_folio=1 last_pid=2104 last_comm=firefox
```

## Structured Workloads Lab

Use `workloads/` for bounded process/memory workload generation plus wrappers for
`stress-ng`, `mmtests`, `phoronix-test-suite`, `sysbench`, and `fio`.

See `workloads/README.md` for build/run commands, safety guardrails, and citations.

Cooperative `process-pager` coverage (actual workload pages, VM-first):

- supported: `interactive_burst`, `anon_streamer`, `random_touch_heap`
- supported (dynamic live ranges): `mmap_churn`
- out of scope: fork workloads (`fork_exit_storm`, `fork_touch_exit`, `fork_exec_storm`)

## 10s Post-Exec Compression Controller (Research Prototype)

Status: archived/secondary for now. This remains in-repo as a prior control-plane
prototype and observability reference. Current experiments focus on internal
`mem-arena` autoloops (`interactive_burst`).

Use `./workload_controller` plus `proc_lifecycle` eBPF events to:

- track process `exec`/`exit`/`fork` in userspace
- enroll mem-arena workloads (`anon_streamer`, `interactive_burst`, `random_touch_heap`, `mmap_churn`)
- send `SIGUSR1` at `exec + N seconds` (default 10s)
- collect compression ACKs + mem-arena stats snapshots over a Unix datagram socket

Build and run:

```bash
make proc_lifecycle workload_controller
sudo ./workload_controller --delay-sec 10 --csv /tmp/workload_controller.csv
```

Then run a mem-arena workload with external policy:

```bash
./workloads/bin/anon_streamer --duration-sec 30 --region-mb 512 --use-mem-arena --controller-enroll --compress-policy external
```

See `controller/README.md` for the full runbook and CSV fields.
To run the entire workload suite with isolated per-workload controller outputs, use:
`sudo ./workloads/scripts/run_controller_workload_matrix.sh`.

## Dedicated RAM Compression Pool

Use `ram-pool/` to provision a dedicated zram-backed compressed RAM space and run
manual compression/readback triggers via workload profiles.

See `ram-pool/README.md` for setup, status, trigger, and reset commands.

## Swap-Free Managed Compression Arena

Use `mem-arena/` for a custom user-space compression arena that does not depend on
swap ingress. This is useful for controlled experiments with explicit compression
and decompression triggers inside workload binaries.

See `mem-arena/README.md` for API/build details and workload integration.
For per-process RAM before/after compression and compressor CPU cost, run
`./mem-arena/process_mem_bench` (or `make mem-arena-bench`).
The benchmark reports `ratio_e2e_post_comp` (primary), `ratio_admitted_post_comp`,
`ratio_codec_post_comp`, and `admit_rate_post_comp`.

### mem-arena 3-Loop Pilot (`interactive_burst`)

`mem-arena` also includes a correctness-first internal 3-loop pilot for:

- hotness tracking (touch metadata + DAMON-based classification)
- background compression (HOT/WARM/COLD policy)
- proactive decompression/prefetch (phase hints + simple next-k prefetch)

Pilot workload:

- `workloads/bin/interactive_burst` with `--arena-autoloops`

Example:

```bash
sudo ./workloads/bin/interactive_burst \
  --duration-sec 20 \
  --region-mb 256 \
  --active-ms 100 \
  --idle-ms 400 \
  --use-mem-arena \
  --arena-cap-mb 128 \
  --arena-autoloops
```

See `mem-arena/README.md` for loop flags, DAMON requirements, stats, and limitations.
For lower-noise measurement runs, prefer running this inside the VM lab (`vm/README.md`).
