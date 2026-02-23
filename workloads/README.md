# workloads: structured memory-pressure lab

This directory provides a bounded, reproducible workload lab for:

- Predictive RAM Compression
- Early Decompression

It combines custom structured workloads (hot/cold/process churn patterns) with wrappers around common external benchmark harnesses.

## Why this exists

Existing tools are strong for pressure and repeatability, but they do not directly encode predictive hot->cold->hot memory lifecycle behavior out of the box. This lab gives both:

- Structured custom patterns for policy learning
- Standard external baselines for comparability

## Build custom workloads

```bash
make -C workloads
```

Run quick smoke checks:

```bash
make -C workloads smoke
```

Build also links `mem-arena/` so workload binaries can optionally run in swap-free managed compression mode.

## Custom workloads (C binaries)

All binaries support strict defaults and common flags:

- `--duration-sec`
- `--workers`
- `--seed`
- `--json`
- `--unsafe-allow-long` (required to exceed safe bounds)

### Workload catalog

### 1) `bin/fork_exit_storm`
- Intent: process lifecycle churn with minimal memory work.
- Good for: validating fork trace volume and scheduler pressure.
- Typical eBPF signals: `sched_process_fork`, run queue activity.
- Example:
```bash
./workloads/bin/fork_exit_storm --duration-sec 30 --workers 4 --fork-rate 50
```

### 2) `bin/fork_touch_exit`
- Intent: process churn plus anonymous page touching before exit.
- Good for: correlating process churn with page-fault/reclaim pressure.
- Typical eBPF signals: `sched_process_fork` + `exceptions/page_fault_*` + `mm/vmscan/*`.
- Example:
```bash
./workloads/bin/fork_touch_exit --duration-sec 30 --workers 4 --fork-rate 20 --touch-pages 256
```

### 3) `bin/fork_exec_storm`
- Intent: repeated `fork()+execve()` to mimic helper/worker process trees.
- Good for: browser-like isolated-process behavior approximation.
- Typical eBPF signals: fork + exec transitions.
- Example:
```bash
./workloads/bin/fork_exec_storm --duration-sec 30 --workers 2 --fork-rate 10 --exec-path /bin/true
```

### 4) `bin/interactive_burst`
- Intent: short active memory bursts followed by idle windows.
- Good for: hot->cold->hot transitions relevant to early decompression.
- Typical eBPF signals: fault bursts, then quiet periods, then bursts again.
- Example:
```bash
./workloads/bin/interactive_burst --duration-sec 60 --region-mb 256 --active-ms 100 --idle-ms 500
```

### 5) `bin/mmap_churn`
- Intent: repeated `mmap/munmap` with page touching.
- Good for: VMA churn and mapping lifecycle stress.
- Typical eBPF signals: mm mapping churn + page faults.
- Example:
```bash
./workloads/bin/mmap_churn --duration-sec 30 --map-kb 1024 --ops-per-sec 1000
```

### 6) `bin/anon_streamer`
- Intent: sequential scan/touch over large anonymous memory with idle gaps.
- Good for: controlled working-set passes and reclaim interaction.
- Typical eBPF signals: sequential fault/re-access waves.
- Example:
```bash
./workloads/bin/anon_streamer --duration-sec 60 --region-mb 1024 --idle-ms 300
```

### 7) `bin/random_touch_heap`
- Intent: random page touches over a large heap region.
- Good for: latency-sensitive random access under memory pressure.
- Typical eBPF signals: high-entropy access patterns and irregular fault locality.
- Example:
```bash
./workloads/bin/random_touch_heap --duration-sec 60 --region-mb 1024 --ops-per-sec 500000
```

### Which one to use first

- Start with `interactive_burst` and `anon_streamer` for predictive compression/decompression policy learning.
- Add `fork_touch_exit` and `mmap_churn` to test robustness under process/mapping churn.
- Use `random_touch_heap` as a worst-case random-access stress.

## Optional swap-free mem-arena mode

Two workloads support direct integration with `mem-arena`:

- `bin/anon_streamer`
- `bin/interactive_burst`

Shared flags:

- `--use-mem-arena`
- `--arena-cap-mb <n>`
- `--arena-min-savings-pct <n>`
- `--arena-stats-json <path>`

External controller integration flags (for `anon_streamer`, `interactive_burst`):

- `--controller-enroll` (requires `--use-mem-arena`)
- `--controller-sock <path>` (default `/tmp/predicomp-controller.sock`)
- `--compress-policy internal|external|both` (default `internal`)

Examples:

```bash
./workloads/bin/anon_streamer --duration-sec 30 --region-mb 512 --use-mem-arena --arena-cap-mb 256 --arena-stats-json /tmp/anon_arena.json
./workloads/bin/interactive_burst --duration-sec 30 --region-mb 256 --active-ms 100 --idle-ms 400 --use-mem-arena --arena-cap-mb 128 --arena-stats-json /tmp/burst_arena.json
```

Controller-driven external compression example (10s policy is configured in the controller, not the workload):

```bash
sudo ./workload_controller --delay-sec 10 --csv /tmp/workload_controller.csv

./workloads/bin/anon_streamer \
  --duration-sec 30 \
  --region-mb 512 \
  --use-mem-arena \
  --arena-cap-mb 256 \
  --controller-enroll \
  --compress-policy external
```

See `mem-arena/README.md` for arena architecture and metric definitions.
For formal per-process RAM before/after compression + compressor CPU accounting,
use `mem-arena/process_mem_bench`.
See `controller/README.md` for the lifecycle probe + PID tracking controller details.

## Safety model (strict by default)

- default duration: 20s
- safe duration cap: 300s unless `--unsafe-allow-long`
- default workers: 4
- safe worker cap: 512 unless `--unsafe-allow-long`
- fork workloads set `RLIMIT_NPROC` proportional to workers
- wrappers use bounded profile runtimes

For stronger isolation, run inside cgroups/systemd scopes.

## External benchmark wrappers

First check tool availability and install guidance:

```bash
workloads/scripts/check_tools.sh
```

Run external profiles/wrappers:

```bash
workloads/scripts/run_stressng_profiles.sh
workloads/scripts/run_sysbench_memory_profiles.sh
workloads/scripts/run_fio_cache_profiles.sh
workloads/scripts/run_mmtests_stub.sh
workloads/scripts/run_phoronix_stub.sh
```

Logs are written to `workloads/results/`.

## Relevance map for this repo

- `stress-ng`: fast pathological sweeps (fork/vm/mmap pressure)
- `mmtests`: MM-focused repeatable harness for deeper regression-style runs
- `Phoronix Test Suite`: standardized batch/repro pipeline when publishing/comparing
- `sysbench` memory: controlled memory baseline runs
- `fio`: page-cache churn and reclaim pressure via file I/O

## Citations

- stress-ng README: https://github.com/ColinIanKing/stress-ng
- mmtests repo: https://github.com/gormanm/mmtests
- Phoronix Test Suite docs: https://www.phoronix-test-suite.com/documentation/
- sysbench repo: https://github.com/akopytov/sysbench
- fio repo/docs: https://github.com/axboe/fio
- Linux man pages:
  - `fork(2)`: https://man7.org/linux/man-pages/man2/fork.2.html
  - `execve(2)`: https://man7.org/linux/man-pages/man2/execve.2.html
  - `mmap(2)`: https://man7.org/linux/man-pages/man2/mmap.2.html
  - `setrlimit(2)`: https://man7.org/linux/man-pages/man2/getrlimit.2.html
