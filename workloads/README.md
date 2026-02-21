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

## Custom workloads (C binaries)

All binaries support strict defaults and common flags:

- `--duration-sec`
- `--workers`
- `--seed`
- `--json`
- `--unsafe-allow-long` (required to exceed safe bounds)

### 1) `bin/fork_exit_storm`
Rate-limited fork/exit churn.

### 2) `bin/fork_touch_exit`
Fork churn where child touches configurable anonymous pages before exit.

### 3) `bin/fork_exec_storm`
Rate-limited `fork()+execve()` storms (default `/bin/true`).

### 4) `bin/interactive_burst`
Active touch bursts followed by idle windows (hot/cold/hot phases).

### 5) `bin/mmap_churn`
Repeated `mmap/munmap` with page touches.

### 6) `bin/anon_streamer`
Sequential page streaming with idle intervals.

### 7) `bin/random_touch_heap`
Random page touches over a large heap region.

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
