# eBPF probes for process and memory research

This repository currently contains two small eBPF programs:

- `proc_create`: prints `hello world <PID>` on process fork
- `page_fault`: prints page fault events with PID, command name, user/kernel type, fault address, and instruction pointer
- `swap_probe`: prints 1s swap/reclaim pressure deltas from `vmscan` tracepoints

`proc_create` and `page_fault` use `bpf_printk`, so output is read from `trace_pipe`.
`swap_probe` prints periodic summaries to stdout.

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

## Dedicated RAM Compression Pool

Use `ram-pool/` to provision a dedicated zram-backed compressed RAM space and run
manual compression/readback triggers via workload profiles.

See `ram-pool/README.md` for setup, status, trigger, and reset commands.
