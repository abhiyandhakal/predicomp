# ram-pool: dedicated compressed RAM space (zram)

This module provisions a dedicated compressed-RAM pool using zram, then drives manual compression/decompression experiments using existing workload generators.

## Architecture

- Kernel compressed pool: `/dev/zramN` swap device
- Manual controller: scripts in `ram-pool/scripts/`
- Pressure/readback generators: `workloads/bin/*`
- Observability: existing `page_fault` and `swap_probe` probes

## Why this phase is manual

Current goal is to validate mechanics and measurement quality before automatic policy logic.
Manual trigger scripts provide controlled and reproducible experiments.

## Prerequisites

- Linux with zram support (`modprobe zram`)
- root access for setup/reset
- built workloads binaries:

```bash
make -C workloads
```

## Quickstart

1. Setup dedicated zram pool:

```bash
sudo ./ram-pool/scripts/setup_zram_pool.sh --device zram0 --algo lz4 --size 2G --mem-limit 1G --priority 100
```

2. Check status:

```bash
./ram-pool/scripts/status_zram_pool.sh --device zram0
```

3. Trigger compression-oriented pressure:

```bash
./ram-pool/scripts/trigger_compress.sh --profile medium --duration-sec 30
```

4. Trigger readback/decompression pressure:

```bash
./ram-pool/scripts/trigger_decompress.sh --profile readback --duration-sec 30
```

5. Reset the pool when done:

```bash
sudo ./ram-pool/scripts/reset_zram_pool.sh --device zram0
```

## Scripts

- `setup_zram_pool.sh`: create/configure/reset zram swap pool
- `status_zram_pool.sh`: print zram counters and derived metrics
- `trigger_compress.sh`: run memory pressure profiles to push pages toward zram
- `trigger_decompress.sh`: run readback profiles to pull pages back
- `reset_zram_pool.sh`: swapoff and reset zram state

## Trigger profiles

### Compression profiles (`trigger_compress.sh`)

- `light`: moderate anonymous-memory streaming
- `medium`: streaming + fork-touch churn
- `heavy`: larger streaming + fork-touch + mmap churn

### Decompression profiles (`trigger_decompress.sh`)

- `readback`: interactive burst readback
- `burst`: aggressive burst + random touch heap

## Metrics interpretation

`status_zram_pool.sh` exposes:

- `orig_data_size`: uncompressed logical bytes written to zram
- `compr_data_size`: compressed payload bytes
- `mem_used_total`: RAM used by zram including metadata
- `num_reads`: read operations (proxy for decompress/readback)
- `num_writes`: write operations (proxy for compression ingress)
- `zero_pages`: zero-filled pages optimized specially
- `compression_ratio`: `compr_data_size / orig_data_size`
- `overhead_bytes`: `max(mem_used_total - compr_data_size, 0)`

### What to look for

- Compression effectiveness: lower `compression_ratio` is better.
- Compression activity: rising `num_writes` during `trigger_compress`.
- Readback activity: rising `num_reads` during `trigger_decompress`.
- Overhead behavior: monitor `overhead_bytes` growth with different profiles.

## Recommended concurrent observability

In parallel terminals:

```bash
sudo ./page_fault
sudo ./swap_probe
sudo cat /sys/kernel/tracing/trace_pipe
```

Then run trigger scripts and correlate:

- zram counter deltas
- page-fault bursts
- reclaim/swap pressure proxies

## Safety notes

- `setup_zram_pool.sh` refuses conflicting active state unless `--force`.
- `reset_zram_pool.sh` should be run after experiments.
- Keep trigger durations bounded and test with `light` profile first.

## Limitations (current phase)

- No automatic per-process/page selection policy yet.
- Manual triggers drive pressure globally, not targeted page sets.
- This is an experimental path for signal validation and workflow hardening.
