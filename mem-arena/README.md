# mem-arena: swap-free managed RAM compression

`mem-arena` is a user-space managed compression arena for research experiments.
It does not depend on swap/zram for ingress. Instead, workloads explicitly allocate regions in this arena and trigger compression/decompression through API calls.

## Goal

Prototype a controlled, page-like compression path to evaluate:

- compression/decompression CPU cost
- access-driven readback behavior
- LRU eviction behavior under bounded compressed pool capacity

## Model

- Region memory is allocated in user space.
- Region is split into fixed-size chunks (default 4 KiB).
- Compression moves chunk payload into a packed variable-size pool (aligned extents).
- Decompression restores chunk to raw memory on access.
- If pool is fragmented, compaction may run before allocation retry.
- If pool capacity is pressured, least-recently-used compressed chunk is evicted (decompressed back to raw).

## Public API

Header: `mem-arena/include/mem_arena.h`

Core calls:

- `mem_arena_create`
- `mem_arena_region_alloc`
- `mem_arena_touch`
- `mem_arena_compress_region`
- `mem_arena_get_stats`
- `mem_arena_region_free`
- `mem_arena_destroy`

## Build

```bash
make -C mem-arena
```

Run demo:

```bash
make -C mem-arena demo
```

Run per-process RAM benchmark:

```bash
make -C mem-arena bench
./mem-arena/process_mem_bench --dataset repetitive --region-mb 256 --arena-cap-mb 128 --runs 5 --warmups 2 --csv mem-arena/process_mem_bench.csv
```

Run multiple datasets sequentially in one command:

```bash
./mem-arena/process_mem_bench --dataset {repetitive,unique,mixed_50_50} --region-mb 256 --arena-cap-mb 128 --runs 5 --warmups 2 --csv mem-arena/process_mem_bench.csv
```

Equivalent quoted list form:

```bash
./mem-arena/process_mem_bench --dataset "repetitive,unique,mixed_50_50" --region-mb 256 --arena-cap-mb 128 --runs 5 --warmups 2 --csv mem-arena/process_mem_bench.csv
```

## Integration with workloads

`workloads/bin/anon_streamer` and `workloads/bin/interactive_burst` support:

- `--use-mem-arena`
- `--arena-cap-mb <n>`
- `--arena-min-savings-pct <n>`
- `--arena-stats-json <path>`

Example:

```bash
./workloads/bin/anon_streamer \
  --duration-sec 30 \
  --region-mb 512 \
  --idle-ms 200 \
  --use-mem-arena \
  --arena-cap-mb 256 \
  --arena-min-savings-pct 5 \
  --arena-stats-json /tmp/anon_stats.json
```

## Stats

- `logical_input_bytes`
- `total_input_bytes_attempted`
- `total_chunks_attempted`
- `chunks_admitted`
- `compressed_bytes_live`
- `pool_bytes_live`
- `pool_bytes_free`
- `pool_bytes_fragmented`
- `pool_largest_free_extent`
- `pool_compactions`
- `slot_bytes_live` (legacy alias of `pool_bytes_live`)
- `compress_ops`
- `decompress_ops`
- `evictions_lru`
- `incompressible_chunks` (chunks not admitted to compressed slots)
- `access_hits_raw`
- `access_hits_decompressed`
- `compression_reject_small_gain` (subset: rejected due to savings threshold)

These are designed to feed your fairness model and early-decompression policy ideas.

Ratio interpretation:

- `ratio_overall_post_comp = total_input_bytes_attempted / pool_bytes_post_compress`
- `ratio_admitted_post_comp = logical_input_bytes / pool_bytes_post_compress`
- `admit_rate_post_comp = chunks_admitted / total_chunks_attempted`

Use `ratio_overall_post_comp` as the primary end-to-end indicator.
`ratio_admitted_post_comp` is a codec-efficiency diagnostic on admitted chunks only.

## Per-Process RAM + CPU + Phase/Fault Tracking

`process_mem_bench` measures, per run:

- `/proc/self/status` snapshots:
  - `VmHWM` at final snapshot
- `/proc/self/smaps_rollup` snapshots:
  - `Rss`, `Pss`, `Anonymous`, `File` across phases
- compression/decompression CPU and wall time:
  - `compress_thread_cpu_ms`, `compress_process_cpu_ms`, `compress_wall_ms`
  - `decompress_thread_cpu_ms`, `decompress_process_cpu_ms`, `decompress_wall_ms`
- latency percentiles for readback touches:
  - `partial_p50/p95/p99_ns`
  - `random_p50/p95/p99_ns`
  - `touch_p50/p95/p99_ns` (all sampled readback touches)
- decompression-triggered stall latency:
  - `stall_p50/p95/p99_ns` (sampled touches that triggered decompression)
  - `stall_events_total`, `stall_events_sampled`
- true Linux page-fault counters (readback window deltas):
  - `minflt_delta`, `majflt_delta` from `/proc/self/stat`
- fault-like readback proxy:
  - `readback_fault_like_events` (delta of `access_hits_decompressed`)

Phase model options:

- `--phase-model single-bulk`
- `--phase-model hot-idle-full-reread`
- `--phase-model hot-idle-partial-random` (default)

Useful tuning flags:

- `--hot-fraction`
- `--partial-reread-fraction`
- `--random-reread-fraction`
- `--reuse-distance-pages`
- `--idle-ms`
- `--latency-sample-step`
- `--seed`

Example:

```bash
./mem-arena/process_mem_bench \
  --dataset repetitive unique mixed_50_50 \
  --region-mb 256 \
  --arena-cap-mb 128 \
  --runs 5 \
  --warmups 2 \
  --phase-model hot-idle-partial-random \
  --hot-fraction 60 \
  --partial-reread-fraction 30 \
  --random-reread-fraction 20 \
  --reuse-distance-pages 64 \
  --latency-sample-step 8 \
  --csv mem-arena/process_mem_bench.csv
```

It writes:

- terminal table for quick review
- CSV for analysis/plotting (`--csv`)

The measured process is the benchmark process itself (managed test process path).

## Limitations

- Managed-buffer scope only (not transparent process-wide memory interception).
- Memory reclaim hints (`madvise`) are best effort and kernel-dependent.
- LZ4 is the only codec in this phase.
