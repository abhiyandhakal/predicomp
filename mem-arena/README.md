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

3-loop prototype calls (pilot):

- `mem_arena_loops_start`
- `mem_arena_loops_stop`
- `mem_arena_loops_is_running`
- `mem_arena_prefetch_chunk`
- `mem_arena_prefetch_range`
- `mem_arena_phase_hint`

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

### 3-Loop Pilot (`interactive_burst`)

`interactive_burst` now supports a correctness-first `mem-arena` pilot mode with:

- hotness tracking loop (explicit touches + DAMON-based classification)
- background compression loop
- proactive prefetch loop (phase hint + next-k prefetch)

Pilot flags:

- `--arena-autoloops`
- `--arena-t-cold-ms <n>`
- `--arena-prefetch-distance <n>`
- `--arena-prefetch-batch <n>`
- `--arena-disable-prefetch`
- `--arena-disable-bg-compress`

Example (idle-heavy, easier to observe loop activity):

```bash
sudo ./workloads/bin/interactive_burst \
  --duration-sec 8 \
  --region-mb 8 \
  --active-ms 20 \
  --idle-ms 500 \
  --use-mem-arena \
  --arena-cap-mb 8 \
  --arena-autoloops \
  --arena-t-cold-ms 100
```

Notes:

- `--arena-autoloops` currently uses the kernel DAMON sysfs admin interface for hotness classification and therefore requires root privileges.
- DAMON is used for classification only in this pilot (no DAMOS memory actions are applied).

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
- 3-loop pilot stats:
  - `hotness_epoch`, `chunks_hot`, `chunks_warm`, `chunks_cold`
  - `damon_snapshots_total`, `damon_regions_observed_total`, `damon_read_errors`
  - `damon_chunks_marked_hot`, `damon_chunks_marked_warm`, `damon_chunks_marked_cold`
  - `damon_last_snapshot_nr_regions`, `damon_last_snapshot_bytes`
  - `bg_compress_attempts`, `bg_compress_admits`, `bg_compress_skipped_*`
  - `prefetch_queue_enqueues`, `prefetch_queue_dedup_skips`, `prefetch_decompress_ops`
  - `demand_decompress_stall_events`, `demand_decompress_stall_ns_total`
  - `adaptive_t_cold_epochs_current`

These are designed to feed your fairness model and early-decompression policy ideas.

Ratio interpretation:

- `ratio_e2e_post_comp = total_input_bytes_attempted / ((total_input_bytes_attempted - logical_input_bytes) + pool_used_bytes_post_comp)`
- `ratio_admitted_post_comp = logical_input_bytes / pool_used_bytes_post_comp`
- `ratio_codec_post_comp = logical_input_bytes / compressed_bytes_post_comp`
- `admit_rate_post_comp = chunks_admitted / total_chunks_attempted`

Use `ratio_e2e_post_comp` as the primary end-to-end indicator.
`ratio_admitted_post_comp` is a codec-efficiency diagnostic on admitted chunks only.
`ratio_codec_post_comp` isolates codec efficiency from pool allocator overhead.

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
- 3-loop pilot hotness classification currently depends on DAMON sysfs admin access and expects exclusive DAMON use for the run.
