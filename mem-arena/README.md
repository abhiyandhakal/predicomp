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
- Compression moves a chunk from raw memory into arena slot storage.
- Decompression restores chunk to raw memory on access.
- If arena slots are full, least-recently-used compressed chunk is evicted (decompressed back to raw).

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
- `compressed_bytes_live`
- `slot_bytes_live`
- `compress_ops`
- `decompress_ops`
- `evictions_lru`
- `incompressible_chunks`
- `access_hits_raw`
- `access_hits_decompressed`
- `compression_reject_small_gain`

These are designed to feed your fairness model and early-decompression policy ideas.

## Per-Process RAM + CPU Tracking

`process_mem_bench` measures, per run:

- `VmRSS` before compression (`rss_pre_kb`)
- `VmRSS` after compression (`rss_post_compress_kb`)
- `VmRSS` after readback/decompression (`rss_post_readback_kb`)
- `VmHWM` (`vmhwm_kb`)
- compression/decompression CPU and wall time:
  - `compress_thread_cpu_ms`, `compress_process_cpu_ms`, `compress_wall_ms`
  - `decompress_thread_cpu_ms`, `decompress_process_cpu_ms`, `decompress_wall_ms`

It writes:

- terminal table for quick review
- CSV for analysis/plotting (`--csv`)

The measured process is the benchmark process itself (managed test process path).

## Limitations

- Managed-buffer scope only (not transparent process-wide memory interception).
- Current slot allocator uses fixed slot size equal to chunk size.
- LZ4 is the only codec in this phase.
