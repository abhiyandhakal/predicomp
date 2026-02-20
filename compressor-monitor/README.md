# compressor-monitor (LZ4 + Zstd level sweep)

This benchmark runs in-process compression/decompression sweeps for multiple levels across codecs.

## Codecs and levels

- LZ4 fast accelerations: `1,2,4,8,16`
- LZ4 HC levels: `3,6,9,12`
- Zstd levels: `1..19`

## Datasets

- `repetitive`: highly compressible repeated pattern
- `unique`: deterministic PRNG bytes (near-incompressible)
- `mixed_50_50`: deterministic interleaving of repetitive/unique 4 KiB blocks with exact 50/50 byte split

## Sizes and runs

- Size ladder: powers of two from 1 KiB up to `--max-size` (default 16 MiB)
- Warmups per case: `--warmups` (default `2`, excluded from summaries)
- Measured runs per case: `--runs` (default `5`, median reported)
- Default run is full sweep across all configured codec levels

## Metrics reported

- `compressed_bytes_median`, `ratio_median`
- `comp_wall_ms_median`, `decomp_wall_ms_median`
- `comp_thread_cpu_ms_median`, `decomp_thread_cpu_ms_median`
- `comp_proc_cpu_ms_median`, `decomp_proc_cpu_ms_median`
- `comp_mib_per_s_median`, `decomp_mib_per_s_median`
- `validation` (`PASS`/`FAIL`)

## Output

- Terminal table with: `codec`, `mode`, `level`, `dataset`, size, ratio, timing, validation
- Single CSV at `compressor-monitor/results.csv`

CSV columns include codec metadata:

- `codec,mode,level,dataset_type,size_bytes,runs,warmups,...`

## Requirements

- `liblz4` development library
- `libzstd` development library
- C compiler (`cc`)

## Build

```bash
make -C compressor-monitor
```

## Run

```bash
./compressor-monitor/compressor_monitor
```

Options:

```bash
./compressor-monitor/compressor_monitor \
  --codecs lz4,zstd \
  --cpu 0 \
  --runs 5 \
  --warmups 2 \
  --max-size 16777216 \
  --full-sweep
```

## Cleanup

```bash
make -C compressor-monitor clean
```

Remove generated sample inputs too:

```bash
make -C compressor-monitor clean-samples
```

## Fairness Policy for RAM Compression

For this research repo, the default fairness objective is a balanced score:

- Goal: maximize useful memory savings per weighted CPU time
- Workload assumption: high readback (decompression cost matters)
- Minimum savings floor: skip compression if savings are below `5%`

Define:

- `bytes_saved = input_bytes - compressed_bytes`
- `fair_score = bytes_saved / (compress_cpu_ms + readback_factor * decompress_cpu_ms)`

Interpretation:

- Higher `fair_score` is better.
- `readback_factor` should be greater than 1 for read-heavy/hot memory so decompression time is penalized.
- If a candidate does not meet the 5% savings floor, treat it as ineligible regardless of score.

Practical default policy:

- Use `LZ4 fast` as the baseline/default for hot memory paths.
- Consider `zstd` settings only for colder pages where read probability is low and compression ratio is more important than decode latency.

How to apply this to benchmark CSV output:

1. For each row, compute `bytes_saved` from `size_bytes` and `compressed_bytes_median`.
2. Use CPU-time metrics (`comp_thread_cpu_ms_median`, `decomp_thread_cpu_ms_median`) to compute `fair_score`.
3. Drop rows with savings below 5%.
4. Rank remaining rows by `fair_score` within each workload profile.
