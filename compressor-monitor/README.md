# compressor-monitor (LZ4 synthetic suite v2)

This benchmark runs in-process LZ4 compression/decompression and reports wall-clock and CPU-time metrics for synthetic datasets.

## Datasets

- `repetitive`: highly compressible repeated pattern
- `unique`: deterministic PRNG bytes (near-incompressible)
- `mixed_50_50`: deterministic interleaving of repetitive/unique 4 KiB blocks with exact 50/50 byte split

## Sizes and runs

- Size ladder: powers of two from 1 KiB up to `--max-size` (default 16 MiB)
- Warmups per case: `--warmups` (default `2`, excluded from summaries)
- Measured runs per case: `--runs` (default `5`, median reported)

## Metrics reported

- `compressed_bytes_median`, `ratio_median`
- `comp_wall_ms_median`, `decomp_wall_ms_median`
- `comp_thread_cpu_ms_median`, `decomp_thread_cpu_ms_median`
- `comp_proc_cpu_ms_median`, `decomp_proc_cpu_ms_median`
- `comp_mib_per_s_median`, `decomp_mib_per_s_median`
- `validation` (`PASS`/`FAIL`)

## Output

- Terminal table (compact key medians)
- CSV at `compressor-monitor/results.csv`

## Requirements

- `liblz4` development library (for `lz4.h` + `-llz4`)
- C compiler (`cc`)

## Build

```bash
make -C compressor-monitor
```

## Run

```bash
./compressor-monitor/compressor_monitor
```

Optional flags:

```bash
./compressor-monitor/compressor_monitor --cpu 0 --runs 5 --warmups 2 --max-size 16777216
```

## Cleanup

```bash
make -C compressor-monitor clean
```

Remove generated sample inputs too:

```bash
make -C compressor-monitor clean-samples
```
