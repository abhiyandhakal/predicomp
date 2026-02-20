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
