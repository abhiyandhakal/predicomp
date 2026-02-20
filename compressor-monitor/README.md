# compressor-monitor (LZ4 synthetic suite)

This benchmark generates deterministic synthetic samples and measures LZ4 behavior across size and data-type patterns.

## What it benchmarks

- Datasets:
  - `repetitive` (highly compressible repeated pattern)
  - `unique` (deterministic PRNG bytes, near-incompressible)
- Sizes:
  - 1KB up to 16MB (powers of two)
- Runs per case:
  - 5
- Summary:
  - median metrics per case

## Metrics reported

- File/ratio:
  - median compressed bytes
  - median compression ratio (`compressed_bytes / input_bytes`)
- Timing:
  - median `compression_ms`
  - median `decompression_ms`
- Scheduler deltas from `/proc/self/sched`:
  - `se.vruntime`
  - `se.sum_exec_runtime`
  - `nr_switches`
  - `nr_voluntary_switches`
  - `nr_involuntary_switches`
- Validation:
  - byte-for-byte input/decompressed match for each run

## Output

- Terminal table with one row per `(dataset_type, size)` plus scheduler median lines.
- CSV file: `compressor-monitor/results.csv`

## Artifact policy

- Kept:
  - Generated input samples in `compressor-monitor/samples/`
- Cleaned per run:
  - Temporary compressed/decompressed outputs (`*.lz4.tmp`, `*.out.tmp`)

## Requirements

- `lz4` CLI available in `PATH`
- C compiler (`cc`)

## Build

```bash
make -C compressor-monitor
```

## Run

```bash
./compressor-monitor/compressor_monitor
```

## Cleanup

```bash
make -C compressor-monitor clean
```

Remove generated sample inputs too:

```bash
make -C compressor-monitor clean-samples
```
