# compressor-monitor (LZ4 baseline)

A minimal baseline tool that:

- Compresses `compressor-monitor/test.txt` with `lz4`
- Decompresses it back
- Measures wall-clock time for compression and decompression
- Captures scheduler deltas from `/proc/self/sched`
- Validates decompressed output byte-for-byte

## Requirements

- `lz4` CLI installed and available in `PATH`
- C compiler (`cc`)

## Build

```bash
make -C compressor-monitor
```

## Run

```bash
./compressor-monitor/compressor_monitor
```

## Output fields

- `compression_ms`, `decompression_ms`: wall-clock duration per phase
- `se.vruntime`, `se.sum_exec_runtime`: scheduler runtime deltas per phase
- `nr_switches`, `nr_voluntary`, `nr_involuntary`: context switch deltas
- `validation`: `PASS` if decompressed bytes exactly match input
