# process-pager (prototype)

Cooperative userspace process pager prototype for `predicomp` research.

What it provides (v1):

- Cooperative client library (`libpredicomp_client.a`) for explicit range registration
- Sidecar daemon (`predicomp_pager`) using a Unix domain socket protocol
- `userfaultfd` fd passing (SCM_RIGHTS) from client to daemon
- UFFD missing fault handling (restore compressed page or zero-fill fallback)
- UFFD write-protect fault handling (dirty tracking)
- Cooperative client-side eviction RPC (daemon requests local `madvise(MADV_DONTNEED)`)
- DAMON sysfs polling (`admin` tree) for target access observations
- Simple in-memory LZ4 compressed page store
- Counters/logging printed at end of a session

## Build

```bash
cd process-pager
make
```

Build outputs:

- `process-pager/predicomp_pager`
- `process-pager/libpredicomp_client.a`

## Runtime Requirements

Typical requirements on an Arch guest:

- Kernel with `userfaultfd` and `DAMON` sysfs admin support
- `liblz4` development package installed (for build)
- Permission to use `userfaultfd` (`vm.unprivileged_userfaultfd=1` if not root)
- Root (or equivalent privilege) is strongly recommended for DAMON admin sysfs and `process_madvise` behavior

Notes:

- The daemon tries DAMON setup and continues if DAMON setup fails.
- This is a single-target v1 prototype (one client/session at a time).
- DAMON is configured on one contiguous span covering all registered ranges, then observations are filtered back to registered pages.
- Prototype is intended for anonymous private page ranges.
- On some kernels, `process_madvise(..., MADV_DONTNEED)` for remote eviction returns `EINVAL`.
  In that case, the daemon automatically switches to a cooperative fallback:
  it asks the client library (running in the target process) to perform local
  `madvise(MADV_DONTNEED)` on selected pages. This preserves real missing-fault restores.
- If both remote and cooperative local eviction fail, the daemon can still fall back to a
  WP-only compressed-page mode for control-loop validation.

## Run

Terminal 1 (daemon):

```bash
cd process-pager
sudo ./predicomp_pager -v \
  --csv /tmp/predicomp_pager_sessions.csv \
  --cold-age-ms 500 \
  --damon-read-ms 200 \
  --soft-cap-bytes $((64 * 1024 * 1024)) \
  --latency-sample-step 1
```

Terminal 2 (your target process):

- Link against `libpredicomp_client.a`
- Create/register page-aligned ranges
- Start the pager client before touching the workload range heavily

Minimal integration sketch:

```c
#include "predicomp_client.h"

struct predicomp_client *pc = NULL;
struct predicomp_range_handle h;

predicomp_client_open(&pc, NULL);
predicomp_client_register_range(
    pc,
    buf,
    buf_len,
    PREDICOMP_CLIENT_RANGE_F_ANON_PRIVATE | PREDICOMP_CLIENT_RANGE_F_WRITABLE,
    &h);
predicomp_client_start(pc);

/* ... workload ... */

predicomp_client_stop(pc);
predicomp_client_close(pc);
```

Example compile linkage (adjust include/library paths):

```bash
cc -O2 -g demo.c -Iprocess-pager/include process-pager/libpredicomp_client.a -o demo
```

## Protocol Summary (v1)

1. Client connects to Unix socket.
2. Client sends `HELLO` (pid + range count).
3. Client sends one `RANGE` message per registered range.
4. Client sends `START` and passes `userfaultfd` via SCM_RIGHTS.
5. Daemon acks and begins fault handling/background compression.
6. Client sends `STOP` (or disconnects) to end the session.

## What To Observe

The daemon prints a session summary with counters such as:

- DAMON snapshots/regions read
- cold page marks
- compression attempts/success/failures
- compressed-store live/peak bytes
- missing and write-protect faults
- restore success/failures
- UFFD ioctl failures
- fault service latency totals/max
- fault/restore p95/p99 latency highlights
- daemon CPU usage split by thread (`control`, `bg`, `fault`)

The daemon can also write one CSV row per session (`--csv`) with:

- all session counters
- per-thread CPU ns + CPU% of session wall time
- compressor CPU/wall timing totals and sampled p50/p95/p99/max
- decompressor/restore timing totals and sampled p50/p95/p99/max
- fault-service latency percentiles (all/missing/WP)
- client-eviction RPC and `process_madvise` latency percentiles

## Metric Semantics (Important)

- `fault_*` latency metrics:
  end-to-end fault service time in the daemon fault thread (user stall proxy)
- `restore_*` latency metrics:
  compressed-page restore path latency (decompressor-attributable path)
- `restore_codec_*` latency metrics:
  LZ4 decompression step only (excludes `UFFDIO_COPY` and other fault handling)
- `*_cpu_*` metrics:
  measured with `CLOCK_THREAD_CPUTIME_ID` in daemon threads (not target process CPU)

## Example VM Behavior (Current Arch Guest)

On the current VM kernel (`process_madvise(MADV_DONTNEED)` returns `EINVAL` remotely), the daemon
should automatically switch to cooperative client eviction and still produce real missing faults:

- `process_madvise_unsupported=1`
- `client_evict_ok > 0`
- `faults_missing > 0`
- `restore_ok > 0`
- `compress_wp_only_fallback=0` (if cooperative eviction succeeds consistently)

On kernels where remote `process_madvise` is unsupported but cooperative eviction works, you
should expect:

- `process_madvise_fail=1` and `process_madvise_unsupported=1`
- `client_evict_ok > 0`
- `faults_missing > 0`
- `restore_ok > 0`
- `compress_wp_only_fallback = 0` (or near zero if the cooperative path succeeds consistently)
