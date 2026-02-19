# eBPF hello world: print PID on process creation

This example attaches an eBPF tracepoint program to:

- `tracepoint/sched/sched_process_fork`

On each fork, it prints the child PID with `bpf_printk`.

## Requirements

- Linux kernel with BTF support (`/sys/kernel/btf/vmlinux` exists)
- `clang`, `bpftool`, `libbpf`, `pkg-config`, `make`
- root privileges to load/attach BPF

## Build

```bash
make
```

## Run

Terminal 1:

```bash
sudo ./proc_create
```

Terminal 2:

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

You should see lines like:

```text
hello world 12345
```

If `/sys/kernel/tracing/trace_pipe` does not exist, mount tracefs:

```bash
sudo mount -t tracefs tracefs /sys/kernel/tracing
```
