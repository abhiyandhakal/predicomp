# eBPF probes for process and memory research

This repository currently contains two small eBPF programs:

- `proc_create`: prints `hello world <PID>` on process fork
- `page_fault`: prints page fault events with PID, command name, and user/kernel type

Both programs use `bpf_printk`, so output is read from `trace_pipe`.

## Requirements

- Linux kernel with BTF support (`/sys/kernel/btf/vmlinux` exists)
- `clang`, `bpftool`, `libbpf`, `pkg-config`, `make`
- root privileges to load/attach BPF

## Build all

```bash
make
```

## Run process-fork monitor

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

## Run page-fault monitor

Terminal 1:

```bash
sudo ./page_fault
```

Terminal 2:

```bash
sudo cat /sys/kernel/tracing/trace_pipe
```

You should see lines like:

```text
page_fault pid=12345 comm=bash type=user
page_fault pid=12345 comm=bash type=kernel
```

If `/sys/kernel/tracing/trace_pipe` does not exist, mount tracefs:

```bash
sudo mount -t tracefs tracefs /sys/kernel/tracing
```
