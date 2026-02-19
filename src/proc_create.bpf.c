#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    int child_pid = (int)ctx->child_pid;

    bpf_printk("hello world %d\\n", child_pid);
    return 0;
}
