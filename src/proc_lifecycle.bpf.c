#include "vmlinux.h"
#include "src/proc_lifecycle_event.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline struct proc_lifecycle_event *reserve_event(uint32_t type, uint32_t pid_hint)
{
    struct proc_lifecycle_event *event;
    uint64_t pid_tgid;
    uint32_t pid;
    uint32_t tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    pid = (uint32_t)pid_tgid;
    tgid = (uint32_t)(pid_tgid >> 32);

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event == NULL) {
        return NULL;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->type = type;
    event->pid = pid_hint != 0 ? pid_hint : pid;
    event->tgid = tgid;
    event->ppid = 0;
    event->ktime_ns = bpf_ktime_get_ns();
    return event;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct proc_lifecycle_event *event;

    event = reserve_event(PROC_LIFECYCLE_EVENT_EXEC, (uint32_t)ctx->pid);
    if (event == NULL) {
        return 0;
    }

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    struct proc_lifecycle_event *event;

    event = reserve_event(PROC_LIFECYCLE_EVENT_EXIT, (uint32_t)ctx->pid);
    if (event == NULL) {
        return 0;
    }

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct proc_lifecycle_event *event;

    event = reserve_event(PROC_LIFECYCLE_EVENT_FORK, (uint32_t)ctx->child_pid);
    if (event == NULL) {
        return 0;
    }

    event->ppid = (uint32_t)ctx->parent_pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}
