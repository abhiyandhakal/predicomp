#include "vmlinux.h"
#include "src/proc_lifecycle_event.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline int submit_event(uint32_t type, uint32_t pid_hint, const char *comm_hint)
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
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->type = type;
    event->pid = pid_hint != 0 ? pid_hint : pid;
    event->tgid = tgid;
    event->ppid = 0;
    event->ktime_ns = bpf_ktime_get_ns();

    if (comm_hint != NULL) {
        __builtin_memcpy(event->comm, comm_hint, sizeof(event->comm));
    } else {
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    return submit_event(PROC_LIFECYCLE_EVENT_EXEC, (uint32_t)ctx->pid, NULL);
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    return submit_event(PROC_LIFECYCLE_EVENT_EXIT, (uint32_t)ctx->pid, ctx->comm);
}
