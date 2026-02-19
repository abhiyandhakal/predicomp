#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct trace_entry {
    __u16 type;
    __u8 flags;
    __u8 preempt_count;
    __s32 pid;
};

struct trace_event_raw_exceptions {
    struct trace_entry ent;
    unsigned long address;
    unsigned long ip;
    unsigned long error_code;
    char __data[0];
};

static __always_inline int emit_page_fault_event(
    struct trace_event_raw_exceptions *ctx,
    int is_user
)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    char comm[16];

    if (bpf_get_current_comm(&comm, sizeof(comm)) != 0) {
        return 0;
    }

    if (is_user) {
        bpf_printk(
            "page_fault pid=%d comm=%s type=user addr=0x%lx ip=0x%lx\\n",
            pid,
            comm,
            ctx->address,
            ctx->ip
        );
    } else {
        bpf_printk(
            "page_fault pid=%d comm=%s type=kernel addr=0x%lx ip=0x%lx\\n",
            pid,
            comm,
            ctx->address,
            ctx->ip
        );
    }

    return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int handle_page_fault_user(struct trace_event_raw_exceptions *ctx)
{
    return emit_page_fault_event(ctx, 1);
}

SEC("tracepoint/exceptions/page_fault_kernel")
int handle_page_fault_kernel(struct trace_event_raw_exceptions *ctx)
{
    return emit_page_fault_event(ctx, 0);
}
