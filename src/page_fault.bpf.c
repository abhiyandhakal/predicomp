#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline int emit_page_fault_event(int is_user) {
  __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  char comm[16];

  if (bpf_get_current_comm(&comm, sizeof(comm)) != 0) {
    return 0;
  }

  if (is_user) {
    bpf_printk("page_fault pid=%d comm=%s type=user\\n", pid, comm);
  } else {
    bpf_printk("page_fault pid=%d comm=%s type=kernel\\n", pid, comm);
  }

  return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int handle_page_fault_user(void *ctx) {
  (void)ctx;
  return emit_page_fault_event(1);
}

SEC("tracepoint/exceptions/page_fault_kernel")
int handle_page_fault_kernel(void *ctx) {
  (void)ctx;
  return emit_page_fault_event(0);
}
