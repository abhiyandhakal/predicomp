#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct swap_probe_stats {
    __u64 kswapd_wake;
    __u64 kswapd_sleep;
    __u64 direct_begin;
    __u64 direct_end;
    __u64 reclaim_pages;
    __u64 write_folio;
    __u32 last_pid;
    char last_comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct swap_probe_stats);
} stats_map SEC(".maps");

static __always_inline void update_common(struct swap_probe_stats *stats)
{
    __u64 pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();
    stats->last_pid = (__u32)(pid_tgid >> 32);
    bpf_get_current_comm(&stats->last_comm, sizeof(stats->last_comm));
}

SEC("tracepoint/vmscan/mm_vmscan_kswapd_wake")
int handle_mm_vmscan_kswapd_wake(void *ctx)
{
    __u32 key = 0;
    struct swap_probe_stats *stats;

    (void)ctx;

    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) {
        return 0;
    }

    __sync_fetch_and_add(&stats->kswapd_wake, 1);
    update_common(stats);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_kswapd_sleep")
int handle_mm_vmscan_kswapd_sleep(void *ctx)
{
    __u32 key = 0;
    struct swap_probe_stats *stats;

    (void)ctx;

    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) {
        return 0;
    }

    __sync_fetch_and_add(&stats->kswapd_sleep, 1);
    update_common(stats);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin")
int handle_mm_vmscan_direct_reclaim_begin(void *ctx)
{
    __u32 key = 0;
    struct swap_probe_stats *stats;

    (void)ctx;

    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) {
        return 0;
    }

    __sync_fetch_and_add(&stats->direct_begin, 1);
    update_common(stats);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_direct_reclaim_end")
int handle_mm_vmscan_direct_reclaim_end(void *ctx)
{
    __u32 key = 0;
    struct swap_probe_stats *stats;

    (void)ctx;

    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) {
        return 0;
    }

    __sync_fetch_and_add(&stats->direct_end, 1);
    update_common(stats);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_reclaim_pages")
int handle_mm_vmscan_reclaim_pages(void *ctx)
{
    __u32 key = 0;
    struct swap_probe_stats *stats;

    (void)ctx;

    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) {
        return 0;
    }

    __sync_fetch_and_add(&stats->reclaim_pages, 1);
    update_common(stats);
    return 0;
}

SEC("tracepoint/vmscan/mm_vmscan_write_folio")
int handle_mm_vmscan_write_folio(void *ctx)
{
    __u32 key = 0;
    struct swap_probe_stats *stats;

    (void)ctx;

    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) {
        return 0;
    }

    __sync_fetch_and_add(&stats->write_folio, 1);
    update_common(stats);
    return 0;
}
