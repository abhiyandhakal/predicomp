#ifndef WORKLOADS_CONTROLLER_CLIENT_H
#define WORKLOADS_CONTROLLER_CLIENT_H

#include <stdint.h>

#include <mem_arena.h>

const char *wl_controller_sock_default_if_null(const char *sock_path);

int wl_controller_send_enroll(
    const char *sock_path,
    const char *workload_name,
    int arena_cap_mb,
    int arena_min_savings_pct,
    int region_mb
);

int wl_controller_send_compress_ack(
    const char *sock_path,
    const char *workload_name,
    uint64_t trigger_count,
    const struct mem_arena_stats *stats,
    uint64_t event_ns
);

#endif
