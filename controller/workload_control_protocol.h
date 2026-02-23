#ifndef WORKLOAD_CONTROL_PROTOCOL_H
#define WORKLOAD_CONTROL_PROTOCOL_H

#include <stdint.h>

#define WL_CONTROLLER_SOCK_DEFAULT "/tmp/predicomp-controller.sock"
#define WL_CONTROLLER_WORKLOAD_NAME_LEN 32

enum wl_controller_msg_type {
    WL_CTL_MSG_ENROLL = 1,
    WL_CTL_MSG_COMPRESS_ACK = 2,
};

struct wl_controller_msg_enroll {
    uint32_t msg_type;
    uint32_t pid;
    char workload_name[WL_CONTROLLER_WORKLOAD_NAME_LEN];
    uint32_t use_mem_arena;
    uint32_t arena_cap_mb;
    uint32_t arena_min_savings_pct;
    uint32_t region_mb;
};

struct wl_controller_msg_compress_ack {
    uint32_t msg_type;
    uint32_t pid;
    char workload_name[WL_CONTROLLER_WORKLOAD_NAME_LEN];
    uint64_t event_ns;
    uint64_t trigger_count;
    uint64_t total_input_bytes_attempted;
    uint64_t chunks_admitted;
    uint64_t logical_input_bytes;
    uint64_t compressed_bytes_live;
    uint64_t pool_bytes_live;
    uint64_t pool_bytes_free;
    uint64_t pool_compactions;
    uint64_t compress_ops;
    uint64_t decompress_ops;
    uint64_t evictions_lru;
    uint64_t incompressible_chunks;
};

#endif
