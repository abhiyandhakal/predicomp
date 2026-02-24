#ifndef MEM_ARENA_H
#define MEM_ARENA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEM_ARENA_OP_INC 1
#define MEM_ARENA_OP_XOR1 2

struct mem_arena_config {
    size_t arena_capacity_bytes;
    size_t chunk_size;
    int min_savings_percent;
    int lz4_acceleration;
};

struct mem_arena_loops_config {
    int enable_hotness_loop;
    int enable_compression_loop;
    int enable_prefetch_loop;
    int enable_damon_classification;
    uint32_t hotness_tick_ms;
    uint32_t compression_tick_ms;
    uint32_t prefetch_tick_ms;
    uint32_t damon_sample_us;
    uint32_t damon_aggr_us;
    uint32_t damon_update_us;
    uint32_t damon_nr_regions_min;
    uint32_t damon_nr_regions_max;
    uint32_t damon_read_tick_ms;
    uint32_t damon_hot_accesses_min;
    uint32_t damon_warm_accesses_min;
    uint32_t t_hot_epochs;
    uint32_t t_cold_epochs_initial;
    uint32_t t_cold_epochs_min;
    uint32_t t_cold_epochs_max;
    uint32_t t_cold_step_up;
    uint32_t t_cold_step_down;
    uint32_t recompress_guard_epochs;
    uint32_t churn_touch_threshold;
    uint32_t low_ratio_skip_bps;
    uint32_t prefetch_distance_chunks;
    uint32_t prefetch_batch_chunks;
    uint32_t prefetch_queue_capacity;
    uint32_t adapt_interval_ms;
    uint32_t target_pool_util_pct;
    uint32_t stall_events_threshold;
};

struct mem_arena_stats {
    uint64_t total_input_bytes_attempted;
    uint64_t total_chunks_attempted;
    uint64_t chunks_admitted;
    uint64_t logical_input_bytes;
    uint64_t compressed_bytes_live;
    uint64_t pool_bytes_live;
    uint64_t pool_bytes_free;
    uint64_t pool_bytes_fragmented;
    uint64_t pool_largest_free_extent;
    uint64_t pool_compactions;
    uint64_t slot_bytes_live;
    uint64_t compress_ops;
    uint64_t decompress_ops;
    uint64_t evictions_lru;
    uint64_t incompressible_chunks;
    uint64_t access_hits_raw;
    uint64_t access_hits_decompressed;
    uint64_t compression_reject_small_gain;
    uint64_t hotness_epoch;
    uint64_t chunks_hot;
    uint64_t chunks_warm;
    uint64_t chunks_cold;
    uint64_t damon_snapshots_total;
    uint64_t damon_regions_observed_total;
    uint64_t damon_chunks_marked_hot;
    uint64_t damon_chunks_marked_warm;
    uint64_t damon_chunks_marked_cold;
    uint64_t damon_read_errors;
    uint64_t damon_last_snapshot_nr_regions;
    uint64_t damon_last_snapshot_bytes;
    uint64_t damon_setup_failures;
    uint64_t damon_commit_failures;
    uint64_t bg_compress_attempts;
    uint64_t bg_compress_admits;
    uint64_t bg_compress_skipped_hot;
    uint64_t bg_compress_skipped_churn;
    uint64_t bg_compress_skipped_low_ratio;
    uint64_t bg_compress_skipped_recent_decompress;
    uint64_t prefetch_queue_enqueues;
    uint64_t prefetch_queue_dedup_skips;
    uint64_t prefetch_decompress_ops;
    uint64_t demand_decompress_stall_events;
    uint64_t demand_decompress_stall_ns_total;
    uint64_t adaptive_t_cold_epochs_current;
};

struct mem_arena;

struct mem_arena *mem_arena_create(const struct mem_arena_config *cfg);
void mem_arena_destroy(struct mem_arena *arena);

int mem_arena_region_alloc(
    struct mem_arena *arena,
    size_t bytes,
    const char *name,
    int *out_region_id,
    unsigned char **out_raw
);

int mem_arena_region_free(struct mem_arena *arena, int region_id);

int mem_arena_touch(
    struct mem_arena *arena,
    int region_id,
    size_t offset,
    int op_kind
);

int mem_arena_compress_region(struct mem_arena *arena, int region_id);
int mem_arena_get_stats(struct mem_arena *arena, struct mem_arena_stats *out_stats);
int mem_arena_loops_start(struct mem_arena *arena, const struct mem_arena_loops_config *cfg);
int mem_arena_loops_stop(struct mem_arena *arena);
int mem_arena_loops_is_running(struct mem_arena *arena, int *out_running);
int mem_arena_prefetch_chunk(struct mem_arena *arena, int region_id, size_t offset);
int mem_arena_prefetch_range(struct mem_arena *arena, int region_id, size_t start_offset, size_t length);
int mem_arena_phase_hint(struct mem_arena *arena, int region_id, const char *phase_name);

#ifdef __cplusplus
}
#endif

#endif
