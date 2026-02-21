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

struct mem_arena_stats {
    uint64_t logical_input_bytes;
    uint64_t compressed_bytes_live;
    uint64_t slot_bytes_live;
    uint64_t compress_ops;
    uint64_t decompress_ops;
    uint64_t evictions_lru;
    uint64_t incompressible_chunks;
    uint64_t access_hits_raw;
    uint64_t access_hits_decompressed;
    uint64_t compression_reject_small_gain;
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

#ifdef __cplusplus
}
#endif

#endif
