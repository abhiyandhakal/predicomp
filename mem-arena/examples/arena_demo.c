#include "mem_arena.h"

#include <inttypes.h>
#include <stdio.h>

int main(void)
{
    struct mem_arena_config cfg;
    struct mem_arena *arena;
    struct mem_arena_stats stats;
    int region_id;
    unsigned char *raw = NULL;
    size_t off;

    cfg.arena_capacity_bytes = 16U * 1024U * 1024U;
    cfg.chunk_size = 4096U;
    cfg.min_savings_percent = 5;
    cfg.lz4_acceleration = 1;

    arena = mem_arena_create(&cfg);
    if (arena == NULL) {
        fprintf(stderr, "mem_arena_create failed\n");
        return 1;
    }

    if (mem_arena_region_alloc(arena, 8U * 1024U * 1024U, "demo", &region_id, &raw) != 0) {
        fprintf(stderr, "mem_arena_region_alloc failed\n");
        mem_arena_destroy(arena);
        return 1;
    }

    for (off = 0; off < 8U * 1024U * 1024U; off += 4096U) {
        raw[off] = 7;
    }

    if (mem_arena_compress_region(arena, region_id) != 0) {
        fprintf(stderr, "mem_arena_compress_region failed\n");
        mem_arena_destroy(arena);
        return 1;
    }

    for (off = 0; off < 8U * 1024U * 1024U; off += 4096U) {
        if (mem_arena_touch(arena, region_id, off, MEM_ARENA_OP_INC) != 0) {
            fprintf(stderr, "mem_arena_touch failed\n");
            mem_arena_destroy(arena);
            return 1;
        }
    }

    if (mem_arena_get_stats(arena, &stats) != 0) {
        fprintf(stderr, "mem_arena_get_stats failed\n");
        mem_arena_destroy(arena);
        return 1;
    }

    printf("demo compress_ops=%" PRIu64 " decompress_ops=%" PRIu64 " evictions=%" PRIu64 "\n",
           stats.compress_ops,
           stats.decompress_ops,
           stats.evictions_lru);

    mem_arena_destroy(arena);
    return 0;
}
