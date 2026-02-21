#ifndef MEM_ARENA_LRU_H
#define MEM_ARENA_LRU_H

#include <stddef.h>
#include <stdint.h>

struct mem_arena_chunk_ref {
    int region_id;
    size_t chunk_idx;
    uint64_t tick;
};

int mem_arena_pick_lru(
    const struct mem_arena_chunk_ref *refs,
    size_t count,
    int *out_idx
);

#endif
