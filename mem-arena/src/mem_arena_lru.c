#include "mem_arena_lru.h"

#include <stddef.h>

int mem_arena_pick_lru(
    const struct mem_arena_chunk_ref *refs,
    size_t count,
    int *out_idx
)
{
    size_t i;
    int found = 0;
    size_t best_idx = 0;

    for (i = 0; i < count; i++) {
        if (refs[i].region_id < 0) {
            continue;
        }
        if (!found || refs[i].tick < refs[best_idx].tick) {
            best_idx = i;
            found = 1;
        }
    }

    if (!found) {
        return -1;
    }

    *out_idx = (int)best_idx;
    return 0;
}
