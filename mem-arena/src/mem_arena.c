#include "mem_arena.h"

#include "mem_arena_codec.h"
#include "mem_arena_lru.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define MEM_ARENA_MAX_REGIONS 64

struct mem_arena_chunk {
    int compressed;
    int slot_idx;
    int comp_len;
    uint64_t tick;
};

struct mem_arena_region {
    int in_use;
    char name[64];
    unsigned char *raw;
    size_t bytes;
    size_t alloc_bytes;
    size_t chunk_count;
    struct mem_arena_chunk *chunks;
};

struct mem_arena_slot {
    int used;
    int region_id;
    size_t chunk_idx;
    int comp_len;
};

struct mem_arena {
    struct mem_arena_config cfg;
    size_t slot_count;
    unsigned char *pool;
    struct mem_arena_slot *slots;
    struct mem_arena_region regions[MEM_ARENA_MAX_REGIONS];
    struct mem_arena_stats stats;
    uint64_t tick;
};

static size_t align_up(size_t value, size_t align)
{
    size_t rem = value % align;

    if (rem == 0) {
        return value;
    }
    return value + (align - rem);
}

static int validate_region_id(struct mem_arena *arena, int region_id)
{
    if (region_id < 0 || region_id >= MEM_ARENA_MAX_REGIONS) {
        return -1;
    }
    if (!arena->regions[region_id].in_use) {
        return -1;
    }
    return 0;
}

static int find_free_slot(struct mem_arena *arena)
{
    size_t i;

    for (i = 0; i < arena->slot_count; i++) {
        if (!arena->slots[i].used) {
            return (int)i;
        }
    }
    return -1;
}

static int decompress_chunk(struct mem_arena *arena, int region_id, size_t chunk_idx)
{
    struct mem_arena_region *region;
    struct mem_arena_chunk *chunk;
    struct mem_arena_slot *slot;
    unsigned char *dst;
    unsigned char *src;
    int out_size;

    if (validate_region_id(arena, region_id) != 0) {
        return -1;
    }

    region = &arena->regions[region_id];
    if (chunk_idx >= region->chunk_count) {
        return -1;
    }
    chunk = &region->chunks[chunk_idx];
    if (!chunk->compressed) {
        return 0;
    }
    if (chunk->slot_idx < 0 || (size_t)chunk->slot_idx >= arena->slot_count) {
        return -1;
    }

    slot = &arena->slots[chunk->slot_idx];
    src = arena->pool + ((size_t)chunk->slot_idx * arena->cfg.chunk_size);
    dst = region->raw + (chunk_idx * arena->cfg.chunk_size);

    out_size = mem_arena_lz4_decompress(src, chunk->comp_len, dst, (int)arena->cfg.chunk_size);
    if (out_size != (int)arena->cfg.chunk_size) {
        return -1;
    }

    arena->stats.decompress_ops++;
    arena->stats.access_hits_decompressed++;
    arena->stats.compressed_bytes_live -= (uint64_t)chunk->comp_len;
    arena->stats.slot_bytes_live -= (uint64_t)arena->cfg.chunk_size;

    slot->used = 0;
    slot->region_id = -1;
    slot->chunk_idx = 0;
    slot->comp_len = 0;

    chunk->compressed = 0;
    chunk->slot_idx = -1;
    chunk->comp_len = 0;
    chunk->tick = ++arena->tick;

    return 0;
}

static int evict_one_lru(struct mem_arena *arena)
{
    struct mem_arena_chunk_ref *refs = NULL;
    int lru_slot = -1;
    size_t i;
    int rc = -1;

    refs = calloc(arena->slot_count, sizeof(*refs));
    if (refs == NULL) {
        return -1;
    }

    for (i = 0; i < arena->slot_count; i++) {
        if (!arena->slots[i].used) {
            refs[i].region_id = -1;
            refs[i].chunk_idx = 0;
            refs[i].tick = 0;
            continue;
        }
        refs[i].region_id = arena->slots[i].region_id;
        refs[i].chunk_idx = arena->slots[i].chunk_idx;
        refs[i].tick = arena->regions[refs[i].region_id].chunks[refs[i].chunk_idx].tick;
    }

    if (mem_arena_pick_lru(refs, arena->slot_count, &lru_slot) != 0) {
        goto out;
    }

    if (decompress_chunk(arena, arena->slots[lru_slot].region_id, arena->slots[lru_slot].chunk_idx) != 0) {
        goto out;
    }

    arena->stats.evictions_lru++;
    rc = 0;

out:
    free(refs);
    return rc;
}

static int compress_chunk(struct mem_arena *arena, int region_id, size_t chunk_idx)
{
    struct mem_arena_region *region;
    struct mem_arena_chunk *chunk;
    unsigned char *src;
    unsigned char *tmp = NULL;
    int out_size;
    int slot_idx;
    int savings_pct;

    if (validate_region_id(arena, region_id) != 0) {
        return -1;
    }

    region = &arena->regions[region_id];
    if (chunk_idx >= region->chunk_count) {
        return -1;
    }

    chunk = &region->chunks[chunk_idx];
    if (chunk->compressed) {
        chunk->tick = ++arena->tick;
        return 0;
    }

    src = region->raw + (chunk_idx * arena->cfg.chunk_size);
    tmp = malloc(arena->cfg.chunk_size + 128U);
    if (tmp == NULL) {
        return -1;
    }

    out_size = mem_arena_lz4_compress(
        src,
        arena->cfg.chunk_size,
        tmp,
        (int)(arena->cfg.chunk_size + 128U),
        arena->cfg.lz4_acceleration
    );
    if (out_size <= 0) {
        arena->stats.incompressible_chunks++;
        free(tmp);
        return 0;
    }

    savings_pct = (int)(((long long)(arena->cfg.chunk_size - (size_t)out_size) * 100LL) /
                        (long long)arena->cfg.chunk_size);
    if (savings_pct < arena->cfg.min_savings_percent) {
        arena->stats.compression_reject_small_gain++;
        free(tmp);
        return 0;
    }

    slot_idx = find_free_slot(arena);
    while (slot_idx < 0) {
        if (evict_one_lru(arena) != 0) {
            free(tmp);
            return -1;
        }
        slot_idx = find_free_slot(arena);
    }

    memcpy(arena->pool + ((size_t)slot_idx * arena->cfg.chunk_size), tmp, (size_t)out_size);

    arena->slots[slot_idx].used = 1;
    arena->slots[slot_idx].region_id = region_id;
    arena->slots[slot_idx].chunk_idx = chunk_idx;
    arena->slots[slot_idx].comp_len = out_size;

    chunk->compressed = 1;
    chunk->slot_idx = slot_idx;
    chunk->comp_len = out_size;
    chunk->tick = ++arena->tick;

    arena->stats.compress_ops++;
    arena->stats.logical_input_bytes += (uint64_t)arena->cfg.chunk_size;
    arena->stats.compressed_bytes_live += (uint64_t)out_size;
    arena->stats.slot_bytes_live += (uint64_t)arena->cfg.chunk_size;

    if (posix_madvise(src, arena->cfg.chunk_size, POSIX_MADV_DONTNEED) != 0) {
        /* Best effort only; simulation still works if kernel ignores this. */
    }

    free(tmp);
    return 0;
}

struct mem_arena *mem_arena_create(const struct mem_arena_config *cfg)
{
    struct mem_arena *arena;

    if (cfg == NULL || cfg->chunk_size == 0 || cfg->arena_capacity_bytes < cfg->chunk_size) {
        return NULL;
    }

    arena = calloc(1, sizeof(*arena));
    if (arena == NULL) {
        return NULL;
    }

    arena->cfg = *cfg;
    arena->slot_count = arena->cfg.arena_capacity_bytes / arena->cfg.chunk_size;
    arena->pool = calloc(arena->slot_count, arena->cfg.chunk_size);
    arena->slots = calloc(arena->slot_count, sizeof(*arena->slots));
    if (arena->pool == NULL || arena->slots == NULL) {
        mem_arena_destroy(arena);
        return NULL;
    }

    for (size_t i = 0; i < arena->slot_count; i++) {
        arena->slots[i].used = 0;
        arena->slots[i].region_id = -1;
    }

    if (arena->cfg.lz4_acceleration <= 0) {
        arena->cfg.lz4_acceleration = 1;
    }
    if (arena->cfg.min_savings_percent < 0) {
        arena->cfg.min_savings_percent = 0;
    }
    if (arena->cfg.min_savings_percent > 95) {
        arena->cfg.min_savings_percent = 95;
    }

    return arena;
}

void mem_arena_destroy(struct mem_arena *arena)
{
    int i;

    if (arena == NULL) {
        return;
    }

    for (i = 0; i < MEM_ARENA_MAX_REGIONS; i++) {
        if (!arena->regions[i].in_use) {
            continue;
        }
        if (arena->regions[i].raw != NULL) {
            munmap(arena->regions[i].raw, arena->regions[i].alloc_bytes);
        }
        free(arena->regions[i].chunks);
    }

    free(arena->slots);
    free(arena->pool);
    free(arena);
}

int mem_arena_region_alloc(
    struct mem_arena *arena,
    size_t bytes,
    const char *name,
    int *out_region_id,
    unsigned char **out_raw
)
{
    size_t alloc_bytes;
    size_t chunk_count;
    int i;
    unsigned char *raw = NULL;
    struct mem_arena_chunk *chunks = NULL;

    if (arena == NULL || out_region_id == NULL || out_raw == NULL || bytes == 0) {
        return -1;
    }

    alloc_bytes = align_up(bytes, arena->cfg.chunk_size);
    chunk_count = alloc_bytes / arena->cfg.chunk_size;

    for (i = 0; i < MEM_ARENA_MAX_REGIONS; i++) {
        if (!arena->regions[i].in_use) {
            break;
        }
    }
    if (i == MEM_ARENA_MAX_REGIONS) {
        return -1;
    }

    raw = mmap(NULL, alloc_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) {
        return -1;
    }

    chunks = calloc(chunk_count, sizeof(*chunks));
    if (chunks == NULL) {
        munmap(raw, alloc_bytes);
        return -1;
    }

    for (size_t idx = 0; idx < chunk_count; idx++) {
        chunks[idx].compressed = 0;
        chunks[idx].slot_idx = -1;
        chunks[idx].comp_len = 0;
        chunks[idx].tick = 0;
    }

    arena->regions[i].in_use = 1;
    arena->regions[i].raw = raw;
    arena->regions[i].bytes = bytes;
    arena->regions[i].alloc_bytes = alloc_bytes;
    arena->regions[i].chunk_count = chunk_count;
    arena->regions[i].chunks = chunks;
    if (name != NULL) {
        snprintf(arena->regions[i].name, sizeof(arena->regions[i].name), "%s", name);
    } else {
        snprintf(arena->regions[i].name, sizeof(arena->regions[i].name), "region-%d", i);
    }

    *out_region_id = i;
    *out_raw = raw;
    return 0;
}

int mem_arena_region_free(struct mem_arena *arena, int region_id)
{
    struct mem_arena_region *region;

    if (validate_region_id(arena, region_id) != 0) {
        return -1;
    }

    region = &arena->regions[region_id];

    for (size_t idx = 0; idx < region->chunk_count; idx++) {
        if (!region->chunks[idx].compressed) {
            continue;
        }

        if (region->chunks[idx].slot_idx >= 0 && (size_t)region->chunks[idx].slot_idx < arena->slot_count) {
            struct mem_arena_slot *slot = &arena->slots[region->chunks[idx].slot_idx];
            if (slot->used) {
                arena->stats.compressed_bytes_live -= (uint64_t)region->chunks[idx].comp_len;
                arena->stats.slot_bytes_live -= (uint64_t)arena->cfg.chunk_size;
            }
            slot->used = 0;
            slot->region_id = -1;
            slot->chunk_idx = 0;
            slot->comp_len = 0;
        }
    }

    munmap(region->raw, region->alloc_bytes);
    free(region->chunks);
    memset(region, 0, sizeof(*region));

    return 0;
}

int mem_arena_touch(
    struct mem_arena *arena,
    int region_id,
    size_t offset,
    int op_kind
)
{
    struct mem_arena_region *region;
    size_t chunk_idx;
    unsigned char *ptr;

    if (validate_region_id(arena, region_id) != 0) {
        return -1;
    }
    region = &arena->regions[region_id];

    if (offset >= region->bytes) {
        return -1;
    }

    chunk_idx = offset / arena->cfg.chunk_size;
    if (region->chunks[chunk_idx].compressed) {
        if (decompress_chunk(arena, region_id, chunk_idx) != 0) {
            return -1;
        }
    } else {
        arena->stats.access_hits_raw++;
        region->chunks[chunk_idx].tick = ++arena->tick;
    }

    ptr = region->raw + offset;
    if (op_kind == MEM_ARENA_OP_INC) {
        (*ptr)++;
    } else if (op_kind == MEM_ARENA_OP_XOR1) {
        (*ptr) ^= 1;
    } else {
        return -1;
    }

    return 0;
}

int mem_arena_compress_region(struct mem_arena *arena, int region_id)
{
    struct mem_arena_region *region;

    if (validate_region_id(arena, region_id) != 0) {
        return -1;
    }

    region = &arena->regions[region_id];
    for (size_t idx = 0; idx < region->chunk_count; idx++) {
        if (compress_chunk(arena, region_id, idx) != 0) {
            return -1;
        }
    }

    return 0;
}

int mem_arena_get_stats(struct mem_arena *arena, struct mem_arena_stats *out_stats)
{
    if (arena == NULL || out_stats == NULL) {
        return -1;
    }

    *out_stats = arena->stats;
    return 0;
}
