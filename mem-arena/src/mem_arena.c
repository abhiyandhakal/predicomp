#include "mem_arena.h"

#include "mem_arena_codec.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define MEM_ARENA_MAX_REGIONS 64
#define MEM_ARENA_POOL_ALIGN 8U

struct mem_arena_chunk {
    int compressed;
    size_t pool_off;
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

struct mem_arena_extent {
    size_t off;
    size_t len;
    struct mem_arena_extent *next;
};

struct mem_arena {
    struct mem_arena_config cfg;
    size_t pool_capacity_bytes;
    unsigned char *pool;
    struct mem_arena_extent *free_extents;
    struct mem_arena_region regions[MEM_ARENA_MAX_REGIONS];
    struct mem_arena_stats stats;
    uint64_t tick;
};

struct live_chunk_ref {
    int region_id;
    size_t chunk_idx;
    size_t off;
    size_t len;
};

static size_t align_up(size_t value, size_t align)
{
    size_t rem;

    if (align == 0) {
        return value;
    }
    rem = value % align;
    if (rem == 0) {
        return value;
    }
    return value + (align - rem);
}

static size_t chunk_alloc_len(int comp_len)
{
    return align_up((size_t)comp_len, MEM_ARENA_POOL_ALIGN);
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

static void free_extent_list(struct mem_arena_extent *head)
{
    while (head != NULL) {
        struct mem_arena_extent *next = head->next;
        free(head);
        head = next;
    }
}

static int insert_free_extent(struct mem_arena *arena, size_t off, size_t len)
{
    struct mem_arena_extent **link = &arena->free_extents;
    struct mem_arena_extent *node;

    if (len == 0) {
        return 0;
    }
    if (off + len > arena->pool_capacity_bytes) {
        return -1;
    }

    while (*link != NULL && (*link)->off < off) {
        link = &(*link)->next;
    }

    node = calloc(1, sizeof(*node));
    if (node == NULL) {
        return -1;
    }
    node->off = off;
    node->len = len;
    node->next = *link;
    *link = node;

    if (node->next != NULL && node->off + node->len == node->next->off) {
        struct mem_arena_extent *next = node->next;
        node->len += next->len;
        node->next = next->next;
        free(next);
    }

    if (&arena->free_extents != link) {
        struct mem_arena_extent *prev = arena->free_extents;
        while (prev != NULL && prev->next != node) {
            prev = prev->next;
        }
        if (prev != NULL && prev->off + prev->len == node->off) {
            prev->len += node->len;
            prev->next = node->next;
            free(node);
        }
    }

    return 0;
}

static int alloc_extent_first_fit(struct mem_arena *arena, size_t len, size_t *out_off)
{
    struct mem_arena_extent **link = &arena->free_extents;

    if (len == 0 || out_off == NULL) {
        return -1;
    }

    while (*link != NULL) {
        struct mem_arena_extent *ext = *link;

        if (ext->len >= len) {
            *out_off = ext->off;
            if (ext->len == len) {
                *link = ext->next;
                free(ext);
            } else {
                ext->off += len;
                ext->len -= len;
            }
            return 0;
        }
        link = &(*link)->next;
    }

    return 1;
}

static size_t free_total_bytes(const struct mem_arena *arena)
{
    const struct mem_arena_extent *ext = arena->free_extents;
    size_t total = 0;

    while (ext != NULL) {
        total += ext->len;
        ext = ext->next;
    }
    return total;
}

static size_t free_largest_extent(const struct mem_arena *arena)
{
    const struct mem_arena_extent *ext = arena->free_extents;
    size_t largest = 0;

    while (ext != NULL) {
        if (ext->len > largest) {
            largest = ext->len;
        }
        ext = ext->next;
    }
    return largest;
}

static void refresh_pool_stats(struct mem_arena *arena)
{
    size_t free_b = free_total_bytes(arena);
    size_t largest = free_largest_extent(arena);
    size_t live_b;

    if (free_b > arena->pool_capacity_bytes) {
        free_b = arena->pool_capacity_bytes;
    }
    live_b = arena->pool_capacity_bytes - free_b;

    arena->stats.pool_bytes_live = (uint64_t)live_b;
    arena->stats.pool_bytes_free = (uint64_t)free_b;
    arena->stats.pool_largest_free_extent = (uint64_t)largest;
    arena->stats.pool_bytes_fragmented = (uint64_t)((free_b > largest) ? (free_b - largest) : 0);
    arena->stats.slot_bytes_live = arena->stats.pool_bytes_live;
}

static int free_chunk_extent(struct mem_arena *arena, struct mem_arena_chunk *chunk)
{
    size_t alloc_len;

    if (!chunk->compressed) {
        return 0;
    }

    alloc_len = chunk_alloc_len(chunk->comp_len);
    if (insert_free_extent(arena, chunk->pool_off, alloc_len) != 0) {
        return -1;
    }

    if (arena->stats.compressed_bytes_live >= (uint64_t)chunk->comp_len) {
        arena->stats.compressed_bytes_live -= (uint64_t)chunk->comp_len;
    } else {
        arena->stats.compressed_bytes_live = 0;
    }

    chunk->compressed = 0;
    chunk->pool_off = (size_t)-1;
    chunk->comp_len = 0;
    chunk->tick = ++arena->tick;

    refresh_pool_stats(arena);
    return 0;
}

static int cmp_live_chunk_off(const void *a, const void *b)
{
    const struct live_chunk_ref *la = (const struct live_chunk_ref *)a;
    const struct live_chunk_ref *lb = (const struct live_chunk_ref *)b;

    if (la->off < lb->off) {
        return -1;
    }
    if (la->off > lb->off) {
        return 1;
    }
    return 0;
}

static int compact_pool(struct mem_arena *arena)
{
    struct live_chunk_ref *refs = NULL;
    size_t count = 0;
    size_t i;
    size_t next_off = 0;

    for (i = 0; i < MEM_ARENA_MAX_REGIONS; i++) {
        struct mem_arena_region *r = &arena->regions[i];
        size_t j;

        if (!r->in_use) {
            continue;
        }
        for (j = 0; j < r->chunk_count; j++) {
            if (r->chunks[j].compressed) {
                count++;
            }
        }
    }

    if (count > 0) {
        size_t idx = 0;

        refs = calloc(count, sizeof(*refs));
        if (refs == NULL) {
            return -1;
        }

        for (i = 0; i < MEM_ARENA_MAX_REGIONS; i++) {
            struct mem_arena_region *r = &arena->regions[i];
            size_t j;

            if (!r->in_use) {
                continue;
            }
            for (j = 0; j < r->chunk_count; j++) {
                struct mem_arena_chunk *c = &r->chunks[j];

                if (!c->compressed) {
                    continue;
                }
                refs[idx].region_id = (int)i;
                refs[idx].chunk_idx = j;
                refs[idx].off = c->pool_off;
                refs[idx].len = chunk_alloc_len(c->comp_len);
                idx++;
            }
        }

        qsort(refs, count, sizeof(*refs), cmp_live_chunk_off);

        for (i = 0; i < count; i++) {
            struct live_chunk_ref *ref = &refs[i];
            struct mem_arena_chunk *chunk = &arena->regions[ref->region_id].chunks[ref->chunk_idx];

            if (ref->off + ref->len > arena->pool_capacity_bytes) {
                free(refs);
                return -1;
            }

            if (ref->off != next_off) {
                memmove(arena->pool + next_off, arena->pool + ref->off, ref->len);
                chunk->pool_off = next_off;
            }
            next_off += ref->len;
        }
    }

    free(refs);
    free_extent_list(arena->free_extents);
    arena->free_extents = NULL;

    if (next_off < arena->pool_capacity_bytes) {
        if (insert_free_extent(arena, next_off, arena->pool_capacity_bytes - next_off) != 0) {
            return -1;
        }
    }

    arena->stats.pool_compactions++;
    refresh_pool_stats(arena);
    return 0;
}

static int decompress_chunk(struct mem_arena *arena, int region_id, size_t chunk_idx)
{
    struct mem_arena_region *region;
    struct mem_arena_chunk *chunk;
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
    if (chunk->pool_off + chunk_alloc_len(chunk->comp_len) > arena->pool_capacity_bytes) {
        return -1;
    }

    src = arena->pool + chunk->pool_off;
    dst = region->raw + (chunk_idx * arena->cfg.chunk_size);

    out_size = mem_arena_lz4_decompress(src, chunk->comp_len, dst, (int)arena->cfg.chunk_size);
    if (out_size != (int)arena->cfg.chunk_size) {
        return -1;
    }

    arena->stats.decompress_ops++;
    arena->stats.access_hits_decompressed++;

    if (free_chunk_extent(arena, chunk) != 0) {
        return -1;
    }

    return 0;
}

static int evict_one_lru(struct mem_arena *arena)
{
    int lru_region = -1;
    size_t lru_chunk = 0;
    uint64_t lru_tick = 0;
    int found = 0;
    int i;

    for (i = 0; i < MEM_ARENA_MAX_REGIONS; i++) {
        struct mem_arena_region *r = &arena->regions[i];
        size_t j;

        if (!r->in_use) {
            continue;
        }
        for (j = 0; j < r->chunk_count; j++) {
            struct mem_arena_chunk *c = &r->chunks[j];

            if (!c->compressed) {
                continue;
            }
            if (!found || c->tick < lru_tick) {
                found = 1;
                lru_tick = c->tick;
                lru_region = i;
                lru_chunk = j;
            }
        }
    }

    if (!found) {
        return -1;
    }
    if (decompress_chunk(arena, lru_region, lru_chunk) != 0) {
        return -1;
    }
    arena->stats.evictions_lru++;
    return 0;
}

static int compress_chunk(struct mem_arena *arena, int region_id, size_t chunk_idx)
{
    struct mem_arena_region *region;
    struct mem_arena_chunk *chunk;
    unsigned char *src;
    unsigned char *tmp = NULL;
    int out_size;
    int savings_pct;
    size_t alloc_len;
    size_t off = 0;

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

    arena->stats.total_chunks_attempted++;
    arena->stats.total_input_bytes_attempted += (uint64_t)arena->cfg.chunk_size;

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
        arena->stats.incompressible_chunks++;
        arena->stats.compression_reject_small_gain++;
        free(tmp);
        return 0;
    }

    alloc_len = chunk_alloc_len(out_size);
    if (alloc_len > arena->pool_capacity_bytes) {
        arena->stats.incompressible_chunks++;
        free(tmp);
        return 0;
    }

    for (;;) {
        int alloc_rc = alloc_extent_first_fit(arena, alloc_len, &off);

        if (alloc_rc == 0) {
            break;
        }
        if (alloc_rc < 0) {
            free(tmp);
            return -1;
        }

        if (free_total_bytes(arena) >= alloc_len) {
            if (compact_pool(arena) != 0) {
                free(tmp);
                return -1;
            }
            continue;
        }

        if (evict_one_lru(arena) != 0) {
            arena->stats.incompressible_chunks++;
            free(tmp);
            return 0;
        }
    }

    memcpy(arena->pool + off, tmp, (size_t)out_size);

    chunk->compressed = 1;
    chunk->pool_off = off;
    chunk->comp_len = out_size;
    chunk->tick = ++arena->tick;

    arena->stats.chunks_admitted++;
    arena->stats.compress_ops++;
    arena->stats.logical_input_bytes += (uint64_t)arena->cfg.chunk_size;
    arena->stats.compressed_bytes_live += (uint64_t)out_size;

    if (madvise(src, arena->cfg.chunk_size, MADV_DONTNEED) != 0) {
        /* Best effort only; simulation still works if kernel ignores this. */
    }

    refresh_pool_stats(arena);
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
    if (arena->cfg.lz4_acceleration <= 0) {
        arena->cfg.lz4_acceleration = 1;
    }
    if (arena->cfg.min_savings_percent < 0) {
        arena->cfg.min_savings_percent = 0;
    }
    if (arena->cfg.min_savings_percent > 95) {
        arena->cfg.min_savings_percent = 95;
    }

    arena->pool_capacity_bytes = arena->cfg.arena_capacity_bytes;
    arena->pool = calloc(1, arena->pool_capacity_bytes);
    if (arena->pool == NULL) {
        mem_arena_destroy(arena);
        return NULL;
    }

    if (insert_free_extent(arena, 0, arena->pool_capacity_bytes) != 0) {
        mem_arena_destroy(arena);
        return NULL;
    }

    refresh_pool_stats(arena);
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

    free_extent_list(arena->free_extents);
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
        chunks[idx].pool_off = (size_t)-1;
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
        struct mem_arena_chunk *chunk = &region->chunks[idx];

        if (!chunk->compressed) {
            continue;
        }
        if (free_chunk_extent(arena, chunk) != 0) {
            return -1;
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

    refresh_pool_stats(arena);
    *out_stats = arena->stats;
    return 0;
}
