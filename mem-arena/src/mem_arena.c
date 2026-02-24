#include "mem_arena.h"

#include "mem_arena_codec.h"
#include "mem_arena_damon.h"

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define MEM_ARENA_MAX_REGIONS 64
#define MEM_ARENA_POOL_ALIGN 8U

enum mem_arena_temp_state {
    MEM_ARENA_STATE_HOT = 0,
    MEM_ARENA_STATE_WARM = 1,
    MEM_ARENA_STATE_COLD = 2,
};

struct mem_arena_chunk {
    int compressed;
    size_t pool_off;
    int comp_len;
    uint64_t tick;
    uint64_t last_touch_epoch;
    uint64_t last_compress_epoch;
    uint64_t last_decompress_epoch;
    uint32_t touch_count_total;
    uint32_t touch_count_window;
    uint16_t last_comp_ratio_bps;
    uint8_t temp_state;
    uint8_t prefetch_queued;
    uint8_t reserved0;
    uint8_t reserved1;
};

struct mem_arena_region {
    int in_use;
    char name[64];
    unsigned char *raw;
    size_t bytes;
    size_t alloc_bytes;
    size_t chunk_count;
    struct mem_arena_chunk *chunks;
    size_t last_touch_chunk_idx;
    long last_stride;
    uint32_t stride_run_len;
};

struct mem_arena_extent {
    size_t off;
    size_t len;
    struct mem_arena_extent *next;
};

struct mem_arena_prefetch_item {
    int region_id;
    size_t chunk_idx;
    uint8_t reason;
};

struct mem_arena {
    struct mem_arena_config cfg;
    size_t pool_capacity_bytes;
    unsigned char *pool;
    struct mem_arena_extent *free_extents;
    struct mem_arena_region regions[MEM_ARENA_MAX_REGIONS];
    struct mem_arena_stats stats;
    uint64_t tick;
    uint64_t epoch;
    pthread_mutex_t mu;
    int mu_init;
    long page_size;
    struct mem_arena_loops_config loops_cfg;
    int loops_running;
    int stop_threads;
    pthread_t hotness_thread;
    pthread_t compression_thread;
    pthread_t prefetch_thread;
    uint64_t next_adapt_ns;
    struct mem_arena_prefetch_item *prefetch_q;
    size_t prefetch_q_cap;
    size_t prefetch_q_head;
    size_t prefetch_q_len;
    struct mem_arena_damon damon;
};

struct live_chunk_ref {
    int region_id;
    size_t chunk_idx;
    size_t off;
    size_t len;
};

int mem_arena_loops_stop(struct mem_arena *arena);

static uint64_t monotonic_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_ms(uint32_t ms)
{
    struct timespec req;

    req.tv_sec = (time_t)(ms / 1000U);
    req.tv_nsec = (long)((ms % 1000U) * 1000000UL);
    nanosleep(&req, NULL);
}

static void mem_arena_lock(struct mem_arena *arena)
{
    if (arena != NULL && arena->mu_init) {
        pthread_mutex_lock(&arena->mu);
    }
}

static void mem_arena_unlock(struct mem_arena *arena)
{
    if (arena != NULL && arena->mu_init) {
        pthread_mutex_unlock(&arena->mu);
    }
}

static struct mem_arena_loops_config default_loops_config(void)
{
    struct mem_arena_loops_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_hotness_loop = 1;
    cfg.enable_compression_loop = 1;
    cfg.enable_prefetch_loop = 1;
    cfg.enable_damon_classification = 1;
    cfg.hotness_tick_ms = 100;
    cfg.compression_tick_ms = 100;
    cfg.prefetch_tick_ms = 50;
    cfg.damon_sample_us = 5000;
    cfg.damon_aggr_us = 100000;
    cfg.damon_update_us = 1000000;
    cfg.damon_nr_regions_min = 10;
    cfg.damon_nr_regions_max = 1000;
    cfg.damon_read_tick_ms = 200;
    cfg.damon_hot_accesses_min = 1;
    cfg.damon_warm_accesses_min = 0;
    cfg.t_hot_epochs = 5;
    cfg.t_cold_epochs_initial = 20;
    cfg.t_cold_epochs_min = 5;
    cfg.t_cold_epochs_max = 200;
    cfg.t_cold_step_up = 2;
    cfg.t_cold_step_down = 1;
    cfg.recompress_guard_epochs = 3;
    cfg.churn_touch_threshold = 8;
    cfg.low_ratio_skip_bps = 9000;
    cfg.prefetch_distance_chunks = 1;
    cfg.prefetch_batch_chunks = 4;
    cfg.prefetch_queue_capacity = 1024;
    cfg.adapt_interval_ms = 1000;
    cfg.target_pool_util_pct = 70;
    cfg.stall_events_threshold = 8;
    return cfg;
}

static int prefetch_queue_push(struct mem_arena *arena, int region_id, size_t chunk_idx, uint8_t reason)
{
    size_t tail;
    struct mem_arena_region *region;
    struct mem_arena_chunk *chunk;

    if (arena == NULL || region_id < 0 || region_id >= MEM_ARENA_MAX_REGIONS) {
        return -1;
    }
    region = &arena->regions[region_id];
    if (!region->in_use || chunk_idx >= region->chunk_count) {
        return -1;
    }
    chunk = &region->chunks[chunk_idx];
    if (!chunk->compressed) {
        return 0;
    }
    if (chunk->prefetch_queued) {
        arena->stats.prefetch_queue_dedup_skips++;
        return 0;
    }
    if (arena->prefetch_q_cap == 0 || arena->prefetch_q_len >= arena->prefetch_q_cap) {
        arena->stats.prefetch_queue_dedup_skips++;
        return 0;
    }

    tail = (arena->prefetch_q_head + arena->prefetch_q_len) % arena->prefetch_q_cap;
    arena->prefetch_q[tail].region_id = region_id;
    arena->prefetch_q[tail].chunk_idx = chunk_idx;
    arena->prefetch_q[tail].reason = reason;
    arena->prefetch_q_len++;
    chunk->prefetch_queued = 1;
    arena->stats.prefetch_queue_enqueues++;
    return 0;
}

static int prefetch_queue_pop(struct mem_arena *arena, struct mem_arena_prefetch_item *out_item)
{
    if (arena == NULL || out_item == NULL || arena->prefetch_q_len == 0) {
        return 1;
    }
    *out_item = arena->prefetch_q[arena->prefetch_q_head];
    arena->prefetch_q_head = (arena->prefetch_q_head + 1) % arena->prefetch_q_cap;
    arena->prefetch_q_len--;
    return 0;
}

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
    chunk->prefetch_queued = 0;

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
    chunk->last_decompress_epoch = arena->epoch;
    chunk->touch_count_window++;
    chunk->temp_state = MEM_ARENA_STATE_HOT;

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
    chunk->last_compress_epoch = arena->epoch;
    chunk->last_comp_ratio_bps = (uint16_t)(((uint64_t)out_size * 10000ULL) / arena->cfg.chunk_size);
    chunk->temp_state = MEM_ARENA_STATE_COLD;
    chunk->prefetch_queued = 0;

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
    arena->page_size = sysconf(_SC_PAGESIZE);
    if (arena->page_size <= 0) {
        arena->page_size = 4096;
    }
    if (pthread_mutex_init(&arena->mu, NULL) != 0) {
        free(arena);
        return NULL;
    }
    arena->mu_init = 1;

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

    (void)mem_arena_loops_stop(arena);

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
    free(arena->prefetch_q);
    free(arena->pool);
    if (arena->mu_init) {
        pthread_mutex_destroy(&arena->mu);
    }
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
    mem_arena_lock(arena);

    alloc_bytes = align_up(bytes, arena->cfg.chunk_size);
    chunk_count = alloc_bytes / arena->cfg.chunk_size;

    for (i = 0; i < MEM_ARENA_MAX_REGIONS; i++) {
        if (!arena->regions[i].in_use) {
            break;
        }
    }
    if (i == MEM_ARENA_MAX_REGIONS) {
        mem_arena_unlock(arena);
        return -1;
    }

    raw = mmap(NULL, alloc_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw == MAP_FAILED) {
        mem_arena_unlock(arena);
        return -1;
    }

    chunks = calloc(chunk_count, sizeof(*chunks));
    if (chunks == NULL) {
        munmap(raw, alloc_bytes);
        mem_arena_unlock(arena);
        return -1;
    }

    for (size_t idx = 0; idx < chunk_count; idx++) {
        chunks[idx].compressed = 0;
        chunks[idx].pool_off = (size_t)-1;
        chunks[idx].comp_len = 0;
        chunks[idx].tick = 0;
        chunks[idx].temp_state = MEM_ARENA_STATE_HOT;
    }

    arena->regions[i].in_use = 1;
    arena->regions[i].raw = raw;
    arena->regions[i].bytes = bytes;
    arena->regions[i].alloc_bytes = alloc_bytes;
    arena->regions[i].chunk_count = chunk_count;
    arena->regions[i].chunks = chunks;
    arena->regions[i].last_touch_chunk_idx = 0;
    arena->regions[i].last_stride = 0;
    arena->regions[i].stride_run_len = 0;
    if (name != NULL) {
        snprintf(arena->regions[i].name, sizeof(arena->regions[i].name), "%s", name);
    } else {
        snprintf(arena->regions[i].name, sizeof(arena->regions[i].name), "region-%d", i);
    }

    *out_region_id = i;
    *out_raw = raw;
    mem_arena_unlock(arena);
    return 0;
}

int mem_arena_region_free(struct mem_arena *arena, int region_id)
{
    struct mem_arena_region *region;

    mem_arena_lock(arena);
    if (validate_region_id(arena, region_id) != 0) {
        mem_arena_unlock(arena);
        return -1;
    }

    region = &arena->regions[region_id];

    for (size_t idx = 0; idx < region->chunk_count; idx++) {
        struct mem_arena_chunk *chunk = &region->chunks[idx];

        if (!chunk->compressed) {
            continue;
        }
        if (free_chunk_extent(arena, chunk) != 0) {
            mem_arena_unlock(arena);
            return -1;
        }
    }

    munmap(region->raw, region->alloc_bytes);
    free(region->chunks);
    memset(region, 0, sizeof(*region));
    mem_arena_unlock(arena);

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
    struct mem_arena_chunk *chunk;
    uint64_t stall_start_ns = 0;
    uint64_t stall_end_ns = 0;
    size_t prev_chunk_idx;
    long stride;

    mem_arena_lock(arena);
    if (validate_region_id(arena, region_id) != 0) {
        mem_arena_unlock(arena);
        return -1;
    }
    region = &arena->regions[region_id];

    if (offset >= region->bytes) {
        mem_arena_unlock(arena);
        return -1;
    }

    chunk_idx = offset / arena->cfg.chunk_size;
    chunk = &region->chunks[chunk_idx];

    if (chunk->compressed) {
        stall_start_ns = monotonic_ns();
        if (decompress_chunk(arena, region_id, chunk_idx) != 0) {
            mem_arena_unlock(arena);
            return -1;
        }
        stall_end_ns = monotonic_ns();
        arena->stats.demand_decompress_stall_events++;
        arena->stats.demand_decompress_stall_ns_total += (stall_end_ns - stall_start_ns);
    } else {
        arena->stats.access_hits_raw++;
        chunk->tick = ++arena->tick;
    }

    ptr = region->raw + offset;
    if (op_kind == MEM_ARENA_OP_INC) {
        (*ptr)++;
    } else if (op_kind == MEM_ARENA_OP_XOR1) {
        (*ptr) ^= 1;
    } else {
        mem_arena_unlock(arena);
        return -1;
    }

    chunk = &region->chunks[chunk_idx];
    chunk->last_touch_epoch = arena->epoch;
    chunk->touch_count_total++;
    chunk->touch_count_window++;
    chunk->temp_state = MEM_ARENA_STATE_HOT;
    chunk->tick = ++arena->tick;

    prev_chunk_idx = region->last_touch_chunk_idx;
    stride = (long)chunk_idx - (long)prev_chunk_idx;
    if (region->stride_run_len == 0) {
        region->last_stride = stride;
        region->stride_run_len = 1;
    } else if (stride == region->last_stride) {
        region->stride_run_len++;
    } else {
        region->last_stride = stride;
        region->stride_run_len = 1;
    }
    region->last_touch_chunk_idx = chunk_idx;

    if (arena->loops_running &&
        arena->loops_cfg.enable_prefetch_loop &&
        region->stride_run_len >= 3 &&
        region->last_stride == 1) {
        for (uint32_t i = 0; i < arena->loops_cfg.prefetch_batch_chunks; i++) {
            size_t next_idx = chunk_idx + arena->loops_cfg.prefetch_distance_chunks + i;
            if (next_idx >= region->chunk_count) {
                break;
            }
            (void)prefetch_queue_push(arena, region_id, next_idx, 1);
        }
    }

    mem_arena_unlock(arena);

    return 0;
}

int mem_arena_compress_region(struct mem_arena *arena, int region_id)
{
    struct mem_arena_region *region;

    mem_arena_lock(arena);
    if (validate_region_id(arena, region_id) != 0) {
        mem_arena_unlock(arena);
        return -1;
    }

    region = &arena->regions[region_id];
    for (size_t idx = 0; idx < region->chunk_count; idx++) {
        if (compress_chunk(arena, region_id, idx) != 0) {
            mem_arena_unlock(arena);
            return -1;
        }
    }
    mem_arena_unlock(arena);

    return 0;
}

static void update_chunk_temp_states_locked(struct mem_arena *arena)
{
    uint64_t hot = 0;
    uint64_t warm = 0;
    uint64_t cold = 0;
    uint64_t epoch = arena->epoch;
    uint32_t t_hot = arena->loops_cfg.t_hot_epochs;
    uint32_t t_cold = (uint32_t)arena->stats.adaptive_t_cold_epochs_current;

    for (int i = 0; i < MEM_ARENA_MAX_REGIONS; i++) {
        struct mem_arena_region *r = &arena->regions[i];

        if (!r->in_use) {
            continue;
        }
        for (size_t j = 0; j < r->chunk_count; j++) {
            struct mem_arena_chunk *c = &r->chunks[j];
            uint64_t age = (epoch >= c->last_touch_epoch) ? (epoch - c->last_touch_epoch) : 0;

            if (age <= t_hot) {
                c->temp_state = MEM_ARENA_STATE_HOT;
                hot++;
            } else if (age >= t_cold) {
                c->temp_state = MEM_ARENA_STATE_COLD;
                cold++;
            } else {
                c->temp_state = MEM_ARENA_STATE_WARM;
                warm++;
            }
        }
    }

    arena->stats.chunks_hot = hot;
    arena->stats.chunks_warm = warm;
    arena->stats.chunks_cold = cold;
}

static void decay_touch_windows_locked(struct mem_arena *arena)
{
    for (int i = 0; i < MEM_ARENA_MAX_REGIONS; i++) {
        struct mem_arena_region *r = &arena->regions[i];

        if (!r->in_use) {
            continue;
        }
        for (size_t j = 0; j < r->chunk_count; j++) {
            struct mem_arena_chunk *c = &r->chunks[j];

            c->touch_count_window /= 2U;
        }
    }
}

static void apply_damon_snapshot_locked(
    struct mem_arena *arena,
    const struct mem_arena_damon_snapshot *snapshot
)
{
    uint64_t hot_marks = 0;
    uint64_t warm_marks = 0;
    uint64_t cold_marks = 0;
    uint32_t hot_thr;
    uint32_t warm_thr;

    if (arena == NULL || snapshot == NULL) {
        return;
    }

    hot_thr = arena->loops_cfg.damon_hot_accesses_min ? arena->loops_cfg.damon_hot_accesses_min : 1;
    warm_thr = arena->loops_cfg.damon_warm_accesses_min;

    arena->stats.damon_snapshots_total++;
    arena->stats.damon_last_snapshot_nr_regions = snapshot->count;
    arena->stats.damon_last_snapshot_bytes = snapshot->total_bytes;
    arena->stats.damon_regions_observed_total += snapshot->count;

    for (size_t i = 0; i < snapshot->count; i++) {
        const struct mem_arena_damon_region_obs *obs = &snapshot->regions[i];
        uint64_t clamped_start;
        uint64_t clamped_end;

        if (obs->end <= obs->start) {
            continue;
        }

        clamped_start = obs->start;
        clamped_end = obs->end;

        for (int rid = 0; rid < MEM_ARENA_MAX_REGIONS; rid++) {
            struct mem_arena_region *r = &arena->regions[rid];
            uint64_t base;
            uint64_t limit;

            if (!r->in_use || r->raw == NULL) {
                continue;
            }
            base = (uint64_t)(uintptr_t)r->raw;
            limit = base + (uint64_t)r->alloc_bytes;
            if (clamped_end <= base || clamped_start >= limit) {
                continue;
            }
            if (clamped_start < base) {
                clamped_start = base;
            }
            if (clamped_end > limit) {
                clamped_end = limit;
            }
            if (clamped_end <= clamped_start) {
                break;
            }

            size_t first = (size_t)((clamped_start - base) / arena->cfg.chunk_size);
            size_t last = (size_t)(((clamped_end - 1U) - base) / arena->cfg.chunk_size);
            if (last >= r->chunk_count) {
                last = r->chunk_count - 1;
            }

            for (size_t cidx = first; cidx <= last; cidx++) {
                struct mem_arena_chunk *c = &r->chunks[cidx];

                if (obs->nr_accesses >= hot_thr) {
                    c->last_touch_epoch = arena->epoch;
                    c->temp_state = MEM_ARENA_STATE_HOT;
                    hot_marks++;
                } else if (obs->nr_accesses >= warm_thr) {
                    if (c->temp_state == MEM_ARENA_STATE_COLD) {
                        c->temp_state = MEM_ARENA_STATE_WARM;
                    }
                    warm_marks++;
                } else {
                    cold_marks++;
                }
            }
            break;
        }
    }

    arena->stats.damon_chunks_marked_hot += hot_marks;
    arena->stats.damon_chunks_marked_warm += warm_marks;
    arena->stats.damon_chunks_marked_cold += cold_marks;
}

static void maybe_apply_damon_locked(struct mem_arena *arena)
{
    struct mem_arena_damon_snapshot snapshot;
    uint64_t now_ns;
    int rc;

    if (arena == NULL || !arena->loops_cfg.enable_damon_classification || !arena->damon.enabled) {
        return;
    }

    now_ns = monotonic_ns();
    rc = mem_arena_damon_poll_snapshot(&arena->damon, &arena->loops_cfg, now_ns, &snapshot);
    if (rc == 1) {
        return;
    }
    if (rc != 0) {
        arena->stats.damon_read_errors++;
        return;
    }

    apply_damon_snapshot_locked(arena, &snapshot);
    mem_arena_damon_snapshot_free(&snapshot);
}

static void adapt_t_cold_locked(struct mem_arena *arena)
{
    uint64_t now_ns;
    uint32_t cur;
    uint64_t stalls;
    uint64_t pool_util_pct = 0;

    if (arena->loops_cfg.adapt_interval_ms == 0) {
        return;
    }
    now_ns = monotonic_ns();
    if (arena->next_adapt_ns != 0 && now_ns < arena->next_adapt_ns) {
        return;
    }
    arena->next_adapt_ns = now_ns + ((uint64_t)arena->loops_cfg.adapt_interval_ms * 1000000ULL);

    cur = (uint32_t)arena->stats.adaptive_t_cold_epochs_current;
    if (cur == 0) {
        cur = arena->loops_cfg.t_cold_epochs_initial;
    }
    stalls = arena->stats.demand_decompress_stall_events;
    if (arena->pool_capacity_bytes > 0) {
        pool_util_pct = (arena->stats.pool_bytes_live * 100ULL) / arena->pool_capacity_bytes;
    }

    if (stalls > arena->loops_cfg.stall_events_threshold) {
        if (cur + arena->loops_cfg.t_cold_step_up <= arena->loops_cfg.t_cold_epochs_max) {
            cur += arena->loops_cfg.t_cold_step_up;
        } else {
            cur = arena->loops_cfg.t_cold_epochs_max;
        }
        arena->stats.demand_decompress_stall_events = 0;
        arena->stats.demand_decompress_stall_ns_total = 0;
    } else if (pool_util_pct < arena->loops_cfg.target_pool_util_pct) {
        if (cur > arena->loops_cfg.t_cold_epochs_min + arena->loops_cfg.t_cold_step_down) {
            cur -= arena->loops_cfg.t_cold_step_down;
        } else {
            cur = arena->loops_cfg.t_cold_epochs_min;
        }
    }

    if (cur < arena->loops_cfg.t_cold_epochs_min) {
        cur = arena->loops_cfg.t_cold_epochs_min;
    }
    if (cur > arena->loops_cfg.t_cold_epochs_max) {
        cur = arena->loops_cfg.t_cold_epochs_max;
    }
    arena->stats.adaptive_t_cold_epochs_current = cur;
}

static void *hotness_loop_main(void *arg)
{
    struct mem_arena *arena = (struct mem_arena *)arg;

    while (!arena->stop_threads) {
        mem_arena_lock(arena);
        arena->epoch++;
        arena->stats.hotness_epoch = arena->epoch;
        maybe_apply_damon_locked(arena);
        decay_touch_windows_locked(arena);
        update_chunk_temp_states_locked(arena);
        mem_arena_unlock(arena);
        sleep_ms(arena->loops_cfg.hotness_tick_ms ? arena->loops_cfg.hotness_tick_ms : 100);
    }
    return NULL;
}

static void *compression_loop_main(void *arg)
{
    struct mem_arena *arena = (struct mem_arena *)arg;

    while (!arena->stop_threads) {
        uint32_t compressed_this_tick = 0;
        uint32_t max_per_tick = 128;

        mem_arena_lock(arena);
        update_chunk_temp_states_locked(arena);
        adapt_t_cold_locked(arena);
        for (int i = 0; i < MEM_ARENA_MAX_REGIONS && !arena->stop_threads; i++) {
            struct mem_arena_region *r = &arena->regions[i];

            if (!r->in_use) {
                continue;
            }
            for (size_t j = 0; j < r->chunk_count; j++) {
                struct mem_arena_chunk *c = &r->chunks[j];

                if (compressed_this_tick >= max_per_tick) {
                    break;
                }
                if (c->compressed) {
                    continue;
                }
                if (c->temp_state != MEM_ARENA_STATE_COLD) {
                    arena->stats.bg_compress_skipped_hot++;
                    continue;
                }
                if (c->touch_count_window > arena->loops_cfg.churn_touch_threshold) {
                    arena->stats.bg_compress_skipped_churn++;
                    continue;
                }
                if (c->last_comp_ratio_bps != 0 && c->last_comp_ratio_bps > arena->loops_cfg.low_ratio_skip_bps) {
                    arena->stats.bg_compress_skipped_low_ratio++;
                    continue;
                }
                if (arena->epoch >= c->last_decompress_epoch &&
                    (arena->epoch - c->last_decompress_epoch) < arena->loops_cfg.recompress_guard_epochs) {
                    arena->stats.bg_compress_skipped_recent_decompress++;
                    continue;
                }

                arena->stats.bg_compress_attempts++;
                if (compress_chunk(arena, i, j) != 0) {
                    continue;
                }
                if (r->chunks[j].compressed) {
                    arena->stats.bg_compress_admits++;
                    compressed_this_tick++;
                }
            }
        }
        mem_arena_unlock(arena);
        sleep_ms(arena->loops_cfg.compression_tick_ms ? arena->loops_cfg.compression_tick_ms : 100);
    }
    return NULL;
}

static void *prefetch_loop_main(void *arg)
{
    struct mem_arena *arena = (struct mem_arena *)arg;

    while (!arena->stop_threads) {
        struct mem_arena_prefetch_item item;

        mem_arena_lock(arena);
        if (prefetch_queue_pop(arena, &item) == 0) {
            if (validate_region_id(arena, item.region_id) == 0 &&
                item.chunk_idx < arena->regions[item.region_id].chunk_count) {
                struct mem_arena_chunk *c = &arena->regions[item.region_id].chunks[item.chunk_idx];

                c->prefetch_queued = 0;
                if (c->compressed && decompress_chunk(arena, item.region_id, item.chunk_idx) == 0) {
                    arena->stats.prefetch_decompress_ops++;
                }
            }
            mem_arena_unlock(arena);
            continue;
        }
        mem_arena_unlock(arena);
        sleep_ms(arena->loops_cfg.prefetch_tick_ms ? arena->loops_cfg.prefetch_tick_ms : 50);
    }
    return NULL;
}

int mem_arena_loops_start(struct mem_arena *arena, const struct mem_arena_loops_config *cfg)
{
    int rc = 0;

    if (arena == NULL) {
        return -1;
    }

    mem_arena_lock(arena);
    if (arena->loops_running) {
        mem_arena_unlock(arena);
        return 0;
    }
    arena->loops_cfg = cfg != NULL ? *cfg : default_loops_config();
    if (arena->loops_cfg.t_cold_epochs_initial == 0) {
        arena->loops_cfg = default_loops_config();
    }
    arena->stats.adaptive_t_cold_epochs_current = arena->loops_cfg.t_cold_epochs_initial;
    arena->stop_threads = 0;
    arena->epoch = 0;
    arena->stats.hotness_epoch = 0;
    if (arena->loops_cfg.prefetch_queue_capacity == 0) {
        arena->loops_cfg.prefetch_queue_capacity = 1024;
    }
    if (arena->prefetch_q_cap != arena->loops_cfg.prefetch_queue_capacity) {
        free(arena->prefetch_q);
        arena->prefetch_q = calloc(arena->loops_cfg.prefetch_queue_capacity, sizeof(*arena->prefetch_q));
        if (arena->prefetch_q == NULL) {
            arena->prefetch_q_cap = 0;
            mem_arena_unlock(arena);
            return -1;
        }
        arena->prefetch_q_cap = arena->loops_cfg.prefetch_queue_capacity;
    }
    arena->prefetch_q_head = 0;
    arena->prefetch_q_len = 0;
    arena->next_adapt_ns = 0;
    arena->loops_running = 1;
    mem_arena_unlock(arena);

    if (arena->loops_cfg.enable_damon_classification) {
        int found_region = -1;
        uint64_t start = 0;
        uint64_t end = 0;

        mem_arena_lock(arena);
        for (int i = 0; i < MEM_ARENA_MAX_REGIONS; i++) {
            if (!arena->regions[i].in_use || arena->regions[i].raw == NULL) {
                continue;
            }
            found_region = i;
            start = (uint64_t)(uintptr_t)arena->regions[i].raw;
            end = start + (uint64_t)arena->regions[i].alloc_bytes;
            break;
        }
        mem_arena_unlock(arena);
        if (found_region < 0) {
            mem_arena_loops_stop(arena);
            return -1;
        }
        rc = mem_arena_damon_setup(&arena->damon, getpid(), start, end, &arena->loops_cfg);
        if (rc != 0) {
            mem_arena_lock(arena);
            arena->stats.damon_setup_failures++;
            mem_arena_unlock(arena);
            mem_arena_loops_stop(arena);
            return -1;
        }
    }
    if (arena->loops_cfg.enable_hotness_loop &&
        pthread_create(&arena->hotness_thread, NULL, hotness_loop_main, arena) != 0) {
        mem_arena_loops_stop(arena);
        return -1;
    }
    if (arena->loops_cfg.enable_compression_loop &&
        pthread_create(&arena->compression_thread, NULL, compression_loop_main, arena) != 0) {
        mem_arena_loops_stop(arena);
        return -1;
    }
    if (arena->loops_cfg.enable_prefetch_loop &&
        pthread_create(&arena->prefetch_thread, NULL, prefetch_loop_main, arena) != 0) {
        mem_arena_loops_stop(arena);
        return -1;
    }

    return 0;
}

int mem_arena_loops_stop(struct mem_arena *arena)
{
    int hot_enabled;
    int comp_enabled;
    int pref_enabled;
    pthread_t hot_t = 0;
    pthread_t comp_t = 0;
    pthread_t pref_t = 0;

    if (arena == NULL) {
        return -1;
    }

    mem_arena_lock(arena);
    if (!arena->loops_running) {
        mem_arena_unlock(arena);
        return 0;
    }
    arena->stop_threads = 1;
    hot_enabled = arena->loops_cfg.enable_hotness_loop;
    comp_enabled = arena->loops_cfg.enable_compression_loop;
    pref_enabled = arena->loops_cfg.enable_prefetch_loop;
    hot_t = arena->hotness_thread;
    comp_t = arena->compression_thread;
    pref_t = arena->prefetch_thread;
    arena->loops_running = 0;
    mem_arena_unlock(arena);

    if (hot_enabled && hot_t != (pthread_t)0) {
        (void)pthread_join(hot_t, NULL);
        arena->hotness_thread = (pthread_t)0;
    }
    if (comp_enabled && comp_t != (pthread_t)0) {
        (void)pthread_join(comp_t, NULL);
        arena->compression_thread = (pthread_t)0;
    }
    if (pref_enabled && pref_t != (pthread_t)0) {
        (void)pthread_join(pref_t, NULL);
        arena->prefetch_thread = (pthread_t)0;
    }

    if (arena->loops_cfg.enable_damon_classification) {
        mem_arena_damon_stop(&arena->damon);
    }

    return 0;
}

int mem_arena_loops_is_running(struct mem_arena *arena, int *out_running)
{
    if (arena == NULL || out_running == NULL) {
        return -1;
    }
    mem_arena_lock(arena);
    *out_running = arena->loops_running;
    mem_arena_unlock(arena);
    return 0;
}

int mem_arena_prefetch_chunk(struct mem_arena *arena, int region_id, size_t offset)
{
    size_t chunk_idx;

    if (arena == NULL) {
        return -1;
    }
    mem_arena_lock(arena);
    if (validate_region_id(arena, region_id) != 0) {
        mem_arena_unlock(arena);
        return -1;
    }
    if (offset >= arena->regions[region_id].bytes) {
        mem_arena_unlock(arena);
        return -1;
    }
    chunk_idx = offset / arena->cfg.chunk_size;
    (void)prefetch_queue_push(arena, region_id, chunk_idx, 2);
    mem_arena_unlock(arena);
    return 0;
}

int mem_arena_prefetch_range(struct mem_arena *arena, int region_id, size_t start_offset, size_t length)
{
    if (arena == NULL || length == 0) {
        return -1;
    }
    for (size_t off = start_offset; off < start_offset + length; off += arena->cfg.chunk_size) {
        (void)mem_arena_prefetch_chunk(arena, region_id, off);
        if (off + arena->cfg.chunk_size < off) {
            break;
        }
    }
    return 0;
}

int mem_arena_phase_hint(struct mem_arena *arena, int region_id, const char *phase_name)
{
    if (arena == NULL || phase_name == NULL) {
        return -1;
    }
    if (strcmp(phase_name, "active_soon") == 0) {
        mem_arena_lock(arena);
        if (validate_region_id(arena, region_id) == 0) {
            size_t max_chunks = arena->loops_cfg.prefetch_batch_chunks * 2U;
            struct mem_arena_region *r = &arena->regions[region_id];
            if (max_chunks == 0) {
                max_chunks = 8;
            }
            for (size_t i = 0; i < r->chunk_count && i < max_chunks; i++) {
                (void)prefetch_queue_push(arena, region_id, i, 3);
            }
        }
        mem_arena_unlock(arena);
    }
    return 0;
}

int mem_arena_get_stats(struct mem_arena *arena, struct mem_arena_stats *out_stats)
{
    if (arena == NULL || out_stats == NULL) {
        return -1;
    }

    mem_arena_lock(arena);
    refresh_pool_stats(arena);
    *out_stats = arena->stats;
    mem_arena_unlock(arena);
    return 0;
}
