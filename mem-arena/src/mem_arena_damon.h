#ifndef MEM_ARENA_DAMON_H
#define MEM_ARENA_DAMON_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct mem_arena_loops_config;

struct mem_arena_damon_region_obs {
    uint64_t start;
    uint64_t end;
    uint64_t nr_accesses;
    uint64_t age;
};

struct mem_arena_damon_snapshot {
    struct mem_arena_damon_region_obs *regions;
    size_t count;
    uint64_t total_bytes;
};

struct mem_arena_damon {
    int enabled;
    pid_t pid;
    uint64_t region_start;
    uint64_t region_end;
    uint64_t last_poll_ns;
};

int mem_arena_damon_setup(
    struct mem_arena_damon *damon,
    pid_t pid,
    uint64_t region_start,
    uint64_t region_end,
    const struct mem_arena_loops_config *cfg
);

int mem_arena_damon_poll_snapshot(
    struct mem_arena_damon *damon,
    const struct mem_arena_loops_config *cfg,
    uint64_t now_ns,
    struct mem_arena_damon_snapshot *out_snapshot
);

void mem_arena_damon_snapshot_free(struct mem_arena_damon_snapshot *snapshot);
void mem_arena_damon_stop(struct mem_arena_damon *damon);

#endif
