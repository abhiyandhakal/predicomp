#ifndef PROCESS_PAGER_DAMON_H
#define PROCESS_PAGER_DAMON_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct pager_damon_config {
    uint32_t sample_us;
    uint32_t aggr_us;
    uint32_t update_us;
    uint32_t read_tick_ms;
    uint32_t nr_regions_min;
    uint32_t nr_regions_max;
};

struct pager_damon_region_obs {
    uint64_t start;
    uint64_t end;
    uint64_t nr_accesses;
    uint64_t age;
};

struct pager_damon_snapshot {
    struct pager_damon_region_obs *regions;
    size_t count;
    uint64_t total_bytes;
};

struct pager_damon {
    int enabled;
    pid_t pid;
    uint64_t region_start;
    uint64_t region_end;
    uint64_t last_poll_ns;
};

int pager_damon_setup(
    struct pager_damon *damon,
    pid_t pid,
    uint64_t region_start,
    uint64_t region_end,
    const struct pager_damon_config *cfg
);

int pager_damon_poll_snapshot(
    struct pager_damon *damon,
    const struct pager_damon_config *cfg,
    uint64_t now_ns,
    struct pager_damon_snapshot *out_snapshot
);

void pager_damon_snapshot_free(struct pager_damon_snapshot *snapshot);
void pager_damon_stop(struct pager_damon *damon);

#endif
