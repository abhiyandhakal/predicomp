#include "mem_arena_damon.h"

#include "mem_arena.h"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define DAMON_ADMIN_ROOT "/sys/kernel/mm/damon/admin"

static int path_join(char *out, size_t out_sz, const char *a, const char *b)
{
    if (out == NULL || out_sz == 0 || a == NULL || b == NULL) {
        return -1;
    }
    if (snprintf(out, out_sz, "%s/%s", a, b) >= (int)out_sz) {
        return -1;
    }
    return 0;
}

static int write_text_file(const char *path, const char *value)
{
    FILE *fp;

    fp = fopen(path, "w");
    if (fp == NULL) {
        return -1;
    }
    if (fputs(value, fp) == EOF) {
        fclose(fp);
        return -1;
    }
    if (fputc('\n', fp) == EOF) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0) {
        return -1;
    }
    return 0;
}

static int write_u64_file(const char *path, uint64_t value)
{
    char buf[64];

    snprintf(buf, sizeof(buf), "%" PRIu64, value);
    return write_text_file(path, buf);
}

static int read_u64_file(const char *path, uint64_t *out_value)
{
    FILE *fp;
    unsigned long long value;

    if (out_value == NULL) {
        return -1;
    }
    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    if (fscanf(fp, "%llu", &value) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *out_value = (uint64_t)value;
    return 0;
}

static int is_numeric_name(const char *name)
{
    if (name == NULL || *name == '\0') {
        return 0;
    }
    for (const char *p = name; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
    }
    return 1;
}

static int ensure_dir_exists(const char *path)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        return -1;
    }
    return S_ISDIR(st.st_mode) ? 0 : -1;
}

static int configure_single_context_target_region(
    pid_t pid,
    uint64_t region_start,
    uint64_t region_end,
    const struct mem_arena_loops_config *cfg
)
{
    char path[PATH_MAX];
    char ctx_path[PATH_MAX];
    char target_path[PATH_MAX];
    char attrs_path[PATH_MAX];
    char scheme_path[PATH_MAX];

    if (path_join(path, sizeof(path), DAMON_ADMIN_ROOT, "kdamonds/nr_kdamonds") != 0) {
        return -1;
    }
    if (write_u64_file(path, 1) != 0) {
        return -1;
    }

    if (path_join(ctx_path, sizeof(ctx_path), DAMON_ADMIN_ROOT, "kdamonds/0/contexts") != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), ctx_path, "nr_contexts") != 0 || write_u64_file(path, 1) != 0) {
        return -1;
    }
    {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s", ctx_path);
        if (snprintf(ctx_path, sizeof(ctx_path), "%s/0", tmp) >= (int)sizeof(ctx_path)) {
            return -1;
        }
    }
    if (path_join(path, sizeof(path), ctx_path, "operations") != 0 || write_text_file(path, "vaddr") != 0) {
        return -1;
    }

    if (path_join(attrs_path, sizeof(attrs_path), ctx_path, "monitoring_attrs") != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), attrs_path, "intervals/sample_us") != 0 ||
        write_u64_file(path, cfg->damon_sample_us ? cfg->damon_sample_us : 5000) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), attrs_path, "intervals/aggr_us") != 0 ||
        write_u64_file(path, cfg->damon_aggr_us ? cfg->damon_aggr_us : 100000) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), attrs_path, "intervals/update_us") != 0 ||
        write_u64_file(path, cfg->damon_update_us ? cfg->damon_update_us : 1000000) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), attrs_path, "nr_regions/min") != 0 ||
        write_u64_file(path, cfg->damon_nr_regions_min ? cfg->damon_nr_regions_min : 10) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), attrs_path, "nr_regions/max") != 0 ||
        write_u64_file(path, cfg->damon_nr_regions_max ? cfg->damon_nr_regions_max : 1000) != 0) {
        return -1;
    }

    if (path_join(target_path, sizeof(target_path), ctx_path, "targets") != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), target_path, "nr_targets") != 0 || write_u64_file(path, 1) != 0) {
        return -1;
    }
    {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s", target_path);
        if (snprintf(target_path, sizeof(target_path), "%s/0", tmp) >= (int)sizeof(target_path)) {
            return -1;
        }
    }
    if (path_join(path, sizeof(path), target_path, "pid_target") != 0 || write_u64_file(path, (uint64_t)pid) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), target_path, "regions/nr_regions") != 0 || write_u64_file(path, 1) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), target_path, "regions/0/start") != 0 || write_u64_file(path, region_start) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), target_path, "regions/0/end") != 0 || write_u64_file(path, region_end) != 0) {
        return -1;
    }

    if (path_join(scheme_path, sizeof(scheme_path), ctx_path, "schemes") != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), scheme_path, "nr_schemes") != 0 || write_u64_file(path, 1) != 0) {
        return -1;
    }
    {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s", scheme_path);
        if (snprintf(scheme_path, sizeof(scheme_path), "%s/0", tmp) >= (int)sizeof(scheme_path)) {
            return -1;
        }
    }

    if (path_join(path, sizeof(path), scheme_path, "access_pattern/sz/min") != 0 ||
        write_u64_file(path, 1) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), scheme_path, "access_pattern/sz/max") != 0 ||
        write_u64_file(path, region_end > region_start ? (region_end - region_start) : 1) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), scheme_path, "access_pattern/nr_accesses/min") != 0 ||
        write_u64_file(path, 0) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), scheme_path, "access_pattern/nr_accesses/max") != 0 ||
        write_u64_file(path, UINT32_MAX) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), scheme_path, "access_pattern/age/min") != 0 ||
        write_u64_file(path, 0) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), scheme_path, "access_pattern/age/max") != 0 ||
        write_u64_file(path, UINT32_MAX) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), scheme_path, "action") != 0 || write_text_file(path, "stat") != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), scheme_path, "apply_interval_us") != 0 ||
        write_u64_file(path, cfg->damon_aggr_us ? cfg->damon_aggr_us : 100000) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), scheme_path, "tried_regions") != 0) {
        return -1;
    }
    if (ensure_dir_exists(path) != 0) {
        return -1;
    }

    if (path_join(path, sizeof(path), DAMON_ADMIN_ROOT, "kdamonds/0/state") != 0) {
        return -1;
    }
    if (write_text_file(path, "commit") != 0) {
        return -1;
    }
    if (write_text_file(path, "on") != 0) {
        return -1;
    }

    return 0;
}

int mem_arena_damon_setup(
    struct mem_arena_damon *damon,
    pid_t pid,
    uint64_t region_start,
    uint64_t region_end,
    const struct mem_arena_loops_config *cfg
)
{
    char path[PATH_MAX];
    uint64_t nr_kdamonds = 0;

    if (damon == NULL || cfg == NULL || region_start >= region_end || pid <= 0) {
        return -1;
    }
    memset(damon, 0, sizeof(*damon));

    if (path_join(path, sizeof(path), DAMON_ADMIN_ROOT, "kdamonds/nr_kdamonds") != 0) {
        return -1;
    }
    if (read_u64_file(path, &nr_kdamonds) != 0) {
        return -1;
    }
    if (nr_kdamonds != 0) {
        errno = EBUSY;
        return -1;
    }

    if (configure_single_context_target_region(pid, region_start, region_end, cfg) != 0) {
        mem_arena_damon_stop(damon);
        return -1;
    }

    damon->enabled = 1;
    damon->pid = pid;
    damon->region_start = region_start;
    damon->region_end = region_end;
    damon->last_poll_ns = 0;
    return 0;
}

static int load_one_obs(const char *dir_path, struct mem_arena_damon_region_obs *out_obs)
{
    char path[PATH_MAX];

    if (out_obs == NULL) {
        return -1;
    }
    memset(out_obs, 0, sizeof(*out_obs));

    if (path_join(path, sizeof(path), dir_path, "start") != 0 || read_u64_file(path, &out_obs->start) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), dir_path, "end") != 0 || read_u64_file(path, &out_obs->end) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), dir_path, "nr_accesses") != 0 || read_u64_file(path, &out_obs->nr_accesses) != 0) {
        return -1;
    }
    if (path_join(path, sizeof(path), dir_path, "age") != 0 || read_u64_file(path, &out_obs->age) != 0) {
        return -1;
    }
    return 0;
}

static int list_tried_regions(struct mem_arena_damon_snapshot *out_snapshot)
{
    const char *base = DAMON_ADMIN_ROOT "/kdamonds/0/contexts/0/schemes/0/tried_regions";
    DIR *dir;
    struct dirent *de;
    size_t cap = 0;

    if (out_snapshot == NULL) {
        return -1;
    }
    memset(out_snapshot, 0, sizeof(*out_snapshot));

    if (read_u64_file(DAMON_ADMIN_ROOT "/kdamonds/0/contexts/0/schemes/0/tried_regions/total_bytes",
                      &out_snapshot->total_bytes) != 0) {
        out_snapshot->total_bytes = 0;
    }

    dir = opendir(base);
    if (dir == NULL) {
        return -1;
    }
    while ((de = readdir(dir)) != NULL) {
        char entry_path[PATH_MAX];
        struct mem_arena_damon_region_obs obs;

        if (!is_numeric_name(de->d_name)) {
            continue;
        }
        if (path_join(entry_path, sizeof(entry_path), base, de->d_name) != 0) {
            continue;
        }
        if (load_one_obs(entry_path, &obs) != 0) {
            continue;
        }
        if (out_snapshot->count == cap) {
            size_t new_cap = cap == 0 ? 16 : cap * 2;
            struct mem_arena_damon_region_obs *tmp;

            tmp = realloc(out_snapshot->regions, new_cap * sizeof(*tmp));
            if (tmp == NULL) {
                closedir(dir);
                return -1;
            }
            out_snapshot->regions = tmp;
            cap = new_cap;
        }
        out_snapshot->regions[out_snapshot->count++] = obs;
    }
    closedir(dir);
    return 0;
}

int mem_arena_damon_poll_snapshot(
    struct mem_arena_damon *damon,
    const struct mem_arena_loops_config *cfg,
    uint64_t now_ns,
    struct mem_arena_damon_snapshot *out_snapshot
)
{
    uint64_t min_period_ns;

    if (damon == NULL || cfg == NULL || out_snapshot == NULL || !damon->enabled) {
        return -1;
    }

    min_period_ns = (uint64_t)(cfg->damon_read_tick_ms ? cfg->damon_read_tick_ms : 200) * 1000000ULL;
    if (damon->last_poll_ns != 0 && now_ns < damon->last_poll_ns + min_period_ns) {
        memset(out_snapshot, 0, sizeof(*out_snapshot));
        return 1;
    }
    damon->last_poll_ns = now_ns;

    if (write_text_file(DAMON_ADMIN_ROOT "/kdamonds/0/state", "update_schemes_tried_regions") != 0) {
        return -1;
    }
    if (list_tried_regions(out_snapshot) != 0) {
        return -1;
    }
    if (write_text_file(DAMON_ADMIN_ROOT "/kdamonds/0/state", "clear_schemes_tried_regions") != 0) {
        mem_arena_damon_snapshot_free(out_snapshot);
        return -1;
    }

    return 0;
}

void mem_arena_damon_snapshot_free(struct mem_arena_damon_snapshot *snapshot)
{
    if (snapshot == NULL) {
        return;
    }
    free(snapshot->regions);
    memset(snapshot, 0, sizeof(*snapshot));
}

void mem_arena_damon_stop(struct mem_arena_damon *damon)
{
    if (damon == NULL) {
        return;
    }

    (void)write_text_file(DAMON_ADMIN_ROOT "/kdamonds/0/state", "off");
    (void)write_u64_file(DAMON_ADMIN_ROOT "/kdamonds/nr_kdamonds", 0);
    memset(damon, 0, sizeof(*damon));
}
