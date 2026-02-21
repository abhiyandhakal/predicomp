#define _GNU_SOURCE

#include "mem_arena.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SIZE 4096U
#define DEFAULT_REGION_MB 256
#define DEFAULT_ARENA_MB 128
#define DEFAULT_MIN_SAVINGS_PCT 5
#define DEFAULT_RUNS 5
#define DEFAULT_WARMUPS 2
#define DEFAULT_HOT_FRACTION 100
#define DEFAULT_PARTIAL_REREAD_FRACTION 30
#define DEFAULT_RANDOM_REREAD_FRACTION 20
#define DEFAULT_REUSE_DISTANCE_PAGES 64
#define DEFAULT_IDLE_MS 100
#define DEFAULT_LATENCY_SAMPLE_STEP 1
#define DEFAULT_SEED 0x12345678ABCDEF01ULL
#define MAX_DATASETS 8

enum phase_model {
    PHASE_SINGLE_BULK = 0,
    PHASE_HOT_IDLE_FULL_REREAD = 1,
    PHASE_HOT_IDLE_PARTIAL_RANDOM = 2,
};

struct options {
    int region_mb;
    int arena_mb;
    int min_savings_pct;
    int runs;
    int warmups;
    int hot_fraction;
    int partial_reread_fraction;
    int random_reread_fraction;
    int reuse_distance_pages;
    int idle_ms;
    int latency_sample_step;
    uint64_t seed;
    enum phase_model phase_model;
    char datasets[MAX_DATASETS][32];
    int dataset_count;
    const char *csv_path;
};

struct mem_snapshot {
    uint64_t vmhwm_kb;
    uint64_t rss_kb;
    uint64_t pss_kb;
    uint64_t anon_kb;
    uint64_t file_kb;
    int smaps_ok;
};

struct clocks {
    struct timespec wall;
    struct timespec thread_cpu;
    struct timespec process_cpu;
};

struct latency_collector {
    uint64_t *vals;
    size_t count;
    size_t cap;
};

struct latency_stats {
    uint64_t samples;
    uint64_t min_ns;
    uint64_t p50_ns;
    uint64_t p95_ns;
    uint64_t p99_ns;
    uint64_t max_ns;
    double avg_ns;
};

struct fault_counts {
    uint64_t minflt;
    uint64_t majflt;
};

struct sample {
    int run_id;
    int warmup;
    struct mem_snapshot pre_comp;
    struct mem_snapshot post_comp;
    struct mem_snapshot post_idle;
    struct mem_snapshot post_partial;
    struct mem_snapshot post_random;
    struct mem_snapshot post_final;
    double compress_wall_ms;
    double compress_thread_cpu_ms;
    double compress_proc_cpu_ms;
    double decompress_wall_ms;
    double decompress_thread_cpu_ms;
    double decompress_proc_cpu_ms;
    uint64_t compressed_bytes_post_compress;
    uint64_t slot_bytes_post_compress;
    uint64_t readback_touches_total;
    uint64_t readback_touches_sampled;
    uint64_t readback_fault_like_events;
    uint64_t stall_events_total;
    uint64_t stall_events_sampled;
    uint64_t minflt_delta;
    uint64_t majflt_delta;
    struct latency_stats partial_latency;
    struct latency_stats random_latency;
    struct latency_stats combined_latency;
    struct latency_stats stall_latency;
    struct mem_arena_stats arena_stats_post_comp;
    struct mem_arena_stats arena_stats;
};

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [--dataset repetitive|unique|mixed_50_50|list] [--region-mb N] [--arena-cap-mb N] "
            "[--min-savings-pct N] [--runs N] [--warmups N] [--csv path] "
            "[--phase-model hot-idle-partial-random|hot-idle-full-reread|single-bulk] "
            "[--hot-fraction N] [--partial-reread-fraction N] [--random-reread-fraction N] "
            "[--reuse-distance-pages N] [--idle-ms N] [--latency-sample-step N] [--seed N]\n",
            prog);
}

static const char *phase_model_name(enum phase_model model)
{
    if (model == PHASE_SINGLE_BULK) {
        return "single-bulk";
    }
    if (model == PHASE_HOT_IDLE_FULL_REREAD) {
        return "hot-idle-full-reread";
    }
    return "hot-idle-partial-random";
}

static int parse_phase_model(const char *value, enum phase_model *out)
{
    if (strcmp(value, "single-bulk") == 0) {
        *out = PHASE_SINGLE_BULK;
        return 0;
    }
    if (strcmp(value, "hot-idle-full-reread") == 0) {
        *out = PHASE_HOT_IDLE_FULL_REREAD;
        return 0;
    }
    if (strcmp(value, "hot-idle-partial-random") == 0) {
        *out = PHASE_HOT_IDLE_PARTIAL_RANDOM;
        return 0;
    }
    return -1;
}

static int parse_pos_int(const char *name, const char *value, int min_v, int max_v)
{
    char *end = NULL;
    long v = strtol(value, &end, 10);

    if (end == value || *end != '\0' || v < min_v || v > max_v) {
        fprintf(stderr, "invalid %s: %s\n", name, value);
        exit(2);
    }
    return (int)v;
}

static uint64_t parse_u64(const char *name, const char *value)
{
    char *end = NULL;
    unsigned long long v = strtoull(value, &end, 10);

    if (end == value || *end != '\0') {
        fprintf(stderr, "invalid %s: %s\n", name, value);
        exit(2);
    }
    return (uint64_t)v;
}

static int is_valid_dataset(const char *name)
{
    return strcmp(name, "repetitive") == 0 || strcmp(name, "unique") == 0 || strcmp(name, "mixed_50_50") == 0;
}

static int add_dataset(struct options *opts, const char *name)
{
    int i;

    if (!is_valid_dataset(name)) {
        return -1;
    }
    for (i = 0; i < opts->dataset_count; i++) {
        if (strcmp(opts->datasets[i], name) == 0) {
            return 0;
        }
    }
    if (opts->dataset_count >= MAX_DATASETS) {
        return -1;
    }

    snprintf(opts->datasets[opts->dataset_count], sizeof(opts->datasets[0]), "%s", name);
    opts->dataset_count++;
    return 0;
}

static int add_dataset_arg(struct options *opts, const char *value)
{
    char *tmp;
    char *src;
    char *dst;
    char *tok;

    tmp = strdup(value);
    if (tmp == NULL) {
        return -1;
    }

    src = tmp;
    dst = tmp;
    while (*src != '\0') {
        if (*src != '{' && *src != '}' && *src != ' ') {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';

    tok = strtok(tmp, ",");
    while (tok != NULL) {
        if (*tok != '\0' && add_dataset(opts, tok) != 0) {
            free(tmp);
            return -1;
        }
        tok = strtok(NULL, ",");
    }

    free(tmp);
    return 0;
}

static int parse_options(int argc, char **argv, struct options *opts)
{
    int i;

    opts->region_mb = DEFAULT_REGION_MB;
    opts->arena_mb = DEFAULT_ARENA_MB;
    opts->min_savings_pct = DEFAULT_MIN_SAVINGS_PCT;
    opts->runs = DEFAULT_RUNS;
    opts->warmups = DEFAULT_WARMUPS;
    opts->hot_fraction = DEFAULT_HOT_FRACTION;
    opts->partial_reread_fraction = DEFAULT_PARTIAL_REREAD_FRACTION;
    opts->random_reread_fraction = DEFAULT_RANDOM_REREAD_FRACTION;
    opts->reuse_distance_pages = DEFAULT_REUSE_DISTANCE_PAGES;
    opts->idle_ms = DEFAULT_IDLE_MS;
    opts->latency_sample_step = DEFAULT_LATENCY_SAMPLE_STEP;
    opts->seed = DEFAULT_SEED;
    opts->phase_model = PHASE_HOT_IDLE_PARTIAL_RANDOM;
    opts->dataset_count = 0;
    snprintf(opts->datasets[opts->dataset_count], sizeof(opts->datasets[0]), "%s", "repetitive");
    opts->dataset_count++;
    opts->csv_path = "mem-arena/process_mem_bench.csv";

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dataset") == 0 && i + 1 < argc) {
            int consumed = 0;
            opts->dataset_count = 0;
            while (i + 1 < argc && argv[i + 1][0] != '-') {
                if (add_dataset_arg(opts, argv[++i]) != 0) {
                    return -1;
                }
                consumed = 1;
            }
            if (!consumed || opts->dataset_count == 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--region-mb") == 0 && i + 1 < argc) {
            opts->region_mb = parse_pos_int("region-mb", argv[++i], 1, 65536);
        } else if (strcmp(argv[i], "--arena-cap-mb") == 0 && i + 1 < argc) {
            opts->arena_mb = parse_pos_int("arena-cap-mb", argv[++i], 1, 65536);
        } else if (strcmp(argv[i], "--min-savings-pct") == 0 && i + 1 < argc) {
            opts->min_savings_pct = parse_pos_int("min-savings-pct", argv[++i], 0, 95);
        } else if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc) {
            opts->runs = parse_pos_int("runs", argv[++i], 1, 1000);
        } else if (strcmp(argv[i], "--warmups") == 0 && i + 1 < argc) {
            opts->warmups = parse_pos_int("warmups", argv[++i], 0, 1000);
        } else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            opts->csv_path = argv[++i];
        } else if (strcmp(argv[i], "--phase-model") == 0 && i + 1 < argc) {
            if (parse_phase_model(argv[++i], &opts->phase_model) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--hot-fraction") == 0 && i + 1 < argc) {
            opts->hot_fraction = parse_pos_int("hot-fraction", argv[++i], 0, 100);
        } else if (strcmp(argv[i], "--partial-reread-fraction") == 0 && i + 1 < argc) {
            opts->partial_reread_fraction = parse_pos_int("partial-reread-fraction", argv[++i], 0, 100);
        } else if (strcmp(argv[i], "--random-reread-fraction") == 0 && i + 1 < argc) {
            opts->random_reread_fraction = parse_pos_int("random-reread-fraction", argv[++i], 0, 100);
        } else if (strcmp(argv[i], "--reuse-distance-pages") == 0 && i + 1 < argc) {
            opts->reuse_distance_pages = parse_pos_int("reuse-distance-pages", argv[++i], 1, 1000000);
        } else if (strcmp(argv[i], "--idle-ms") == 0 && i + 1 < argc) {
            opts->idle_ms = parse_pos_int("idle-ms", argv[++i], 0, 600000);
        } else if (strcmp(argv[i], "--latency-sample-step") == 0 && i + 1 < argc) {
            opts->latency_sample_step = parse_pos_int("latency-sample-step", argv[++i], 1, 1000000);
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            opts->seed = parse_u64("seed", argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            exit(0);
        } else {
            return -1;
        }
    }

    if (opts->dataset_count <= 0) {
        return -1;
    }
    return 0;
}

static uint64_t xorshift64(uint64_t *state)
{
    uint64_t x = *state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void fill_dataset(unsigned char *buf, size_t len, const char *dataset)
{
    size_t i;

    if (strcmp(dataset, "repetitive") == 0) {
        memset(buf, 0x5A, len);
        return;
    }

    if (strcmp(dataset, "unique") == 0) {
        uint64_t state = 0x123456789ULL;
        unsigned int b = 0;

        for (i = 0; i < len; i++) {
            if (b == 0) {
                (void)xorshift64(&state);
            }
            buf[i] = (unsigned char)((state >> (8U * b)) & 0xFFU);
            b = (b + 1U) & 7U;
        }
        return;
    }

    for (i = 0; i < len; i += PAGE_SIZE) {
        size_t j;
        size_t end = i + PAGE_SIZE;

        if (end > len) {
            end = len;
        }

        if (((i / PAGE_SIZE) % 2U) == 0U) {
            memset(buf + i, 0x33, end - i);
        } else {
            uint64_t state = (uint64_t)(i + 1U) * 0x9E3779B97F4A7C15ULL;
            unsigned int b = 0;

            for (j = i; j < end; j++) {
                if (b == 0) {
                    (void)xorshift64(&state);
                }
                buf[j] = (unsigned char)((state >> (8U * b)) & 0xFFU);
                b = (b + 1U) & 7U;
            }
        }
    }
}

static int read_status_kb(const char *key, uint64_t *out_kb)
{
    FILE *fp = fopen("/proc/self/status", "r");
    char line[256];
    size_t key_len = strlen(key);

    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long v = 0;

        if (strncmp(line, key, key_len) == 0 && sscanf(line + key_len, "%llu", &v) == 1) {
            fclose(fp);
            *out_kb = (uint64_t)v;
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

static int read_smaps_rollup(struct mem_snapshot *snap)
{
    FILE *fp;
    char line[256];

    snap->rss_kb = 0;
    snap->pss_kb = 0;
    snap->anon_kb = 0;
    snap->file_kb = 0;
    snap->smaps_ok = 0;

    fp = fopen("/proc/self/smaps_rollup", "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned long long v = 0;

        if (sscanf(line, "Rss: %llu kB", &v) == 1) {
            snap->rss_kb = (uint64_t)v;
            continue;
        }
        if (sscanf(line, "Pss: %llu kB", &v) == 1) {
            snap->pss_kb = (uint64_t)v;
            continue;
        }
        if (sscanf(line, "Anonymous: %llu kB", &v) == 1) {
            snap->anon_kb = (uint64_t)v;
            continue;
        }
        if (sscanf(line, "File: %llu kB", &v) == 1) {
            snap->file_kb = (uint64_t)v;
            continue;
        }
    }

    fclose(fp);
    snap->smaps_ok = 1;
    return 0;
}

static int capture_mem_snapshot(struct mem_snapshot *snap)
{
    if (read_status_kb("VmHWM:", &snap->vmhwm_kb) != 0) {
        snap->vmhwm_kb = 0;
    }

    if (read_smaps_rollup(snap) != 0) {
        snap->smaps_ok = 0;
    }

    return 0;
}

static int read_fault_counts(struct fault_counts *out)
{
    FILE *fp;
    char line[4096];
    char *rp;
    char *ctx;
    char *tok;
    int field = 3;
    uint64_t minflt = 0;
    uint64_t majflt = 0;
    int have_minflt = 0;
    int have_majflt = 0;

    fp = fopen("/proc/self/stat", "r");
    if (fp == NULL) {
        return -1;
    }
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    rp = strrchr(line, ')');
    if (rp == NULL || rp[1] != ' ') {
        return -1;
    }

    tok = strtok_r(rp + 2, " ", &ctx);
    while (tok != NULL) {
        if (field == 10) {
            minflt = strtoull(tok, NULL, 10);
            have_minflt = 1;
        } else if (field == 12) {
            majflt = strtoull(tok, NULL, 10);
            have_majflt = 1;
        }
        if (have_minflt && have_majflt) {
            out->minflt = minflt;
            out->majflt = majflt;
            return 0;
        }
        field++;
        tok = strtok_r(NULL, " ", &ctx);
    }

    return -1;
}

static int snap_clocks(struct clocks *c)
{
    if (clock_gettime(CLOCK_MONOTONIC, &c->wall) != 0) {
        return -1;
    }
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &c->thread_cpu) != 0) {
        return -1;
    }
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c->process_cpu) != 0) {
        return -1;
    }
    return 0;
}

static double msdiff(const struct timespec *a, const struct timespec *b)
{
    double sec = (double)(b->tv_sec - a->tv_sec);
    double nsec = (double)(b->tv_nsec - a->tv_nsec);

    return sec * 1000.0 + nsec / 1000000.0;
}

static uint64_t nsdiff(const struct timespec *a, const struct timespec *b)
{
    uint64_t sec = (uint64_t)(b->tv_sec - a->tv_sec);
    int64_t nsec = (int64_t)b->tv_nsec - (int64_t)a->tv_nsec;

    if (nsec < 0) {
        sec -= 1U;
        nsec += 1000000000LL;
    }
    return sec * 1000000000ULL + (uint64_t)nsec;
}

static void lc_init(struct latency_collector *lc)
{
    lc->vals = NULL;
    lc->count = 0;
    lc->cap = 0;
}

static void lc_free(struct latency_collector *lc)
{
    free(lc->vals);
    lc->vals = NULL;
    lc->count = 0;
    lc->cap = 0;
}

static int lc_push(struct latency_collector *lc, uint64_t ns)
{
    uint64_t *next;
    size_t next_cap;

    if (lc->count == lc->cap) {
        next_cap = (lc->cap == 0) ? 1024U : lc->cap * 2U;
        next = realloc(lc->vals, next_cap * sizeof(*next));
        if (next == NULL) {
            return -1;
        }
        lc->vals = next;
        lc->cap = next_cap;
    }

    lc->vals[lc->count++] = ns;
    return 0;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;

    if (va < vb) {
        return -1;
    }
    if (va > vb) {
        return 1;
    }
    return 0;
}

static uint64_t percentile_u64(const uint64_t *vals, size_t n, int pct)
{
    size_t idx;

    if (n == 0) {
        return 0;
    }
    if (pct <= 0) {
        return vals[0];
    }
    if (pct >= 100) {
        return vals[n - 1];
    }

    idx = (size_t)(((uint64_t)(n - 1) * (uint64_t)pct + 99U) / 100U);
    if (idx >= n) {
        idx = n - 1;
    }
    return vals[idx];
}

static int finalize_latency(const struct latency_collector *lc, struct latency_stats *out)
{
    uint64_t *tmp;
    size_t i;
    long double sum = 0.0;

    memset(out, 0, sizeof(*out));
    if (lc->count == 0) {
        return 0;
    }

    tmp = malloc(lc->count * sizeof(*tmp));
    if (tmp == NULL) {
        return -1;
    }

    memcpy(tmp, lc->vals, lc->count * sizeof(*tmp));
    qsort(tmp, lc->count, sizeof(*tmp), cmp_u64);

    out->samples = (uint64_t)lc->count;
    out->min_ns = tmp[0];
    out->max_ns = tmp[lc->count - 1];
    out->p50_ns = percentile_u64(tmp, lc->count, 50);
    out->p95_ns = percentile_u64(tmp, lc->count, 95);
    out->p99_ns = percentile_u64(tmp, lc->count, 99);

    for (i = 0; i < lc->count; i++) {
        sum += (long double)lc->vals[i];
    }
    out->avg_ns = (double)(sum / (long double)lc->count);

    free(tmp);
    return 0;
}

static int timed_touch(
    struct mem_arena *arena,
    int region_id,
    size_t offset,
    int op_kind,
    uint64_t *touch_idx,
    int sample_step,
    uint64_t *out_ns,
    int *out_sampled,
    int *out_stall
)
{
    int rc;
    int sample_now;
    struct mem_arena_stats before_stats;
    struct mem_arena_stats after_stats;

    if (mem_arena_get_stats(arena, &before_stats) != 0) {
        return -1;
    }

    sample_now = ((*touch_idx % (uint64_t)sample_step) == 0U);

    if (sample_now) {
        struct timespec t0;
        struct timespec t1;

        if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0) {
            return -1;
        }
        rc = mem_arena_touch(arena, region_id, offset, op_kind);
        if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
            return -1;
        }
        if (rc != 0) {
            return -1;
        }
        *out_ns = nsdiff(&t0, &t1);
    } else {
        if (mem_arena_touch(arena, region_id, offset, op_kind) != 0) {
            return -1;
        }
        *out_ns = 0;
    }

    if (mem_arena_get_stats(arena, &after_stats) != 0) {
        return -1;
    }

    *out_sampled = sample_now;
    *out_stall = (after_stats.decompress_ops > before_stats.decompress_ops) ? 1 : 0;
    (*touch_idx)++;
    return 0;
}

static size_t pct_pages(size_t total_pages, int pct)
{
    size_t v;

    if (pct <= 0) {
        return 0;
    }
    if (pct >= 100) {
        return total_pages;
    }

    v = (size_t)(((uint64_t)total_pages * (uint64_t)pct) / 100ULL);
    if (v == 0 && total_pages > 0) {
        v = 1;
    }
    if (v > total_pages) {
        v = total_pages;
    }
    return v;
}

static int run_one(const struct options *opts, const char *dataset, int run_id, int warmup, struct sample *s)
{
    struct mem_arena_config cfg;
    struct mem_arena *arena = NULL;
    int region_id = -1;
    unsigned char *raw = NULL;
    size_t len = (size_t)opts->region_mb * 1024UL * 1024UL;
    size_t total_pages = len / PAGE_SIZE;
    size_t hot_pages;
    size_t partial_pages;
    size_t random_touches;
    size_t i;
    struct clocks c0;
    struct clocks c1;
    struct clocks d0;
    struct clocks d1;
    struct mem_arena_stats after_comp;
    struct mem_arena_stats before_readback;
    struct mem_arena_stats after_readback;
    struct latency_collector partial_lc;
    struct latency_collector random_lc;
    struct latency_collector combined_lc;
    struct latency_collector stall_lc;
    struct fault_counts faults_before;
    struct fault_counts faults_after;
    uint64_t touch_idx = 0;
    uint64_t seed;

    memset(s, 0, sizeof(*s));
    s->run_id = run_id;
    s->warmup = warmup;

    lc_init(&partial_lc);
    lc_init(&random_lc);
    lc_init(&combined_lc);
    lc_init(&stall_lc);

    cfg.arena_capacity_bytes = (size_t)opts->arena_mb * 1024UL * 1024UL;
    cfg.chunk_size = PAGE_SIZE;
    cfg.min_savings_percent = opts->min_savings_pct;
    cfg.lz4_acceleration = 1;

    arena = mem_arena_create(&cfg);
    if (arena == NULL) {
        goto fail;
    }
    if (mem_arena_region_alloc(arena, len, "bench-region", &region_id, &raw) != 0) {
        goto fail;
    }

    fill_dataset(raw, len, dataset);

    hot_pages = pct_pages(total_pages, opts->hot_fraction);
    for (i = 0; i < hot_pages; i++) {
        size_t off = i * PAGE_SIZE;
        if (mem_arena_touch(arena, region_id, off, MEM_ARENA_OP_XOR1) != 0) {
            goto fail;
        }
    }

    if (capture_mem_snapshot(&s->pre_comp) != 0) {
        goto fail;
    }

    if (snap_clocks(&c0) != 0 || mem_arena_compress_region(arena, region_id) != 0 || snap_clocks(&c1) != 0) {
        goto fail;
    }
    if (capture_mem_snapshot(&s->post_comp) != 0) {
        goto fail;
    }
    if (mem_arena_get_stats(arena, &after_comp) != 0) {
        goto fail;
    }
    s->compressed_bytes_post_compress = after_comp.compressed_bytes_live;
    s->slot_bytes_post_compress = after_comp.slot_bytes_live;
    s->arena_stats_post_comp = after_comp;

    s->compress_wall_ms = msdiff(&c0.wall, &c1.wall);
    s->compress_thread_cpu_ms = msdiff(&c0.thread_cpu, &c1.thread_cpu);
    s->compress_proc_cpu_ms = msdiff(&c0.process_cpu, &c1.process_cpu);

    if (opts->idle_ms > 0) {
        struct timespec ts;

        ts.tv_sec = opts->idle_ms / 1000;
        ts.tv_nsec = (opts->idle_ms % 1000) * 1000000L;
        (void)nanosleep(&ts, NULL);
    }
    if (capture_mem_snapshot(&s->post_idle) != 0) {
        goto fail;
    }

    if (mem_arena_get_stats(arena, &before_readback) != 0) {
        goto fail;
    }

    if (snap_clocks(&d0) != 0) {
        goto fail;
    }
    if (read_fault_counts(&faults_before) != 0) {
        goto fail;
    }

    if (opts->phase_model == PHASE_SINGLE_BULK || opts->phase_model == PHASE_HOT_IDLE_FULL_REREAD) {
        for (i = 0; i < total_pages; i++) {
            size_t off = i * PAGE_SIZE;
            uint64_t latency_ns = 0;
            int sampled = 0;
            int stall = 0;
            if (timed_touch(arena,
                            region_id,
                            off,
                            MEM_ARENA_OP_XOR1,
                            &touch_idx,
                            opts->latency_sample_step,
                            &latency_ns,
                            &sampled,
                            &stall) != 0) {
                goto fail;
            }
            if (sampled) {
                if (lc_push(&combined_lc, latency_ns) != 0 || lc_push(&partial_lc, latency_ns) != 0) {
                    goto fail;
                }
                s->readback_touches_sampled++;
            }
            if (stall) {
                s->stall_events_total++;
                if (sampled) {
                    if (lc_push(&stall_lc, latency_ns) != 0) {
                        goto fail;
                    }
                    s->stall_events_sampled++;
                }
            }
            s->readback_touches_total++;
        }
        s->post_partial = s->post_idle;
        if (capture_mem_snapshot(&s->post_partial) != 0) {
            goto fail;
        }
        s->post_random = s->post_partial;
    } else {
        partial_pages = pct_pages(total_pages, opts->partial_reread_fraction);
        random_touches = pct_pages(total_pages, opts->random_reread_fraction);

        for (i = 0; i < partial_pages; i++) {
            size_t off = i * PAGE_SIZE;
            uint64_t latency_ns = 0;
            int sampled = 0;
            int stall = 0;
            if (timed_touch(arena,
                            region_id,
                            off,
                            MEM_ARENA_OP_XOR1,
                            &touch_idx,
                            opts->latency_sample_step,
                            &latency_ns,
                            &sampled,
                            &stall) != 0) {
                goto fail;
            }
            if (sampled) {
                if (lc_push(&combined_lc, latency_ns) != 0 || lc_push(&partial_lc, latency_ns) != 0) {
                    goto fail;
                }
                s->readback_touches_sampled++;
            }
            if (stall) {
                s->stall_events_total++;
                if (sampled) {
                    if (lc_push(&stall_lc, latency_ns) != 0) {
                        goto fail;
                    }
                    s->stall_events_sampled++;
                }
            }
            s->readback_touches_total++;
        }

        if (capture_mem_snapshot(&s->post_partial) != 0) {
            goto fail;
        }

        seed = opts->seed ^ (uint64_t)run_id;
        for (i = 0; i < random_touches; i++) {
            size_t page_idx;
            size_t off;
            uint64_t latency_ns = 0;
            uint64_t r = xorshift64(&seed);
            uint64_t dist = (uint64_t)opts->reuse_distance_pages;
            int sampled = 0;
            int stall = 0;

            page_idx = (size_t)(r % (uint64_t)total_pages);
            if (dist > 0 && total_pages > 0) {
                int64_t delta = (int64_t)(xorshift64(&seed) % (2ULL * dist + 1ULL)) - (int64_t)dist;
                int64_t adjusted = (int64_t)page_idx + delta;
                while (adjusted < 0) {
                    adjusted += (int64_t)total_pages;
                }
                page_idx = (size_t)((uint64_t)adjusted % (uint64_t)total_pages);
            }
            off = page_idx * PAGE_SIZE;

            if (timed_touch(arena,
                            region_id,
                            off,
                            MEM_ARENA_OP_XOR1,
                            &touch_idx,
                            opts->latency_sample_step,
                            &latency_ns,
                            &sampled,
                            &stall) != 0) {
                goto fail;
            }
            if (sampled) {
                if (lc_push(&combined_lc, latency_ns) != 0 || lc_push(&random_lc, latency_ns) != 0) {
                    goto fail;
                }
                s->readback_touches_sampled++;
            }
            if (stall) {
                s->stall_events_total++;
                if (sampled) {
                    if (lc_push(&stall_lc, latency_ns) != 0) {
                        goto fail;
                    }
                    s->stall_events_sampled++;
                }
            }
            s->readback_touches_total++;
        }

        if (capture_mem_snapshot(&s->post_random) != 0) {
            goto fail;
        }
    }

    if (snap_clocks(&d1) != 0) {
        goto fail;
    }
    if (read_fault_counts(&faults_after) != 0) {
        goto fail;
    }

    s->decompress_wall_ms = msdiff(&d0.wall, &d1.wall);
    s->decompress_thread_cpu_ms = msdiff(&d0.thread_cpu, &d1.thread_cpu);
    s->decompress_proc_cpu_ms = msdiff(&d0.process_cpu, &d1.process_cpu);
    if (faults_after.minflt >= faults_before.minflt) {
        s->minflt_delta = faults_after.minflt - faults_before.minflt;
    }
    if (faults_after.majflt >= faults_before.majflt) {
        s->majflt_delta = faults_after.majflt - faults_before.majflt;
    }

    if (capture_mem_snapshot(&s->post_final) != 0) {
        goto fail;
    }

    if (mem_arena_get_stats(arena, &after_readback) != 0) {
        goto fail;
    }
    s->arena_stats = after_readback;
    if (after_readback.access_hits_decompressed >= before_readback.access_hits_decompressed) {
        s->readback_fault_like_events =
            after_readback.access_hits_decompressed - before_readback.access_hits_decompressed;
    }

    if (finalize_latency(&partial_lc, &s->partial_latency) != 0 ||
        finalize_latency(&random_lc, &s->random_latency) != 0 ||
        finalize_latency(&combined_lc, &s->combined_latency) != 0 ||
        finalize_latency(&stall_lc, &s->stall_latency) != 0) {
        goto fail;
    }

    lc_free(&partial_lc);
    lc_free(&random_lc);
    lc_free(&combined_lc);
    lc_free(&stall_lc);
    mem_arena_destroy(arena);
    return 0;

fail:
    lc_free(&partial_lc);
    lc_free(&random_lc);
    lc_free(&combined_lc);
    lc_free(&stall_lc);
    if (arena != NULL) {
        mem_arena_destroy(arena);
    }
    return -1;
}

static int write_csv_header(FILE *fp)
{
    return fprintf(fp,
                   "dataset,run,warmup,pid,phase_model,region_mb,arena_cap_mb,min_savings_pct,"
                   "hot_fraction,partial_reread_fraction,random_reread_fraction,reuse_distance_pages,idle_ms,"
                   "latency_sample_step,"
                   "vmhwm_post_final_kb,"
                   "pss_pre_kb,pss_post_comp_kb,pss_post_idle_kb,pss_post_partial_kb,pss_post_random_kb,pss_post_final_kb,"
                   "rss_pre_kb,rss_post_comp_kb,rss_post_idle_kb,rss_post_partial_kb,rss_post_random_kb,rss_post_final_kb,"
                   "anon_pre_kb,anon_post_comp_kb,anon_post_idle_kb,anon_post_partial_kb,anon_post_random_kb,anon_post_final_kb,"
                   "file_pre_kb,file_post_comp_kb,file_post_idle_kb,file_post_partial_kb,file_post_random_kb,file_post_final_kb,"
                   "rss_delta_comp_kb,rss_delta_final_kb,"
                   "compress_wall_ms,compress_thread_cpu_ms,compress_process_cpu_ms,"
                   "decompress_wall_ms,decompress_thread_cpu_ms,decompress_process_cpu_ms,"
                   "partial_samples,partial_p50_ns,partial_p95_ns,partial_p99_ns,partial_max_ns,"
                   "random_samples,random_p50_ns,random_p95_ns,random_p99_ns,random_max_ns,"
                   "touch_samples,touch_p50_ns,touch_p95_ns,touch_p99_ns,touch_max_ns,"
                   "stall_samples,stall_p50_ns,stall_p95_ns,stall_p99_ns,stall_max_ns,"
                   "readback_touches_total,readback_touches_sampled,readback_fault_like_events,"
                   "stall_events_total,stall_events_sampled,minflt_delta,majflt_delta,"
                   "compressed_bytes_post_compress,slot_bytes_post_compress,"
                   "logical_input_bytes,compressed_bytes_live,slot_bytes_live,compress_ops,decompress_ops,evictions_lru,"
                   "incompressible_chunks,access_hits_raw,access_hits_decompressed,compression_reject_small_gain\n") < 0
               ? -1
               : 0;
}

static int append_csv_row(FILE *fp, const struct options *opts, const char *dataset, const struct sample *s)
{
    long long rss_delta_comp = (long long)s->pre_comp.rss_kb - (long long)s->post_comp.rss_kb;
    long long rss_delta_final = (long long)s->pre_comp.rss_kb - (long long)s->post_final.rss_kb;

    if (fprintf(fp,
                "%s,%d,%d,%d,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,",
                dataset,
                s->run_id,
                s->warmup,
                (int)getpid(),
                phase_model_name(opts->phase_model),
                opts->region_mb,
                opts->arena_mb,
                opts->min_savings_pct,
                opts->hot_fraction,
                opts->partial_reread_fraction,
                opts->random_reread_fraction,
                opts->reuse_distance_pages,
                opts->idle_ms,
                opts->latency_sample_step) < 0) {
        return -1;
    }
    if (fprintf(fp,
                "%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",",
                s->post_final.vmhwm_kb,
                s->pre_comp.pss_kb,
                s->post_comp.pss_kb,
                s->post_idle.pss_kb,
                s->post_partial.pss_kb,
                s->post_random.pss_kb,
                s->post_final.pss_kb,
                s->pre_comp.rss_kb,
                s->post_comp.rss_kb,
                s->post_idle.rss_kb,
                s->post_partial.rss_kb,
                s->post_random.rss_kb,
                s->post_final.rss_kb,
                s->pre_comp.anon_kb,
                s->post_comp.anon_kb,
                s->post_idle.anon_kb,
                s->post_partial.anon_kb,
                s->post_random.anon_kb,
                s->post_final.anon_kb,
                s->pre_comp.file_kb,
                s->post_comp.file_kb,
                s->post_idle.file_kb,
                s->post_partial.file_kb,
                s->post_random.file_kb,
                s->post_final.file_kb) < 0) {
        return -1;
    }
    if (fprintf(fp,
                "%lld,%lld,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,",
                rss_delta_comp,
                rss_delta_final,
                s->compress_wall_ms,
                s->compress_thread_cpu_ms,
                s->compress_proc_cpu_ms,
                s->decompress_wall_ms,
                s->decompress_thread_cpu_ms,
                s->decompress_proc_cpu_ms) < 0) {
        return -1;
    }
    if (fprintf(fp,
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",",
                s->partial_latency.samples,
                s->partial_latency.p50_ns,
                s->partial_latency.p95_ns,
                s->partial_latency.p99_ns,
                s->partial_latency.max_ns,
                s->random_latency.samples,
                s->random_latency.p50_ns,
                s->random_latency.p95_ns,
                s->random_latency.p99_ns,
                s->random_latency.max_ns,
                s->combined_latency.samples,
                s->combined_latency.p50_ns,
                s->combined_latency.p95_ns,
                s->combined_latency.p99_ns,
                s->combined_latency.max_ns,
                s->stall_latency.samples,
                s->stall_latency.p50_ns,
                s->stall_latency.p95_ns,
                s->stall_latency.p99_ns,
                s->stall_latency.max_ns) < 0) {
        return -1;
    }
    if (fprintf(fp,
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",",
                s->readback_touches_total,
                s->readback_touches_sampled,
                s->readback_fault_like_events,
                s->stall_events_total,
                s->stall_events_sampled,
                s->minflt_delta,
                s->majflt_delta,
                s->compressed_bytes_post_compress,
                s->slot_bytes_post_compress) < 0) {
        return -1;
    }
    if (fprintf(fp,
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                s->arena_stats.logical_input_bytes,
                s->arena_stats.compressed_bytes_live,
                s->arena_stats.slot_bytes_live,
                s->arena_stats.compress_ops,
                s->arena_stats.decompress_ops,
                s->arena_stats.evictions_lru,
                s->arena_stats.incompressible_chunks,
                s->arena_stats.access_hits_raw,
                s->arena_stats.access_hits_decompressed,
                s->arena_stats.compression_reject_small_gain) < 0) {
        return -1;
    }
    return 0;
}

static void print_header(void)
{
    printf("dataset      run warm phase_model               rss_pre_kb rss_post_comp_kb rss_post_final_kb ");
    printf("comp_cpu_ms decomp_cpu_ms touch_p99_ns stall_p99_ns stall_events minflt majflt incompressible\n");
    printf("------------ --- ---- ------------------------- ------------ ------------------ ------------------- ");
    printf("----------- ------------- ------------ ----------- ------------ ------ ------ ------------\n");
}

static void print_row(const char *dataset, const struct sample *s, const struct options *opts)
{
    printf("%-12s %3d %4d %-25s %12" PRIu64 " %18" PRIu64 " %19" PRIu64 " %11.3f %13.3f %12" PRIu64
           " %11" PRIu64 " %12" PRIu64 " %6" PRIu64 " %6" PRIu64 " %12" PRIu64 "\n",
           dataset,
           s->run_id,
           s->warmup,
           phase_model_name(opts->phase_model),
           s->pre_comp.rss_kb,
           s->post_comp.rss_kb,
           s->post_final.rss_kb,
           s->compress_thread_cpu_ms,
           s->decompress_thread_cpu_ms,
           s->combined_latency.p99_ns,
           s->stall_latency.p99_ns,
           s->stall_events_total,
           s->minflt_delta,
           s->majflt_delta,
           s->arena_stats.incompressible_chunks);
}

int main(int argc, char **argv)
{
    struct options opts;
    int d;
    int i;
    int total_runs;
    FILE *csv = NULL;

    if (parse_options(argc, argv, &opts) != 0) {
        usage(argv[0]);
        return 2;
    }

    csv = fopen(opts.csv_path, "w");
    if (csv == NULL) {
        fprintf(stderr, "failed to open CSV %s: %s\n", opts.csv_path, strerror(errno));
        return 1;
    }
    if (write_csv_header(csv) != 0) {
        fclose(csv);
        return 1;
    }

    print_header();
    total_runs = opts.warmups + opts.runs;
    for (d = 0; d < opts.dataset_count; d++) {
        const char *dataset = opts.datasets[d];

        for (i = 0; i < total_runs; i++) {
            struct sample s;
            int warmup = (i < opts.warmups) ? 1 : 0;

            if (run_one(&opts, dataset, i + 1, warmup, &s) != 0) {
                fprintf(stderr, "run failed dataset=%s iteration=%d\n", dataset, i + 1);
                fclose(csv);
                return 1;
            }
            print_row(dataset, &s, &opts);
            if (append_csv_row(csv, &opts, dataset, &s) != 0) {
                fprintf(stderr, "failed to append CSV row\n");
                fclose(csv);
                return 1;
            }
        }
    }

    fclose(csv);
    printf("csv_written=%s\n", opts.csv_path);
    return 0;
}
