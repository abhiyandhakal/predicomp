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

struct options {
    int region_mb;
    int arena_mb;
    int min_savings_pct;
    int runs;
    int warmups;
    const char *dataset;
    const char *csv_path;
};

struct sample {
    int run_id;
    int warmup;
    uint64_t rss_pre_kb;
    uint64_t rss_post_compress_kb;
    uint64_t rss_post_readback_kb;
    uint64_t hwm_kb;
    double compress_wall_ms;
    double compress_thread_cpu_ms;
    double compress_proc_cpu_ms;
    double decompress_wall_ms;
    double decompress_thread_cpu_ms;
    double decompress_proc_cpu_ms;
    uint64_t compressed_bytes_post_compress;
    uint64_t slot_bytes_post_compress;
    struct mem_arena_stats arena_stats;
};

struct clocks {
    struct timespec wall;
    struct timespec thread_cpu;
    struct timespec process_cpu;
};

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [--dataset repetitive|unique|mixed_50_50] [--region-mb N] [--arena-cap-mb N] "
            "[--min-savings-pct N] [--runs N] [--warmups N] [--csv path]\n",
            prog);
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

static int parse_options(int argc, char **argv, struct options *opts)
{
    int i;

    opts->region_mb = DEFAULT_REGION_MB;
    opts->arena_mb = DEFAULT_ARENA_MB;
    opts->min_savings_pct = DEFAULT_MIN_SAVINGS_PCT;
    opts->runs = DEFAULT_RUNS;
    opts->warmups = DEFAULT_WARMUPS;
    opts->dataset = "repetitive";
    opts->csv_path = "mem-arena/process_mem_bench.csv";

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dataset") == 0 && i + 1 < argc) {
            opts->dataset = argv[++i];
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
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            exit(0);
        } else {
            return -1;
        }
    }

    if (strcmp(opts->dataset, "repetitive") != 0 && strcmp(opts->dataset, "unique") != 0 &&
        strcmp(opts->dataset, "mixed_50_50") != 0) {
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

static int snap(struct clocks *c)
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

static int run_one(const struct options *opts, int run_id, int warmup, struct sample *s)
{
    struct mem_arena_config cfg;
    struct mem_arena *arena = NULL;
    struct mem_arena_stats post_comp_stats;
    int region_id = -1;
    unsigned char *raw = NULL;
    size_t len = (size_t)opts->region_mb * 1024UL * 1024UL;
    size_t off;
    struct clocks c0, c1, d0, d1;

    memset(s, 0, sizeof(*s));
    s->run_id = run_id;
    s->warmup = warmup;

    cfg.arena_capacity_bytes = (size_t)opts->arena_mb * 1024UL * 1024UL;
    cfg.chunk_size = PAGE_SIZE;
    cfg.min_savings_percent = opts->min_savings_pct;
    cfg.lz4_acceleration = 1;

    arena = mem_arena_create(&cfg);
    if (arena == NULL) {
        return -1;
    }
    if (mem_arena_region_alloc(arena, len, "bench-region", &region_id, &raw) != 0) {
        mem_arena_destroy(arena);
        return -1;
    }

    fill_dataset(raw, len, opts->dataset);
    for (off = 0; off < len; off += PAGE_SIZE) {
        raw[off] ^= 1;
    }

    if (read_status_kb("VmRSS:", &s->rss_pre_kb) != 0) {
        mem_arena_destroy(arena);
        return -1;
    }
    if (read_status_kb("VmHWM:", &s->hwm_kb) != 0) {
        s->hwm_kb = 0;
    }

    if (snap(&c0) != 0 || mem_arena_compress_region(arena, region_id) != 0 || snap(&c1) != 0) {
        mem_arena_destroy(arena);
        return -1;
    }
    if (read_status_kb("VmRSS:", &s->rss_post_compress_kb) != 0) {
        mem_arena_destroy(arena);
        return -1;
    }
    if (mem_arena_get_stats(arena, &post_comp_stats) != 0) {
        mem_arena_destroy(arena);
        return -1;
    }
    s->compressed_bytes_post_compress = post_comp_stats.compressed_bytes_live;
    s->slot_bytes_post_compress = post_comp_stats.slot_bytes_live;

    if (snap(&d0) != 0) {
        mem_arena_destroy(arena);
        return -1;
    }
    for (off = 0; off < len; off += PAGE_SIZE) {
        if (mem_arena_touch(arena, region_id, off, MEM_ARENA_OP_XOR1) != 0) {
            mem_arena_destroy(arena);
            return -1;
        }
    }
    if (snap(&d1) != 0) {
        mem_arena_destroy(arena);
        return -1;
    }
    if (read_status_kb("VmRSS:", &s->rss_post_readback_kb) != 0) {
        mem_arena_destroy(arena);
        return -1;
    }

    s->compress_wall_ms = msdiff(&c0.wall, &c1.wall);
    s->compress_thread_cpu_ms = msdiff(&c0.thread_cpu, &c1.thread_cpu);
    s->compress_proc_cpu_ms = msdiff(&c0.process_cpu, &c1.process_cpu);
    s->decompress_wall_ms = msdiff(&d0.wall, &d1.wall);
    s->decompress_thread_cpu_ms = msdiff(&d0.thread_cpu, &d1.thread_cpu);
    s->decompress_proc_cpu_ms = msdiff(&d0.process_cpu, &d1.process_cpu);

    if (mem_arena_get_stats(arena, &s->arena_stats) != 0) {
        mem_arena_destroy(arena);
        return -1;
    }

    mem_arena_destroy(arena);
    return 0;
}

static int write_csv_header(FILE *fp)
{
    return fprintf(fp,
                   "dataset,run,warmup,pid,region_mb,arena_cap_mb,min_savings_pct,"
                   "rss_pre_kb,rss_post_compress_kb,rss_post_readback_kb,rss_delta_comp_kb,vmhwm_kb,"
                   "compress_wall_ms,compress_thread_cpu_ms,compress_process_cpu_ms,"
                   "decompress_wall_ms,decompress_thread_cpu_ms,decompress_process_cpu_ms,"
                   "compressed_bytes_post_compress,slot_bytes_post_compress,"
                   "logical_input_bytes,compressed_bytes_live,slot_bytes_live,compress_ops,decompress_ops,"
                   "evictions_lru,incompressible_chunks,access_hits_raw,access_hits_decompressed,"
                   "compression_reject_small_gain\n") < 0
               ? -1
               : 0;
}

static int append_csv_row(FILE *fp, const struct options *opts, const struct sample *s)
{
    long long delta = (long long)s->rss_pre_kb - (long long)s->rss_post_compress_kb;

    if (fprintf(fp, "%s,%d,%d,%d,%d,%d,%d,", opts->dataset, s->run_id, s->warmup, (int)getpid(), opts->region_mb,
                opts->arena_mb, opts->min_savings_pct) < 0) {
        return -1;
    }
    if (fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%lld,%" PRIu64 ",", s->rss_pre_kb, s->rss_post_compress_kb,
                s->rss_post_readback_kb, delta, s->hwm_kb) < 0) {
        return -1;
    }
    if (fprintf(fp, "%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,", s->compress_wall_ms, s->compress_thread_cpu_ms,
                s->compress_proc_cpu_ms, s->decompress_wall_ms, s->decompress_thread_cpu_ms,
                s->decompress_proc_cpu_ms) < 0) {
        return -1;
    }
    if (fprintf(fp, "%" PRIu64 ",%" PRIu64 ",", s->compressed_bytes_post_compress, s->slot_bytes_post_compress) < 0) {
        return -1;
    }
    if (fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",", s->arena_stats.logical_input_bytes,
                s->arena_stats.compressed_bytes_live, s->arena_stats.slot_bytes_live, s->arena_stats.compress_ops,
                s->arena_stats.decompress_ops) < 0) {
        return -1;
    }
    if (fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n", s->arena_stats.evictions_lru,
                s->arena_stats.incompressible_chunks, s->arena_stats.access_hits_raw,
                s->arena_stats.access_hits_decompressed, s->arena_stats.compression_reject_small_gain) < 0) {
        return -1;
    }
    return 0;
}

static void print_header(void)
{
    printf("dataset      run warmup rss_pre_kb rss_post_comp_kb rss_post_read_kb rss_delta_comp_kb comp_thread_ms decomp_thread_ms comp_bytes_post slot_bytes_post comp_ops decomp_ops evictions\n");
    printf("------------ --- ------ ---------- ---------------- ---------------- ---------------- ------------ --------------- --------------- -------------- -------- --------- ---------\n");
}

static void print_row(const char *dataset, const struct sample *s)
{
    long long delta = (long long)s->rss_pre_kb - (long long)s->rss_post_compress_kb;

    printf("%-12s %3d %6d %10" PRIu64 " %16" PRIu64 " %16" PRIu64 " %16lld %12.3f %15.3f %15" PRIu64
           " %14" PRIu64 " %8" PRIu64 " %9" PRIu64 " %9" PRIu64 "\n",
           dataset,
           s->run_id,
           s->warmup,
           s->rss_pre_kb,
           s->rss_post_compress_kb,
           s->rss_post_readback_kb,
           delta,
           s->compress_thread_cpu_ms,
           s->decompress_thread_cpu_ms,
           s->compressed_bytes_post_compress,
           s->slot_bytes_post_compress,
           s->arena_stats.compress_ops,
           s->arena_stats.decompress_ops,
           s->arena_stats.evictions_lru);
}

int main(int argc, char **argv)
{
    struct options opts;
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
    for (i = 0; i < total_runs; i++) {
        struct sample s;
        int warmup = (i < opts.warmups) ? 1 : 0;
        if (run_one(&opts, i + 1, warmup, &s) != 0) {
            fprintf(stderr, "run failed at iteration %d\n", i + 1);
            fclose(csv);
            return 1;
        }
        print_row(opts.dataset, &s);
        if (append_csv_row(csv, &opts, &s) != 0) {
            fprintf(stderr, "failed to append CSV row\n");
            fclose(csv);
            return 1;
        }
    }

    fclose(csv);
    printf("csv_written=%s\n", opts.csv_path);
    return 0;
}
