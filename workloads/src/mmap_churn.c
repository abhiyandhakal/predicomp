#include "common.h"
#include "controller_client.h"

#include <mem_arena.h>

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define DEFAULT_MAP_KB 512
#define DEFAULT_OPS_PER_SEC 500
#define DEFAULT_ARENA_REGION_MB 128
#define PAGE_SIZE 4096

enum compress_policy {
    COMPRESS_POLICY_INTERNAL = 0,
    COMPRESS_POLICY_EXTERNAL = 1,
    COMPRESS_POLICY_BOTH = 2,
};

static volatile sig_atomic_t g_compress_requested;

static void on_sigusr1(int sig)
{
    (void)sig;
    g_compress_requested = 1;
}

static const char *compress_policy_name(enum compress_policy policy)
{
    if (policy == COMPRESS_POLICY_EXTERNAL) {
        return "external";
    }
    if (policy == COMPRESS_POLICY_BOTH) {
        return "both";
    }
    return "internal";
}

static enum compress_policy parse_compress_policy(const char *value)
{
    if (strcmp(value, "internal") == 0) {
        return COMPRESS_POLICY_INTERNAL;
    }
    if (strcmp(value, "external") == 0) {
        return COMPRESS_POLICY_EXTERNAL;
    }
    if (strcmp(value, "both") == 0) {
        return COMPRESS_POLICY_BOTH;
    }

    fprintf(stderr, "invalid --compress-policy: %s (expected internal|external|both)\n", value);
    exit(2);
}

static int write_arena_stats_json(
    const char *path,
    const char *workload,
    const struct mem_arena_stats *stats
)
{
    FILE *fp;

    if (path == NULL) {
        return 0;
    }

    fp = fopen(path, "w");
    if (fp == NULL) {
        perror("fopen(arena_stats_json)");
        return -1;
    }

    fprintf(fp, "{");
    fprintf(fp, "\"workload\":\"%s\",", workload);
    fprintf(fp, "\"logical_input_bytes\":%" PRIu64 ",", stats->logical_input_bytes);
    fprintf(fp, "\"compressed_bytes_live\":%" PRIu64 ",", stats->compressed_bytes_live);
    fprintf(fp, "\"slot_bytes_live\":%" PRIu64 ",", stats->slot_bytes_live);
    fprintf(fp, "\"compress_ops\":%" PRIu64 ",", stats->compress_ops);
    fprintf(fp, "\"decompress_ops\":%" PRIu64 ",", stats->decompress_ops);
    fprintf(fp, "\"evictions_lru\":%" PRIu64 ",", stats->evictions_lru);
    fprintf(fp, "\"incompressible_chunks\":%" PRIu64 ",", stats->incompressible_chunks);
    fprintf(fp, "\"access_hits_raw\":%" PRIu64 ",", stats->access_hits_raw);
    fprintf(fp, "\"access_hits_decompressed\":%" PRIu64 ",", stats->access_hits_decompressed);
    fprintf(fp, "\"compression_reject_small_gain\":%" PRIu64, stats->compression_reject_small_gain);
    fprintf(fp, "}\n");

    fclose(fp);
    return 0;
}

static int maybe_external_compress(
    struct mem_arena *arena,
    int region_id,
    const char *controller_sock,
    uint64_t *trigger_count
)
{
    struct mem_arena_stats stats;

    if (!g_compress_requested) {
        return 0;
    }

    g_compress_requested = 0;
    if (mem_arena_compress_region(arena, region_id) != 0) {
        return -1;
    }

    memset(&stats, 0, sizeof(stats));
    if (mem_arena_get_stats(arena, &stats) != 0) {
        return -1;
    }

    (*trigger_count)++;
    if (controller_sock != NULL) {
        (void)wl_controller_send_compress_ack(
            controller_sock,
            "mmap_churn",
            *trigger_count,
            &stats,
            wl_now_ns()
        );
    }

    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [options]\n", prog);
    fprintf(stderr, "  --map-kb <n>              bytes per mmap region in KiB (default %d)\n", DEFAULT_MAP_KB);
    fprintf(stderr, "  --ops-per-sec <n>         mmap/munmap ops per second (default %d)\n", DEFAULT_OPS_PER_SEC);
    fprintf(stderr, "  --use-mem-arena           enable sidecar managed compression arena\n");
    fprintf(stderr, "  --arena-region-mb <n>     sidecar arena region size MB (default %d)\n", DEFAULT_ARENA_REGION_MB);
    fprintf(stderr, "  --arena-cap-mb <n>        arena compressed pool MB (default 256)\n");
    fprintf(stderr, "  --arena-min-savings-pct <n> min savings threshold %% (default 5)\n");
    fprintf(stderr, "  --arena-stats-json <path> write arena stats JSON\n");
    fprintf(stderr, "  --controller-enroll       enroll with workload controller (requires mem-arena)\n");
    fprintf(stderr, "  --controller-sock <path>  controller unix datagram socket path\n");
    fprintf(stderr, "  --compress-policy <mode>  internal|external|both (default internal)\n");
    wl_print_common_help();
}

int main(int argc, char **argv)
{
    struct wl_common_opts common;
    int map_kb = DEFAULT_MAP_KB;
    int ops_per_sec = DEFAULT_OPS_PER_SEC;
    int use_mem_arena = 0;
    int arena_region_mb = DEFAULT_ARENA_REGION_MB;
    int arena_cap_mb = 256;
    int arena_min_savings_pct = 5;
    const char *arena_stats_json = NULL;
    int controller_enroll = 0;
    const char *controller_sock = NULL;
    enum compress_policy compress_policy = COMPRESS_POLICY_INTERNAL;
    uint64_t external_compress_triggers = 0;
    uint64_t ops = 0;
    size_t len;
    uint64_t interval_ns;
    uint64_t start_ns;
    uint64_t deadline_ns;
    uint64_t compress_every_ops;
    struct mem_arena *arena = NULL;
    int region_id = -1;
    unsigned char *arena_buf = NULL;
    struct mem_arena_stats arena_stats;
    size_t sidecar_len = 0;
    size_t sidecar_pages = 0;
    size_t sidecar_page_idx = 0;

    wl_init_common_opts(&common);
    memset(&arena_stats, 0, sizeof(arena_stats));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "--unsafe-allow-long") == 0) {
            wl_parse_common_arg(&common, argv[i], NULL);
            continue;
        }
        if (strcmp(argv[i], "--use-mem-arena") == 0) {
            use_mem_arena = 1;
            continue;
        }
        if (strcmp(argv[i], "--controller-enroll") == 0) {
            controller_enroll = 1;
            continue;
        }
        if (i + 1 >= argc) {
            fprintf(stderr, "missing value for %s\n", argv[i]);
            return 2;
        }
        if (strcmp(argv[i], "--map-kb") == 0) {
            map_kb = wl_parse_int_arg("--map-kb", argv[++i], 4, 1048576);
            continue;
        }
        if (strcmp(argv[i], "--ops-per-sec") == 0) {
            ops_per_sec = wl_parse_int_arg("--ops-per-sec", argv[++i], 1, 100000);
            continue;
        }
        if (strcmp(argv[i], "--arena-region-mb") == 0) {
            arena_region_mb = wl_parse_int_arg("--arena-region-mb", argv[++i], 1, 16384);
            continue;
        }
        if (strcmp(argv[i], "--arena-cap-mb") == 0) {
            arena_cap_mb = wl_parse_int_arg("--arena-cap-mb", argv[++i], 8, 65536);
            continue;
        }
        if (strcmp(argv[i], "--arena-min-savings-pct") == 0) {
            arena_min_savings_pct = wl_parse_int_arg("--arena-min-savings-pct", argv[++i], 0, 95);
            continue;
        }
        if (strcmp(argv[i], "--arena-stats-json") == 0) {
            arena_stats_json = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--controller-sock") == 0) {
            controller_sock = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--compress-policy") == 0) {
            compress_policy = parse_compress_policy(argv[++i]);
            continue;
        }
        if (wl_parse_common_arg(&common, argv[i], argv[i + 1])) {
            i++;
            continue;
        }
        fprintf(stderr, "unknown arg: %s\n", argv[i]);
        return 2;
    }

    if (wl_validate_common_opts(&common) != 0) {
        return 2;
    }
    if (controller_enroll && !use_mem_arena) {
        fprintf(stderr, "--controller-enroll requires --use-mem-arena\n");
        return 2;
    }
    if (compress_policy != COMPRESS_POLICY_INTERNAL && !use_mem_arena) {
        fprintf(stderr, "--compress-policy %s requires --use-mem-arena\n",
                compress_policy_name(compress_policy));
        return 2;
    }
    controller_sock = wl_controller_sock_default_if_null(controller_sock);

    signal(SIGUSR1, on_sigusr1);

    len = (size_t)map_kb * 1024UL;
    interval_ns = 1000000000ULL / (uint64_t)ops_per_sec;
    compress_every_ops = (uint64_t)ops_per_sec / 10ULL;
    if (compress_every_ops == 0) {
        compress_every_ops = 1;
    }

    if (use_mem_arena) {
        struct mem_arena_config cfg;

        sidecar_len = (size_t)arena_region_mb * 1024UL * 1024UL;
        sidecar_pages = sidecar_len / PAGE_SIZE;
        if (sidecar_pages == 0) {
            fprintf(stderr, "arena sidecar region too small\n");
            return 1;
        }

        cfg.arena_capacity_bytes = (size_t)arena_cap_mb * 1024UL * 1024UL;
        cfg.chunk_size = PAGE_SIZE;
        cfg.min_savings_percent = arena_min_savings_pct;
        cfg.lz4_acceleration = 1;

        arena = mem_arena_create(&cfg);
        if (arena == NULL) {
            fprintf(stderr, "mem_arena_create failed\n");
            return 1;
        }
        if (mem_arena_region_alloc(arena, sidecar_len, "mmap_churn_sidecar", &region_id, &arena_buf) != 0) {
            fprintf(stderr, "mem_arena_region_alloc failed\n");
            mem_arena_destroy(arena);
            return 1;
        }
        memset(arena_buf, 0, sidecar_len);

        if (controller_enroll) {
            if (wl_controller_send_enroll(controller_sock,
                                          "mmap_churn",
                                          arena_cap_mb,
                                          arena_min_savings_pct,
                                          arena_region_mb) != 0) {
                mem_arena_destroy(arena);
                return 1;
            }
        }
    }

    start_ns = wl_now_ns();
    deadline_ns = start_ns + (uint64_t)common.duration_sec * 1000000000ULL;

    while (wl_now_ns() < deadline_ns) {
        char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (p == MAP_FAILED) {
            perror("mmap");
            if (arena != NULL) {
                mem_arena_destroy(arena);
            }
            return 1;
        }
        for (size_t off = 0; off < len; off += PAGE_SIZE) {
            p[off] = (char)(off & 0xff);
        }
        if (munmap(p, len) != 0) {
            perror("munmap");
            if (arena != NULL) {
                mem_arena_destroy(arena);
            }
            return 1;
        }

        if (use_mem_arena) {
            size_t sidecar_off = (sidecar_page_idx % sidecar_pages) * PAGE_SIZE;

            if (mem_arena_touch(arena, region_id, sidecar_off, MEM_ARENA_OP_XOR1) != 0) {
                fprintf(stderr, "mem_arena_touch failed\n");
                mem_arena_destroy(arena);
                return 1;
            }
            sidecar_page_idx++;
        }

        ops++;

        if (use_mem_arena && maybe_external_compress(arena,
                                                     region_id,
                                                     controller_enroll ? controller_sock : NULL,
                                                     &external_compress_triggers) != 0) {
            fprintf(stderr, "external mem_arena_compress_region failed\n");
            mem_arena_destroy(arena);
            return 1;
        }

        if (use_mem_arena &&
            (compress_policy == COMPRESS_POLICY_INTERNAL || compress_policy == COMPRESS_POLICY_BOTH) &&
            (ops % compress_every_ops) == 0) {
            if (mem_arena_compress_region(arena, region_id) != 0) {
                fprintf(stderr, "mem_arena_compress_region failed\n");
                mem_arena_destroy(arena);
                return 1;
            }
        }

        wl_sleep_ns(interval_ns);
    }

    if (use_mem_arena && maybe_external_compress(arena,
                                                 region_id,
                                                 controller_enroll ? controller_sock : NULL,
                                                 &external_compress_triggers) != 0) {
        fprintf(stderr, "external mem_arena_compress_region failed\n");
        mem_arena_destroy(arena);
        return 1;
    }

    if (use_mem_arena) {
        if (mem_arena_get_stats(arena, &arena_stats) != 0) {
            fprintf(stderr, "mem_arena_get_stats failed\n");
            mem_arena_destroy(arena);
            return 1;
        }
    }

    double elapsed_ms = (double)(wl_now_ns() - start_ns) / 1000000.0;
    if (common.json) {
        printf("{");
        wl_print_json_kv_str("workload", "mmap_churn", false);
        wl_print_json_kv_u64("ops", ops, false);
        wl_print_json_kv_u64("map_kb", (uint64_t)map_kb, false);
        wl_print_json_kv_u64("use_mem_arena", (uint64_t)use_mem_arena, false);
        if (use_mem_arena) {
            wl_print_json_kv_u64("arena_region_mb", (uint64_t)arena_region_mb, false);
        }
        wl_print_json_kv_str("compress_policy", compress_policy_name(compress_policy), false);
        wl_print_json_kv_u64("external_compress_triggers", external_compress_triggers, false);
        if (use_mem_arena) {
            wl_print_json_kv_u64("arena_compress_ops", arena_stats.compress_ops, false);
            wl_print_json_kv_u64("arena_decompress_ops", arena_stats.decompress_ops, false);
            wl_print_json_kv_u64("arena_evictions_lru", arena_stats.evictions_lru, false);
        }
        wl_print_json_kv_double("elapsed_ms", elapsed_ms, true);
        printf("}\n");
    } else {
        printf("mmap_churn map_kb=%d ops_per_sec=%d duration_sec=%d ops=%" PRIu64 " elapsed_ms=%.3f use_mem_arena=%d",
               map_kb,
               ops_per_sec,
               common.duration_sec,
               ops,
               elapsed_ms,
               use_mem_arena);
        if (use_mem_arena) {
            printf(" arena_region_mb=%d", arena_region_mb);
        }
        printf(" compress_policy=%s external_compress_triggers=%" PRIu64,
               compress_policy_name(compress_policy),
               external_compress_triggers);
        if (use_mem_arena) {
            printf(" arena_compress_ops=%" PRIu64 " arena_decompress_ops=%" PRIu64 " arena_evictions_lru=%" PRIu64,
                   arena_stats.compress_ops,
                   arena_stats.decompress_ops,
                   arena_stats.evictions_lru);
        }
        printf("\n");
    }

    if (use_mem_arena) {
        if (arena_stats_json != NULL) {
            if (write_arena_stats_json(arena_stats_json, "mmap_churn", &arena_stats) != 0) {
                mem_arena_destroy(arena);
                return 1;
            }
        }
        mem_arena_destroy(arena);
    }

    return 0;
}
