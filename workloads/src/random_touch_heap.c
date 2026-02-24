#include "common.h"
#include "controller_client.h"

#include <mem_arena.h>
#include <predicomp_client.h>

#include <inttypes.h>
#include <signal.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_REGION_MB 512
#define DEFAULT_OPS_PER_SEC 400000
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

static uint64_t xorshift64(uint64_t *state)
{
    uint64_t x = *state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
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
            "random_touch_heap",
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
    fprintf(stderr, "  --region-mb <n>            region size in MB (default %d)\n", DEFAULT_REGION_MB);
    fprintf(stderr, "  --ops-per-sec <n>          random touches per second (default %d)\n", DEFAULT_OPS_PER_SEC);
    fprintf(stderr, "  --use-mem-arena            enable managed compression arena\n");
    fprintf(stderr, "  --use-process-pager        enable cooperative process-pager mode\n");
    fprintf(stderr, "  --pager-sock <path>        process-pager daemon UNIX socket (default /tmp/predicomp-pager.sock)\n");
    fprintf(stderr, "  --arena-cap-mb <n>         arena compressed pool MB (default 256)\n");
    fprintf(stderr, "  --arena-min-savings-pct <n> min savings threshold %% (default 5)\n");
    fprintf(stderr, "  --arena-stats-json <path>  write arena stats JSON\n");
    fprintf(stderr, "  --controller-enroll        enroll with workload controller (requires mem-arena)\n");
    fprintf(stderr, "  --controller-sock <path>   controller unix datagram socket path\n");
    fprintf(stderr, "  --compress-policy <mode>   internal|external|both (default internal)\n");
    wl_print_common_help();
}

int main(int argc, char **argv)
{
    struct wl_common_opts common;
    int region_mb = DEFAULT_REGION_MB;
    int ops_per_sec = DEFAULT_OPS_PER_SEC;
    int use_mem_arena = 0;
    int use_process_pager = 0;
    const char *pager_sock = NULL;
    int arena_cap_mb = 256;
    int arena_min_savings_pct = 5;
    const char *arena_stats_json = NULL;
    int controller_enroll = 0;
    const char *controller_sock = NULL;
    enum compress_policy compress_policy = COMPRESS_POLICY_INTERNAL;
    uint64_t external_compress_triggers = 0;
    uint64_t ops = 0;
    size_t len;
    size_t page_count;
    uint64_t state;
    uint64_t start_ns;
    uint64_t deadline_ns;
    uint64_t interval_ns;
    uint64_t compress_every_ops;
    struct mem_arena *arena = NULL;
    int region_id = -1;
    unsigned char *arena_buf = NULL;
    char *buf = NULL;
    int used_mmap_region = 0;
    struct predicomp_client *pager_client = NULL;
    struct predicomp_client_config pager_cfg;
    struct predicomp_range_handle pager_range;
    int pager_range_registered = 0;
    struct mem_arena_stats arena_stats;

    wl_init_common_opts(&common);
    memset(&arena_stats, 0, sizeof(arena_stats));
    memset(&pager_cfg, 0, sizeof(pager_cfg));
    memset(&pager_range, 0, sizeof(pager_range));

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
        if (strcmp(argv[i], "--use-process-pager") == 0) {
            use_process_pager = 1;
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
        if (strcmp(argv[i], "--region-mb") == 0) {
            region_mb = wl_parse_int_arg("--region-mb", argv[++i], 1, 16384);
            continue;
        }
        if (strcmp(argv[i], "--ops-per-sec") == 0) {
            ops_per_sec = wl_parse_int_arg("--ops-per-sec", argv[++i], 1, 50000000);
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
        if (strcmp(argv[i], "--pager-sock") == 0) {
            pager_sock = argv[++i];
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
    if (use_mem_arena && use_process_pager) {
        fprintf(stderr, "--use-mem-arena and --use-process-pager are mutually exclusive\n");
        return 2;
    }
    if (pager_sock != NULL && !use_process_pager) {
        fprintf(stderr, "--pager-sock requires --use-process-pager\n");
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

    len = (size_t)region_mb * 1024UL * 1024UL;
    page_count = len / PAGE_SIZE;
    if (page_count == 0) {
        fprintf(stderr, "region too small\n");
        return 1;
    }

    if (use_mem_arena) {
        struct mem_arena_config cfg;

        cfg.arena_capacity_bytes = (size_t)arena_cap_mb * 1024UL * 1024UL;
        cfg.chunk_size = PAGE_SIZE;
        cfg.min_savings_percent = arena_min_savings_pct;
        cfg.lz4_acceleration = 1;

        arena = mem_arena_create(&cfg);
        if (arena == NULL) {
            fprintf(stderr, "mem_arena_create failed\n");
            return 1;
        }
        if (mem_arena_region_alloc(arena, len, "random_touch_heap", &region_id, &arena_buf) != 0) {
            fprintf(stderr, "mem_arena_region_alloc failed\n");
            mem_arena_destroy(arena);
            return 1;
        }
        memset(arena_buf, 0, len);
        if (controller_enroll) {
            if (wl_controller_send_enroll(controller_sock,
                                          "random_touch_heap",
                                          arena_cap_mb,
                                          arena_min_savings_pct,
                                          region_mb) != 0) {
                mem_arena_destroy(arena);
                return 1;
            }
        }
    } else if (use_process_pager) {
        buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        used_mmap_region = 1;
    } else {
        buf = malloc(len);
        if (buf == NULL) {
            perror("malloc");
            return 1;
        }
        memset(buf, 0, len);
    }

    if (use_process_pager) {
        memset(buf, 0, len);
        pager_cfg.daemon_sock_path = pager_sock;
        pager_cfg.enable_wp = 1;
        pager_cfg.enable_missing = 1;
        if (predicomp_client_open(&pager_client, &pager_cfg) != 0) {
            perror("predicomp_client_open");
            if (used_mmap_region) {
                munmap(buf, len);
            }
            return 1;
        }
        if (predicomp_client_register_range(pager_client,
                                            buf,
                                            len,
                                            PREDICOMP_CLIENT_RANGE_F_ANON_PRIVATE |
                                                PREDICOMP_CLIENT_RANGE_F_WRITABLE,
                                            &pager_range) != 0) {
            perror("predicomp_client_register_range");
            predicomp_client_close(pager_client);
            if (used_mmap_region) {
                munmap(buf, len);
            }
            return 1;
        }
        pager_range_registered = 1;
        if (predicomp_client_start(pager_client) != 0) {
            perror("predicomp_client_start");
            predicomp_client_close(pager_client);
            if (used_mmap_region) {
                munmap(buf, len);
            }
            return 1;
        }
    }

    state = common.seed;
    start_ns = wl_now_ns();
    deadline_ns = start_ns + (uint64_t)common.duration_sec * 1000000000ULL;
    interval_ns = 1000000000ULL / (uint64_t)ops_per_sec;
    compress_every_ops = (uint64_t)ops_per_sec / 10ULL;
    if (compress_every_ops == 0) {
        compress_every_ops = 1;
    }

    while (wl_now_ns() < deadline_ns) {
        size_t page_idx = (size_t)(xorshift64(&state) % page_count);
        size_t off = page_idx * PAGE_SIZE;

        if (use_mem_arena) {
            if (mem_arena_touch(arena, region_id, off, MEM_ARENA_OP_XOR1) != 0) {
                fprintf(stderr, "mem_arena_touch failed\n");
                mem_arena_destroy(arena);
                return 1;
            }
        } else {
            buf[off] ^= 1;
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
        wl_print_json_kv_str("workload", "random_touch_heap", false);
        wl_print_json_kv_u64("ops", ops, false);
        wl_print_json_kv_u64("region_mb", (uint64_t)region_mb, false);
        wl_print_json_kv_u64("use_mem_arena", (uint64_t)use_mem_arena, false);
        wl_print_json_kv_u64("use_process_pager", (uint64_t)use_process_pager, false);
        if (use_process_pager) {
            wl_print_json_kv_str("pager_sock",
                                 pager_sock != NULL ? pager_sock : "/tmp/predicomp-pager.sock",
                                 false);
            wl_print_json_kv_u64("pager_range_registered", (uint64_t)pager_range_registered, false);
            wl_print_json_kv_u64("pager_range_id", (uint64_t)pager_range.id, false);
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
        printf("random_touch_heap region_mb=%d ops_per_sec=%d duration_sec=%d ops=%" PRIu64 " elapsed_ms=%.3f use_mem_arena=%d use_process_pager=%d compress_policy=%s external_compress_triggers=%" PRIu64,
               region_mb,
               ops_per_sec,
               common.duration_sec,
               ops,
               elapsed_ms,
               use_mem_arena,
               use_process_pager,
               compress_policy_name(compress_policy),
               external_compress_triggers);
        if (use_process_pager) {
            printf(" pager_sock=%s pager_range_registered=%d pager_range_id=%d",
                   pager_sock != NULL ? pager_sock : "/tmp/predicomp-pager.sock",
                   pager_range_registered,
                   pager_range.id);
        }
        if (use_mem_arena) {
            printf(" arena_compress_ops=%" PRIu64 " arena_decompress_ops=%" PRIu64 " arena_evictions_lru=%" PRIu64,
                   arena_stats.compress_ops,
                   arena_stats.decompress_ops,
                   arena_stats.evictions_lru);
        }
        printf("\n");
    }

    if (use_process_pager && pager_client != NULL) {
        (void)predicomp_client_stop(pager_client);
        predicomp_client_close(pager_client);
        pager_client = NULL;
    }

    if (use_mem_arena) {
        if (arena_stats_json != NULL) {
            if (write_arena_stats_json(arena_stats_json, "random_touch_heap", &arena_stats) != 0) {
                mem_arena_destroy(arena);
                return 1;
            }
        }
        mem_arena_destroy(arena);
    } else if (used_mmap_region) {
        munmap(buf, len);
    } else {
        free(buf);
    }

    return 0;
}
