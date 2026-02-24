#include "common.h"

#include <mem_arena.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_REGION_MB 128
#define DEFAULT_ACTIVE_MS 100
#define DEFAULT_IDLE_MS 400
#define PAGE_SIZE 4096

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

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [options]\n", prog);
    fprintf(stderr, "  --region-mb <n>            region size in MB (default %d)\n", DEFAULT_REGION_MB);
    fprintf(stderr, "  --active-ms <n>            active touch phase (default %d)\n", DEFAULT_ACTIVE_MS);
    fprintf(stderr, "  --idle-ms <n>              idle phase (default %d)\n", DEFAULT_IDLE_MS);
    fprintf(stderr, "  --use-mem-arena            enable managed compression arena\n");
    fprintf(stderr, "  --arena-cap-mb <n>         arena compressed pool MB (default 256)\n");
    fprintf(stderr, "  --arena-min-savings-pct <n> min savings threshold %% (default 5)\n");
    fprintf(stderr, "  --arena-stats-json <path>  write arena stats JSON\n");
    fprintf(stderr, "  --arena-autoloops          enable mem-arena hotness/compress/prefetch loops\n");
    fprintf(stderr, "  --arena-t-cold-ms <n>      initial cold threshold in ms (default 2000)\n");
    fprintf(stderr, "  --arena-prefetch-distance <n> prefetch next-k start distance (default 1)\n");
    fprintf(stderr, "  --arena-prefetch-batch <n> prefetch batch chunks (default 4)\n");
    fprintf(stderr, "  --arena-disable-prefetch   disable mem-arena prefetch loop in autoloops mode\n");
    fprintf(stderr, "  --arena-disable-bg-compress disable mem-arena background compression loop in autoloops mode\n");
    wl_print_common_help();
}

int main(int argc, char **argv)
{
    struct wl_common_opts common;
    int region_mb = DEFAULT_REGION_MB;
    int active_ms = DEFAULT_ACTIVE_MS;
    int idle_ms = DEFAULT_IDLE_MS;
    int use_mem_arena = 0;
    int arena_cap_mb = 256;
    int arena_min_savings_pct = 5;
    const char *arena_stats_json = NULL;
    int arena_autoloops = 0;
    int arena_t_cold_ms = 2000;
    int arena_prefetch_distance = 1;
    int arena_prefetch_batch = 4;
    int arena_disable_prefetch = 0;
    int arena_disable_bg_compress = 0;
    uint64_t touches = 0;
    size_t len;
    uint64_t start_ns;
    uint64_t deadline_ns;
    struct mem_arena *arena = NULL;
    int region_id = -1;
    unsigned char *raw_buf = NULL;
    struct mem_arena_stats arena_stats;

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
        if (strcmp(argv[i], "--arena-autoloops") == 0) {
            arena_autoloops = 1;
            continue;
        }
        if (strcmp(argv[i], "--arena-disable-prefetch") == 0) {
            arena_disable_prefetch = 1;
            continue;
        }
        if (strcmp(argv[i], "--arena-disable-bg-compress") == 0) {
            arena_disable_bg_compress = 1;
            continue;
        }
        if (i + 1 >= argc) {
            fprintf(stderr, "missing value for %s\n", argv[i]);
            return 2;
        }
        if (strcmp(argv[i], "--region-mb") == 0) {
            region_mb = wl_parse_int_arg("--region-mb", argv[++i], 1, 8192);
            continue;
        }
        if (strcmp(argv[i], "--active-ms") == 0) {
            active_ms = wl_parse_int_arg("--active-ms", argv[++i], 1, 10000);
            continue;
        }
        if (strcmp(argv[i], "--idle-ms") == 0) {
            idle_ms = wl_parse_int_arg("--idle-ms", argv[++i], 1, 30000);
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
        if (strcmp(argv[i], "--arena-t-cold-ms") == 0) {
            arena_t_cold_ms = wl_parse_int_arg("--arena-t-cold-ms", argv[++i], 100, 60000);
            continue;
        }
        if (strcmp(argv[i], "--arena-prefetch-distance") == 0) {
            arena_prefetch_distance = wl_parse_int_arg("--arena-prefetch-distance", argv[++i], 1, 1024);
            continue;
        }
        if (strcmp(argv[i], "--arena-prefetch-batch") == 0) {
            arena_prefetch_batch = wl_parse_int_arg("--arena-prefetch-batch", argv[++i], 1, 1024);
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
    len = (size_t)region_mb * 1024UL * 1024UL;

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
        if (mem_arena_region_alloc(arena, len, "interactive_burst", &region_id, &raw_buf) != 0) {
            fprintf(stderr, "mem_arena_region_alloc failed\n");
            mem_arena_destroy(arena);
            return 1;
        }
        if (arena_autoloops) {
            struct mem_arena_loops_config loops_cfg = {0};

            loops_cfg.enable_hotness_loop = 1;
            loops_cfg.enable_compression_loop = arena_disable_bg_compress ? 0 : 1;
            loops_cfg.enable_prefetch_loop = arena_disable_prefetch ? 0 : 1;
            loops_cfg.enable_damon_classification = 1;
            loops_cfg.hotness_tick_ms = 50;
            loops_cfg.compression_tick_ms = 100;
            loops_cfg.prefetch_tick_ms = 50;
            loops_cfg.damon_sample_us = 5000;
            loops_cfg.damon_aggr_us = 100000;
            loops_cfg.damon_update_us = 1000000;
            loops_cfg.damon_nr_regions_min = 10;
            loops_cfg.damon_nr_regions_max = 1000;
            loops_cfg.damon_read_tick_ms = 200;
            loops_cfg.damon_hot_accesses_min = 1;
            loops_cfg.damon_warm_accesses_min = 0;
            loops_cfg.t_hot_epochs = 2;
            loops_cfg.t_cold_epochs_initial = (uint32_t)((arena_t_cold_ms + 99) / 100);
            if (loops_cfg.t_cold_epochs_initial < 2) {
                loops_cfg.t_cold_epochs_initial = 2;
            }
            loops_cfg.t_cold_epochs_min = 2;
            loops_cfg.t_cold_epochs_max = 600;
            loops_cfg.t_cold_step_up = 2;
            loops_cfg.t_cold_step_down = 1;
            loops_cfg.recompress_guard_epochs = 3;
            loops_cfg.churn_touch_threshold = 100000;
            loops_cfg.low_ratio_skip_bps = 9000;
            loops_cfg.prefetch_distance_chunks = (uint32_t)arena_prefetch_distance;
            loops_cfg.prefetch_batch_chunks = (uint32_t)arena_prefetch_batch;
            loops_cfg.prefetch_queue_capacity = 1024;
            loops_cfg.adapt_interval_ms = 1000;
            loops_cfg.target_pool_util_pct = 70;
            loops_cfg.stall_events_threshold = 8;

            if (mem_arena_loops_start(arena, &loops_cfg) != 0) {
                fprintf(stderr, "mem_arena_loops_start failed\n");
                mem_arena_destroy(arena);
                return 1;
            }
        }
    } else {
        raw_buf = malloc(len);
        if (raw_buf == NULL) {
            perror("malloc");
            return 1;
        }
    }

    memset(raw_buf, 0, len);

    start_ns = wl_now_ns();
    deadline_ns = start_ns + (uint64_t)common.duration_sec * 1000000000ULL;

    while (wl_now_ns() < deadline_ns) {
        uint64_t active_end = wl_now_ns() + (uint64_t)active_ms * 1000000ULL;
        while (wl_now_ns() < active_end) {
            for (size_t off = 0; off < len; off += PAGE_SIZE) {
                if (use_mem_arena) {
                    if (mem_arena_touch(arena, region_id, off, MEM_ARENA_OP_XOR1) != 0) {
                        fprintf(stderr, "mem_arena_touch failed\n");
                        mem_arena_destroy(arena);
                        return 1;
                    }
                } else {
                    raw_buf[off] ^= 1;
                }
                touches++;
            }
        }

        if (use_mem_arena && !arena_autoloops) {
            if (mem_arena_compress_region(arena, region_id) != 0) {
                fprintf(stderr, "mem_arena_compress_region failed\n");
                mem_arena_destroy(arena);
                return 1;
            }
        }

        if (use_mem_arena && arena_autoloops) {
            (void)mem_arena_phase_hint(arena, region_id, "active_soon");
            (void)mem_arena_prefetch_range(arena, region_id, 0, (size_t)arena_prefetch_batch * PAGE_SIZE);
        }
        wl_sleep_ns((uint64_t)idle_ms * 1000000ULL);
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
        wl_print_json_kv_str("workload", "interactive_burst", false);
        wl_print_json_kv_u64("touches", touches, false);
        wl_print_json_kv_u64("region_mb", (uint64_t)region_mb, false);
        wl_print_json_kv_u64("use_mem_arena", (uint64_t)use_mem_arena, false);
        wl_print_json_kv_u64("arena_autoloops", (uint64_t)arena_autoloops, false);
        if (use_mem_arena) {
            wl_print_json_kv_u64("arena_compress_ops", arena_stats.compress_ops, false);
            wl_print_json_kv_u64("arena_decompress_ops", arena_stats.decompress_ops, false);
            wl_print_json_kv_u64("arena_evictions_lru", arena_stats.evictions_lru, false);
            wl_print_json_kv_u64("arena_hotness_epoch", arena_stats.hotness_epoch, false);
            wl_print_json_kv_u64("arena_damon_snapshots", arena_stats.damon_snapshots_total, false);
            wl_print_json_kv_u64("arena_damon_regions_observed", arena_stats.damon_regions_observed_total, false);
            wl_print_json_kv_u64("arena_damon_read_errors", arena_stats.damon_read_errors, false);
            wl_print_json_kv_u64("arena_bg_compress_attempts", arena_stats.bg_compress_attempts, false);
            wl_print_json_kv_u64("arena_bg_compress_admits", arena_stats.bg_compress_admits, false);
            wl_print_json_kv_u64("arena_prefetch_decompress_ops", arena_stats.prefetch_decompress_ops, false);
            wl_print_json_kv_u64("arena_demand_decompress_stall_events", arena_stats.demand_decompress_stall_events, false);
            wl_print_json_kv_u64("arena_demand_decompress_stall_ns_total", arena_stats.demand_decompress_stall_ns_total, false);
            wl_print_json_kv_u64("arena_t_cold_epochs_current", arena_stats.adaptive_t_cold_epochs_current, false);
        }
        wl_print_json_kv_double("elapsed_ms", elapsed_ms, true);
        printf("}\n");
    } else {
        printf("interactive_burst region_mb=%d active_ms=%d idle_ms=%d duration_sec=%d touches=%" PRIu64 " elapsed_ms=%.3f use_mem_arena=%d arena_autoloops=%d",
               region_mb,
               active_ms,
               idle_ms,
               common.duration_sec,
               touches,
               elapsed_ms,
               use_mem_arena,
               arena_autoloops);
        if (use_mem_arena) {
            printf(" arena_compress_ops=%" PRIu64 " arena_decompress_ops=%" PRIu64 " arena_evictions_lru=%" PRIu64
                   " arena_hotness_epoch=%" PRIu64 " arena_damon_snapshots=%" PRIu64 " arena_damon_regions=%" PRIu64
                   " arena_damon_read_errors=%" PRIu64 " arena_bg_compress_attempts=%" PRIu64
                   " arena_bg_compress_admits=%" PRIu64 " arena_prefetch_decompress_ops=%" PRIu64
                   " arena_demand_decomp_stalls=%" PRIu64,
                   arena_stats.compress_ops,
                   arena_stats.decompress_ops,
                   arena_stats.evictions_lru,
                   arena_stats.hotness_epoch,
                   arena_stats.damon_snapshots_total,
                   arena_stats.damon_regions_observed_total,
                   arena_stats.damon_read_errors,
                   arena_stats.bg_compress_attempts,
                   arena_stats.bg_compress_admits,
                   arena_stats.prefetch_decompress_ops,
                   arena_stats.demand_decompress_stall_events);
        }
        printf("\n");
    }

    if (use_mem_arena) {
        if (arena_autoloops) {
            (void)mem_arena_loops_stop(arena);
        }
        if (arena_stats_json != NULL) {
            if (write_arena_stats_json(arena_stats_json, "interactive_burst", &arena_stats) != 0) {
                mem_arena_destroy(arena);
                return 1;
            }
        }
        mem_arena_destroy(arena);
    } else {
        free(raw_buf);
    }

    return 0;
}
