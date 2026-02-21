#include "common.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_REGION_MB 128
#define DEFAULT_ACTIVE_MS 100
#define DEFAULT_IDLE_MS 400
#define PAGE_SIZE 4096

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [options]\n", prog);
    fprintf(stderr, "  --region-mb <n>  region size in MB (default %d)\n", DEFAULT_REGION_MB);
    fprintf(stderr, "  --active-ms <n>  active touch phase (default %d)\n", DEFAULT_ACTIVE_MS);
    fprintf(stderr, "  --idle-ms <n>    idle phase (default %d)\n", DEFAULT_IDLE_MS);
    wl_print_common_help();
}

int main(int argc, char **argv)
{
    struct wl_common_opts common;
    int region_mb = DEFAULT_REGION_MB;
    int active_ms = DEFAULT_ACTIVE_MS;
    int idle_ms = DEFAULT_IDLE_MS;
    uint64_t touches = 0;

    wl_init_common_opts(&common);
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--json") == 0 || strcmp(argv[i], "--unsafe-allow-long") == 0) {
            wl_parse_common_arg(&common, argv[i], NULL);
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

    size_t len = (size_t)region_mb * 1024UL * 1024UL;
    char *buf = malloc(len);
    if (buf == NULL) {
        perror("malloc");
        return 1;
    }

    memset(buf, 0, len);
    uint64_t start_ns = wl_now_ns();
    uint64_t deadline_ns = start_ns + (uint64_t)common.duration_sec * 1000000000ULL;

    while (wl_now_ns() < deadline_ns) {
        uint64_t active_end = wl_now_ns() + (uint64_t)active_ms * 1000000ULL;
        while (wl_now_ns() < active_end) {
            for (size_t off = 0; off < len; off += PAGE_SIZE) {
                buf[off] ^= 1;
                touches++;
            }
        }
        wl_sleep_ns((uint64_t)idle_ms * 1000000ULL);
    }

    double elapsed_ms = (double)(wl_now_ns() - start_ns) / 1000000.0;
    if (common.json) {
        printf("{");
        wl_print_json_kv_str("workload", "interactive_burst", false);
        wl_print_json_kv_u64("touches", touches, false);
        wl_print_json_kv_u64("region_mb", (uint64_t)region_mb, false);
        wl_print_json_kv_double("elapsed_ms", elapsed_ms, true);
        printf("}\n");
    } else {
        printf("interactive_burst region_mb=%d active_ms=%d idle_ms=%d duration_sec=%d touches=%" PRIu64 " elapsed_ms=%.3f\n",
               region_mb,
               active_ms,
               idle_ms,
               common.duration_sec,
               touches,
               elapsed_ms);
    }

    free(buf);
    return 0;
}
