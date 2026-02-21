#include "common.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_REGION_MB 512
#define DEFAULT_OPS_PER_SEC 400000
#define PAGE_SIZE 4096

static uint64_t xorshift64(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [options]\n", prog);
    fprintf(stderr, "  --region-mb <n>    region size in MB (default %d)\n", DEFAULT_REGION_MB);
    fprintf(stderr, "  --ops-per-sec <n>  random touches per second (default %d)\n", DEFAULT_OPS_PER_SEC);
    wl_print_common_help();
}

int main(int argc, char **argv)
{
    struct wl_common_opts common;
    int region_mb = DEFAULT_REGION_MB;
    int ops_per_sec = DEFAULT_OPS_PER_SEC;
    uint64_t ops = 0;

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
            region_mb = wl_parse_int_arg("--region-mb", argv[++i], 1, 16384);
            continue;
        }
        if (strcmp(argv[i], "--ops-per-sec") == 0) {
            ops_per_sec = wl_parse_int_arg("--ops-per-sec", argv[++i], 1, 50000000);
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
    size_t page_count = len / PAGE_SIZE;
    if (page_count == 0) {
        fprintf(stderr, "region too small\n");
        return 1;
    }

    char *buf = malloc(len);
    if (buf == NULL) {
        perror("malloc");
        return 1;
    }
    memset(buf, 0, len);

    uint64_t state = common.seed;
    uint64_t start_ns = wl_now_ns();
    uint64_t deadline_ns = start_ns + (uint64_t)common.duration_sec * 1000000000ULL;
    uint64_t interval_ns = 1000000000ULL / (uint64_t)ops_per_sec;

    while (wl_now_ns() < deadline_ns) {
        size_t page_idx = (size_t)(xorshift64(&state) % page_count);
        buf[page_idx * PAGE_SIZE] ^= 1;
        ops++;
        wl_sleep_ns(interval_ns);
    }

    double elapsed_ms = (double)(wl_now_ns() - start_ns) / 1000000.0;
    if (common.json) {
        printf("{");
        wl_print_json_kv_str("workload", "random_touch_heap", false);
        wl_print_json_kv_u64("ops", ops, false);
        wl_print_json_kv_u64("region_mb", (uint64_t)region_mb, false);
        wl_print_json_kv_double("elapsed_ms", elapsed_ms, true);
        printf("}\n");
    } else {
        printf("random_touch_heap region_mb=%d ops_per_sec=%d duration_sec=%d ops=%" PRIu64 " elapsed_ms=%.3f\n",
               region_mb,
               ops_per_sec,
               common.duration_sec,
               ops,
               elapsed_ms);
    }

    free(buf);
    return 0;
}
