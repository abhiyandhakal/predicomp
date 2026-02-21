#include "common.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define DEFAULT_MAP_KB 512
#define DEFAULT_OPS_PER_SEC 500
#define PAGE_SIZE 4096

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [options]\n", prog);
    fprintf(stderr, "  --map-kb <n>       bytes per mmap region in KiB (default %d)\n", DEFAULT_MAP_KB);
    fprintf(stderr, "  --ops-per-sec <n>  mmap/munmap ops per second (default %d)\n", DEFAULT_OPS_PER_SEC);
    wl_print_common_help();
}

int main(int argc, char **argv)
{
    struct wl_common_opts common;
    int map_kb = DEFAULT_MAP_KB;
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
        if (strcmp(argv[i], "--map-kb") == 0) {
            map_kb = wl_parse_int_arg("--map-kb", argv[++i], 4, 1048576);
            continue;
        }
        if (strcmp(argv[i], "--ops-per-sec") == 0) {
            ops_per_sec = wl_parse_int_arg("--ops-per-sec", argv[++i], 1, 100000);
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

    size_t len = (size_t)map_kb * 1024UL;
    uint64_t interval_ns = 1000000000ULL / (uint64_t)ops_per_sec;
    uint64_t start_ns = wl_now_ns();
    uint64_t deadline_ns = start_ns + (uint64_t)common.duration_sec * 1000000000ULL;

    while (wl_now_ns() < deadline_ns) {
        char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        for (size_t off = 0; off < len; off += PAGE_SIZE) {
            p[off] = (char)(off & 0xff);
        }
        if (munmap(p, len) != 0) {
            perror("munmap");
            return 1;
        }
        ops++;
        wl_sleep_ns(interval_ns);
    }

    double elapsed_ms = (double)(wl_now_ns() - start_ns) / 1000000.0;
    if (common.json) {
        printf("{");
        wl_print_json_kv_str("workload", "mmap_churn", false);
        wl_print_json_kv_u64("ops", ops, false);
        wl_print_json_kv_u64("map_kb", (uint64_t)map_kb, false);
        wl_print_json_kv_double("elapsed_ms", elapsed_ms, true);
        printf("}\n");
    } else {
        printf("mmap_churn map_kb=%d ops_per_sec=%d duration_sec=%d ops=%" PRIu64 " elapsed_ms=%.3f\n",
               map_kb,
               ops_per_sec,
               common.duration_sec,
               ops,
               elapsed_ms);
    }

    return 0;
}
