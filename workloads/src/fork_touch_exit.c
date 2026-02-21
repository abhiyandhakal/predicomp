#include "common.h"

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_FORK_RATE 20
#define DEFAULT_TOUCH_PAGES 64
#define MAX_FORK_RATE 1000
#define MAX_TOUCH_PAGES 16384
#define PAGE_SIZE 4096

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void touch_pages(int pages)
{
    size_t len = (size_t)pages * PAGE_SIZE;
    char *buf = malloc(len);

    if (buf == NULL) {
        _exit(1);
    }
    for (size_t i = 0; i < len; i += PAGE_SIZE) {
        buf[i] = (char)(i & 0xff);
    }
    free(buf);
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [options]\n", prog);
    fprintf(stderr, "  --fork-rate <n>    forks/sec per worker (default %d)\n", DEFAULT_FORK_RATE);
    fprintf(stderr, "  --touch-pages <n>  pages touched by child (default %d)\n", DEFAULT_TOUCH_PAGES);
    wl_print_common_help();
}

int main(int argc, char **argv)
{
    struct wl_common_opts common;
    int fork_rate = DEFAULT_FORK_RATE;
    int touch_pages_n = DEFAULT_TOUCH_PAGES;
    uint64_t fork_count = 0;

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
        if (strcmp(argv[i], "--fork-rate") == 0) {
            fork_rate = wl_parse_int_arg("--fork-rate", argv[++i], 1, MAX_FORK_RATE);
            continue;
        }
        if (strcmp(argv[i], "--touch-pages") == 0) {
            touch_pages_n = wl_parse_int_arg("--touch-pages", argv[++i], 1, MAX_TOUCH_PAGES);
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

    struct rlimit lim;
    lim.rlim_cur = (rlim_t)(common.workers * 32);
    if (lim.rlim_cur < 4096) {
        lim.rlim_cur = 4096;
    }
    lim.rlim_max = lim.rlim_cur;
    if (setrlimit(RLIMIT_NPROC, &lim) != 0) {
        perror("setrlimit(RLIMIT_NPROC)");
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    uint64_t start_ns = wl_now_ns();
    uint64_t deadline_ns = start_ns + (uint64_t)common.duration_sec * 1000000000ULL;
    uint64_t interval_ns = 1000000000ULL / (uint64_t)fork_rate;

    while (!g_stop && wl_now_ns() < deadline_ns) {
        for (int w = 0; w < common.workers; w++) {
            pid_t pid = fork();
            if (pid == 0) {
                touch_pages(touch_pages_n);
                _exit(0);
            }
            if (pid > 0) {
                fork_count++;
                waitpid(pid, NULL, 0);
            }
        }
        wl_sleep_ns(interval_ns);
    }

    double elapsed_ms = (double)(wl_now_ns() - start_ns) / 1000000.0;
    if (common.json) {
        printf("{");
        wl_print_json_kv_str("workload", "fork_touch_exit", false);
        wl_print_json_kv_u64("forks", fork_count, false);
        wl_print_json_kv_u64("touch_pages", (uint64_t)touch_pages_n, false);
        wl_print_json_kv_double("elapsed_ms", elapsed_ms, true);
        printf("}\n");
    } else {
        printf("fork_touch_exit workers=%d fork_rate=%d touch_pages=%d duration_sec=%d forks=%" PRIu64 " elapsed_ms=%.3f\n",
               common.workers,
               fork_rate,
               touch_pages_n,
               common.duration_sec,
               fork_count,
               elapsed_ms);
    }

    return 0;
}
