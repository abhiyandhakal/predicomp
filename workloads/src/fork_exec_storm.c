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

#define DEFAULT_FORK_RATE 10
#define MAX_FORK_RATE 500

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo)
{
    (void)signo;
    g_stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [options]\n", prog);
    fprintf(stderr, "  --fork-rate <n>   execs/sec per worker (default %d)\n", DEFAULT_FORK_RATE);
    fprintf(stderr, "  --exec-path <p>   executable path (default /bin/true)\n");
    wl_print_common_help();
}

int main(int argc, char **argv)
{
    struct wl_common_opts common;
    int fork_rate = DEFAULT_FORK_RATE;
    const char *exec_path = "/bin/true";
    uint64_t exec_count = 0;

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
        if (strcmp(argv[i], "--exec-path") == 0) {
            exec_path = argv[++i];
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
                execl(exec_path, exec_path, (char *)NULL);
                _exit(1);
            }
            if (pid > 0) {
                exec_count++;
                waitpid(pid, NULL, 0);
            }
        }
        wl_sleep_ns(interval_ns);
    }

    double elapsed_ms = (double)(wl_now_ns() - start_ns) / 1000000.0;
    if (common.json) {
        printf("{");
        wl_print_json_kv_str("workload", "fork_exec_storm", false);
        wl_print_json_kv_u64("execs", exec_count, false);
        wl_print_json_kv_str("exec_path", exec_path, false);
        wl_print_json_kv_double("elapsed_ms", elapsed_ms, true);
        printf("}\n");
    } else {
        printf("fork_exec_storm workers=%d fork_rate=%d exec_path=%s duration_sec=%d execs=%" PRIu64 " elapsed_ms=%.3f\n",
               common.workers,
               fork_rate,
               exec_path,
               common.duration_sec,
               exec_count,
               elapsed_ms);
    }

    return 0;
}
