#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "swap_probe.skel.h"

static volatile sig_atomic_t stop;

struct swap_probe_stats {
    __u64 kswapd_wake;
    __u64 kswapd_sleep;
    __u64 direct_begin;
    __u64 direct_end;
    __u64 reclaim_pages;
    __u64 write_folio;
    __u32 last_pid;
    char last_comm[16];
};

static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void print_delta(const struct swap_probe_stats *curr, const struct swap_probe_stats *prev)
{
    time_t now;

    now = time(NULL);
    printf(
        "swap_probe ts=%ld kswapd_wake=%llu kswapd_sleep=%llu "
        "direct_begin=%llu direct_end=%llu reclaim_pages=%llu write_folio=%llu "
        "last_pid=%u last_comm=%s\n",
        now,
        (unsigned long long)(curr->kswapd_wake - prev->kswapd_wake),
        (unsigned long long)(curr->kswapd_sleep - prev->kswapd_sleep),
        (unsigned long long)(curr->direct_begin - prev->direct_begin),
        (unsigned long long)(curr->direct_end - prev->direct_end),
        (unsigned long long)(curr->reclaim_pages - prev->reclaim_pages),
        (unsigned long long)(curr->write_folio - prev->write_folio),
        curr->last_pid,
        curr->last_comm
    );
}

int main(void)
{
    struct swap_probe_bpf *skel;
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    struct swap_probe_stats curr = {0};
    struct swap_probe_stats prev = {0};
    __u32 key = 0;
    int map_fd;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    err = setrlimit(RLIMIT_MEMLOCK, &rlim);
    if (err) {
        perror("failed to increase memlock rlimit");
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    skel = swap_probe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton (try running as root)\n");
        return 1;
    }

    err = swap_probe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF skeleton: %d\n", err);
        swap_probe_bpf__destroy(skel);
        return 1;
    }

    map_fd = bpf_map__fd(skel->maps.stats_map);
    if (map_fd < 0) {
        fprintf(stderr, "failed to get stats map fd\n");
        swap_probe_bpf__destroy(skel);
        return 1;
    }

    printf("attached. printing 1s swap/reclaim deltas (stdout)\n");
    printf(
        "fields: ts, kswapd_wake, kswapd_sleep, direct_begin, direct_end, "
        "reclaim_pages, write_folio, last_pid, last_comm\n"
    );
    printf("press Ctrl+C to exit...\n");

    while (!stop) {
        sleep(1);

        memset(&curr, 0, sizeof(curr));
        err = bpf_map_lookup_elem(map_fd, &key, &curr);
        if (err) {
            fprintf(stderr, "bpf_map_lookup_elem failed: %s\n", strerror(errno));
            continue;
        }

        print_delta(&curr, &prev);
        prev = curr;
        fflush(stdout);
    }

    swap_probe_bpf__destroy(skel);
    return 0;
}
