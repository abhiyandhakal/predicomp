#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "proc_create.skel.h"

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static const char *trace_pipe_path(void)
{
    if (access("/sys/kernel/tracing/trace_pipe", R_OK) == 0) {
        return "/sys/kernel/tracing/trace_pipe";
    }

    if (access("/sys/kernel/debug/tracing/trace_pipe", R_OK) == 0) {
        return "/sys/kernel/debug/tracing/trace_pipe";
    }

    return "/sys/kernel/tracing/trace_pipe";
}

int main(void)
{
    struct proc_create_bpf *skel;
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    err = setrlimit(RLIMIT_MEMLOCK, &rlim);
    if (err) {
        perror("failed to increase memlock rlimit");
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    skel = proc_create_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton (try running as root)\n");
        return 1;
    }

    err = proc_create_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach BPF skeleton: %d\n", err);
        proc_create_bpf__destroy(skel);
        return 1;
    }

    printf("attached. run: sudo cat %s\n", trace_pipe_path());
    printf("press Ctrl+C to exit...\n");

    while (!stop) {
        sleep(1);
    }

    proc_create_bpf__destroy(skel);
    return 0;
}
