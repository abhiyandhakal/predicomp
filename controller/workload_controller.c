#define _POSIX_C_SOURCE 200809L

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "workload_control_protocol.h"
#include "proc_lifecycle_event.h"
#include "proc_lifecycle.skel.h"

#define DEFAULT_DELAY_SEC 10
#define DEFAULT_HASH_CAP 4096
#define HASH_MAX_LOAD_PCT 70

enum slot_state {
    SLOT_EMPTY = 0,
    SLOT_USED = 1,
    SLOT_TOMBSTONE = 2,
};

struct tracked_proc {
    pid_t pid;
    uint32_t generation;
    uint64_t exec_event_ns;
    uint64_t exit_event_ns;
    uint64_t deadline_ns;
    uint64_t controller_seen_ns;
    uint64_t compress_request_ns;
    uint64_t compress_ack_ns;
    pid_t parent_pid_last_seen;
    pid_t lineage_root_pid;
    char comm[PROC_LIFECYCLE_COMM_LEN];
    char workload_name[WL_CONTROLLER_WORKLOAD_NAME_LEN];
    int enrolled;
    int use_mem_arena;
    int compress_sent;
    int compress_ack;
    int exited;
    int missed_due_to_no_enroll;
    int csv_flushed;
    uint32_t arena_cap_mb;
    uint32_t arena_min_savings_pct;
    uint32_t region_mb;
    uint64_t trigger_count;
    uint64_t total_input_bytes_attempted;
    uint64_t chunks_admitted;
    uint64_t logical_input_bytes;
    uint64_t compressed_bytes_live;
    uint64_t pool_bytes_live;
    uint64_t pool_bytes_free;
    uint64_t pool_compactions;
    uint64_t compress_ops;
    uint64_t decompress_ops;
    uint64_t evictions_lru;
    uint64_t incompressible_chunks;
};

struct pid_table_slot {
    enum slot_state state;
    struct tracked_proc proc;
};

struct pid_table {
    struct pid_table_slot *slots;
    size_t cap;
    size_t used;
    size_t tombstones;
};

struct timer_item {
    uint64_t deadline_ns;
    pid_t pid;
    uint32_t generation;
};

struct timer_heap {
    struct timer_item *items;
    size_t len;
    size_t cap;
};

struct controller_state {
    struct proc_lifecycle_bpf *skel;
    struct ring_buffer *rb;
    int uds_fd;
    char sock_path[PATH_MAX];
    FILE *csv_fp;
    struct pid_table table;
    struct timer_heap heap;
    uint64_t delay_ns;
    int verbose;
};

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t hash_u32(uint32_t x)
{
    uint64_t v = x;

    v ^= v >> 33;
    v *= 0xff51afd7ed558ccdULL;
    v ^= v >> 33;
    v *= 0xc4ceb9fe1a85ec53ULL;
    v ^= v >> 33;
    return v;
}

static int pid_table_init(struct pid_table *t, size_t cap)
{
    t->slots = calloc(cap, sizeof(*t->slots));
    if (t->slots == NULL) {
        return -1;
    }
    t->cap = cap;
    t->used = 0;
    t->tombstones = 0;
    return 0;
}

static void pid_table_destroy(struct pid_table *t)
{
    free(t->slots);
    memset(t, 0, sizeof(*t));
}

static struct pid_table_slot *pid_table_find_slot(struct pid_table *t, pid_t pid)
{
    size_t start = (size_t)(hash_u32((uint32_t)pid) % t->cap);

    for (size_t i = 0; i < t->cap; i++) {
        struct pid_table_slot *slot = &t->slots[(start + i) % t->cap];

        if (slot->state == SLOT_EMPTY) {
            return NULL;
        }
        if (slot->state == SLOT_USED && slot->proc.pid == pid) {
            return slot;
        }
    }
    return NULL;
}

static int pid_table_rehash(struct pid_table *t, size_t new_cap)
{
    struct pid_table_slot *old_slots = t->slots;
    size_t old_cap = t->cap;
    struct pid_table new_table;

    memset(&new_table, 0, sizeof(new_table));
    if (pid_table_init(&new_table, new_cap) != 0) {
        return -1;
    }

    for (size_t i = 0; i < old_cap; i++) {
        struct pid_table_slot *old = &old_slots[i];

        if (old->state != SLOT_USED) {
            continue;
        }

        size_t start = (size_t)(hash_u32((uint32_t)old->proc.pid) % new_table.cap);
        for (size_t j = 0; j < new_table.cap; j++) {
            struct pid_table_slot *dst = &new_table.slots[(start + j) % new_table.cap];

            if (dst->state == SLOT_EMPTY) {
                dst->state = SLOT_USED;
                dst->proc = old->proc;
                new_table.used++;
                break;
            }
        }
    }

    free(old_slots);
    *t = new_table;
    return 0;
}

static int pid_table_maybe_grow(struct pid_table *t)
{
    size_t load_pct;

    if (t->cap == 0) {
        return -1;
    }

    load_pct = ((t->used + t->tombstones) * 100U) / t->cap;
    if (load_pct < HASH_MAX_LOAD_PCT) {
        return 0;
    }

    return pid_table_rehash(t, t->cap * 2U);
}

static struct tracked_proc *pid_table_get_or_insert(struct pid_table *t, pid_t pid)
{
    size_t start;
    struct pid_table_slot *first_tomb = NULL;

    if (pid_table_maybe_grow(t) != 0) {
        return NULL;
    }

    start = (size_t)(hash_u32((uint32_t)pid) % t->cap);

    for (size_t i = 0; i < t->cap; i++) {
        struct pid_table_slot *slot = &t->slots[(start + i) % t->cap];

        if (slot->state == SLOT_USED && slot->proc.pid == pid) {
            return &slot->proc;
        }
        if (slot->state == SLOT_TOMBSTONE && first_tomb == NULL) {
            first_tomb = slot;
            continue;
        }
        if (slot->state == SLOT_EMPTY) {
            struct pid_table_slot *dst = first_tomb != NULL ? first_tomb : slot;

            if (dst->state == SLOT_TOMBSTONE) {
                t->tombstones--;
            }
            memset(&dst->proc, 0, sizeof(dst->proc));
            dst->state = SLOT_USED;
            dst->proc.pid = pid;
            dst->proc.generation = 1;
            t->used++;
            return &dst->proc;
        }
    }

    return NULL;
}

static void pid_table_erase_if_terminal(struct pid_table *t, struct tracked_proc *proc)
{
    if (proc == NULL) {
        return;
    }
    if (!proc->csv_flushed || !proc->exited) {
        return;
    }

    for (size_t i = 0; i < t->cap; i++) {
        struct pid_table_slot *slot = &t->slots[i];

        if (slot->state == SLOT_USED && &slot->proc == proc) {
            memset(&slot->proc, 0, sizeof(slot->proc));
            slot->state = SLOT_TOMBSTONE;
            t->used--;
            t->tombstones++;
            return;
        }
    }
}

static int timer_heap_push(struct timer_heap *h, struct timer_item item)
{
    if (h->len == h->cap) {
        size_t new_cap = h->cap == 0 ? 128 : h->cap * 2;
        struct timer_item *new_items = realloc(h->items, new_cap * sizeof(*new_items));

        if (new_items == NULL) {
            return -1;
        }
        h->items = new_items;
        h->cap = new_cap;
    }

    h->items[h->len] = item;
    h->len++;

    for (size_t i = h->len - 1; i > 0;) {
        size_t p = (i - 1) / 2;

        if (h->items[p].deadline_ns <= h->items[i].deadline_ns) {
            break;
        }
        struct timer_item tmp = h->items[p];
        h->items[p] = h->items[i];
        h->items[i] = tmp;
        i = p;
    }

    return 0;
}

static int timer_heap_empty(const struct timer_heap *h)
{
    return h->len == 0;
}

static struct timer_item timer_heap_peek(const struct timer_heap *h)
{
    return h->items[0];
}

static struct timer_item timer_heap_pop(struct timer_heap *h)
{
    struct timer_item out = h->items[0];

    h->len--;
    if (h->len == 0) {
        return out;
    }

    h->items[0] = h->items[h->len];

    for (size_t i = 0;;) {
        size_t l = i * 2 + 1;
        size_t r = i * 2 + 2;
        size_t m = i;

        if (l < h->len && h->items[l].deadline_ns < h->items[m].deadline_ns) {
            m = l;
        }
        if (r < h->len && h->items[r].deadline_ns < h->items[m].deadline_ns) {
            m = r;
        }
        if (m == i) {
            break;
        }
        struct timer_item tmp = h->items[i];
        h->items[i] = h->items[m];
        h->items[m] = tmp;
        i = m;
    }

    return out;
}

static void timer_heap_destroy(struct timer_heap *h)
{
    free(h->items);
    memset(h, 0, sizeof(*h));
}

static void csv_write_header(FILE *fp)
{
    fprintf(fp,
            "pid,generation,comm,workload_name,enrolled,use_mem_arena,exec_event_ns,deadline_ns,"
            "exit_event_ns,parent_pid_last_seen,lineage_root_pid,compress_sent,compress_ack,"
            "exited,missed_due_to_no_enroll,compress_request_ns,"
            "compress_ack_ns,compress_latency_ms,trigger_count,arena_cap_mb,arena_min_savings_pct,"
            "region_mb,total_input_bytes_attempted,chunks_admitted,logical_input_bytes,"
            "compressed_bytes_live,pool_bytes_live,pool_bytes_free,pool_compactions,compress_ops,"
            "decompress_ops,evictions_lru,incompressible_chunks\n");
    fflush(fp);
}

static void csv_write_row(FILE *fp, const struct tracked_proc *p)
{
    double latency_ms = 0.0;

    if (p->compress_request_ns != 0 && p->compress_ack_ns >= p->compress_request_ns) {
        latency_ms = (double)(p->compress_ack_ns - p->compress_request_ns) / 1000000.0;
    }

    fprintf(fp,
            "%d,%u,%s,%s,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%d,%d,%d,%d,%d,%d,%" PRIu64
            ",%" PRIu64 ",%.3f,%" PRIu64 ",%u,%u,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
            ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
            p->pid,
            p->generation,
            p->comm,
            p->workload_name,
            p->enrolled,
            p->use_mem_arena,
            p->exec_event_ns,
            p->deadline_ns,
            p->exit_event_ns,
            p->parent_pid_last_seen,
            p->lineage_root_pid,
            p->compress_sent,
            p->compress_ack,
            p->exited,
            p->missed_due_to_no_enroll,
            p->compress_request_ns,
            p->compress_ack_ns,
            latency_ms,
            p->trigger_count,
            p->arena_cap_mb,
            p->arena_min_savings_pct,
            p->region_mb,
            p->total_input_bytes_attempted,
            p->chunks_admitted,
            p->logical_input_bytes,
            p->compressed_bytes_live,
            p->pool_bytes_live,
            p->pool_bytes_free,
            p->pool_compactions,
            p->compress_ops,
            p->decompress_ops,
            p->evictions_lru,
            p->incompressible_chunks);
    fflush(fp);
}

static void maybe_flush_csv_row(struct controller_state *st, struct tracked_proc *p)
{
    if (st->csv_fp == NULL || p == NULL || p->csv_flushed) {
        return;
    }
    if (!p->exited) {
        return;
    }
    csv_write_row(st->csv_fp, p);
    p->csv_flushed = 1;
}

static void log_proc(const char *tag, const struct tracked_proc *p)
{
    printf("%s pid=%d gen=%u comm=%s workload=%s enrolled=%d sent=%d ack=%d exited=%d missed=%d\n",
           tag,
           p->pid,
           p->generation,
           p->comm[0] != '\0' ? p->comm : "-",
           p->workload_name[0] != '\0' ? p->workload_name : "-",
           p->enrolled,
           p->compress_sent,
           p->compress_ack,
           p->exited,
           p->missed_due_to_no_enroll);
}

static void tracked_proc_reset_for_exec(struct tracked_proc *p, const struct proc_lifecycle_event *ev, uint64_t delay_ns)
{
    int preserve_enrolled = p->enrolled;
    int preserve_use_mem_arena = p->use_mem_arena;
    char preserve_workload[WL_CONTROLLER_WORKLOAD_NAME_LEN];
    uint32_t preserve_cap = p->arena_cap_mb;
    uint32_t preserve_min_savings = p->arena_min_savings_pct;
    uint32_t preserve_region_mb = p->region_mb;
    pid_t preserve_parent = p->parent_pid_last_seen;
    pid_t preserve_root = p->lineage_root_pid;

    memcpy(preserve_workload, p->workload_name, sizeof(preserve_workload));

    if (p->exec_event_ns != 0 || p->exited || p->compress_sent || p->compress_ack) {
        p->generation++;
    }

    memset(p->comm, 0, sizeof(p->comm));
    memcpy(p->comm, ev->comm, sizeof(p->comm));

    p->exec_event_ns = ev->ktime_ns;
    p->exit_event_ns = 0;
    p->deadline_ns = ev->ktime_ns + delay_ns;
    p->controller_seen_ns = now_ns();
    p->compress_request_ns = 0;
    p->compress_ack_ns = 0;
    p->compress_sent = 0;
    p->compress_ack = 0;
    p->exited = 0;
    p->missed_due_to_no_enroll = 0;
    p->csv_flushed = 0;
    p->trigger_count = 0;
    p->total_input_bytes_attempted = 0;
    p->chunks_admitted = 0;
    p->logical_input_bytes = 0;
    p->compressed_bytes_live = 0;
    p->pool_bytes_live = 0;
    p->pool_bytes_free = 0;
    p->pool_compactions = 0;
    p->compress_ops = 0;
    p->decompress_ops = 0;
    p->evictions_lru = 0;
    p->incompressible_chunks = 0;
    p->parent_pid_last_seen = preserve_parent;
    p->lineage_root_pid = preserve_root;

    p->enrolled = preserve_enrolled;
    p->use_mem_arena = preserve_use_mem_arena;
    memcpy(p->workload_name, preserve_workload, sizeof(p->workload_name));
    p->arena_cap_mb = preserve_cap;
    p->arena_min_savings_pct = preserve_min_savings;
    p->region_mb = preserve_region_mb;
}

static void handle_fork_event(struct controller_state *st, const struct proc_lifecycle_event *ev)
{
    struct tracked_proc *child;
    struct tracked_proc *parent;
    pid_t root_pid;

    child = pid_table_get_or_insert(&st->table, (pid_t)ev->pid);
    if (child == NULL) {
        fprintf(stderr, "pid table insert failed for fork child pid=%u\n", ev->pid);
        return;
    }

    parent = pid_table_get_or_insert(&st->table, (pid_t)ev->ppid);
    if (parent != NULL && parent->lineage_root_pid == 0 && parent->pid > 0) {
        parent->lineage_root_pid = parent->pid;
    }

    child->parent_pid_last_seen = (pid_t)ev->ppid;
    root_pid = (pid_t)ev->ppid;
    if (parent != NULL && parent->lineage_root_pid > 0) {
        root_pid = parent->lineage_root_pid;
    }
    if (root_pid > 0) {
        child->lineage_root_pid = root_pid;
    }
}

static int handle_exec_event(struct controller_state *st, const struct proc_lifecycle_event *ev)
{
    struct tracked_proc *p;
    struct timer_item item;

    p = pid_table_get_or_insert(&st->table, (pid_t)ev->pid);
    if (p == NULL) {
        fprintf(stderr, "pid table insert failed for pid=%u\n", ev->pid);
        return -1;
    }

    tracked_proc_reset_for_exec(p, ev, st->delay_ns);
    if (p->lineage_root_pid == 0 && p->pid > 0) {
        p->lineage_root_pid = p->pid;
    }

    item.deadline_ns = p->deadline_ns;
    item.pid = p->pid;
    item.generation = p->generation;
    if (timer_heap_push(&st->heap, item) != 0) {
        fprintf(stderr, "timer heap push failed\n");
        return -1;
    }

    if (st->verbose) {
        log_proc("exec", p);
    }
    return 0;
}

static int handle_exit_event(struct controller_state *st, const struct proc_lifecycle_event *ev)
{
    struct pid_table_slot *slot = pid_table_find_slot(&st->table, (pid_t)ev->pid);

    if (slot == NULL) {
        return 0;
    }

    struct tracked_proc *p = &slot->proc;

    if (ev->comm[0] != '\0') {
        memset(p->comm, 0, sizeof(p->comm));
        memcpy(p->comm, ev->comm, sizeof(p->comm));
    }
    p->exited = 1;
    p->exit_event_ns = ev->ktime_ns;

    if (st->verbose) {
        log_proc("exit", p);
    }

    maybe_flush_csv_row(st, p);
    pid_table_erase_if_terminal(&st->table, p);
    return 0;
}

static int on_lifecycle_event(void *ctx, void *data, size_t data_sz)
{
    struct controller_state *st = ctx;
    const struct proc_lifecycle_event *ev = data;

    if (data_sz < sizeof(*ev)) {
        return 0;
    }

    if (ev->type == PROC_LIFECYCLE_EVENT_EXEC) {
        handle_exec_event(st, ev);
        return 0;
    }
    if (ev->type == PROC_LIFECYCLE_EVENT_EXIT) {
        handle_exit_event(st, ev);
        return 0;
    }
    if (ev->type == PROC_LIFECYCLE_EVENT_FORK) {
        handle_fork_event(st, ev);
        return 0;
    }

    return 0;
}

static int open_uds_server(const char *path)
{
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        perror("socket(AF_UNIX)");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "socket path too long: %s\n", path);
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind(controller socket)");
        close(fd);
        return -1;
    }

    return fd;
}

static void handle_enroll_msg(struct controller_state *st, const struct wl_controller_msg_enroll *msg)
{
    struct tracked_proc *p = pid_table_get_or_insert(&st->table, (pid_t)msg->pid);

    if (p == NULL) {
        fprintf(stderr, "pid table insert failed for enroll pid=%u\n", msg->pid);
        return;
    }

    p->enrolled = 1;
    p->use_mem_arena = (int)msg->use_mem_arena;
    p->arena_cap_mb = msg->arena_cap_mb;
    p->arena_min_savings_pct = msg->arena_min_savings_pct;
    p->region_mb = msg->region_mb;
    if (p->lineage_root_pid == 0 && p->pid > 0) {
        p->lineage_root_pid = p->pid;
    }
    memset(p->workload_name, 0, sizeof(p->workload_name));
    memcpy(p->workload_name, msg->workload_name, sizeof(p->workload_name));

    if (st->verbose) {
        log_proc("enroll", p);
    }
}

static void handle_compress_ack_msg(
    struct controller_state *st,
    const struct wl_controller_msg_compress_ack *msg
)
{
    struct pid_table_slot *slot = pid_table_find_slot(&st->table, (pid_t)msg->pid);
    struct tracked_proc *p;

    if (slot == NULL) {
        p = pid_table_get_or_insert(&st->table, (pid_t)msg->pid);
        if (p == NULL) {
            fprintf(stderr, "pid table insert failed for ack pid=%u\n", msg->pid);
            return;
        }
    } else {
        p = &slot->proc;
    }

    p->compress_ack = 1;
    p->compress_ack_ns = msg->event_ns;
    p->trigger_count = msg->trigger_count;
    p->total_input_bytes_attempted = msg->total_input_bytes_attempted;
    p->chunks_admitted = msg->chunks_admitted;
    p->logical_input_bytes = msg->logical_input_bytes;
    p->compressed_bytes_live = msg->compressed_bytes_live;
    p->pool_bytes_live = msg->pool_bytes_live;
    p->pool_bytes_free = msg->pool_bytes_free;
    p->pool_compactions = msg->pool_compactions;
    p->compress_ops = msg->compress_ops;
    p->decompress_ops = msg->decompress_ops;
    p->evictions_lru = msg->evictions_lru;
    p->incompressible_chunks = msg->incompressible_chunks;

    if (p->workload_name[0] == '\0') {
        memcpy(p->workload_name, msg->workload_name, sizeof(p->workload_name));
    }

    if (st->verbose) {
        log_proc("compress_ack", p);
    }
}

static void drain_uds(struct controller_state *st)
{
    unsigned char buf[1024];

    for (;;) {
        ssize_t n = recv(st->uds_fd, buf, sizeof(buf), 0);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            perror("recv(controller socket)");
            return;
        }
        if ((size_t)n < sizeof(uint32_t)) {
            continue;
        }

        uint32_t msg_type;
        memcpy(&msg_type, buf, sizeof(msg_type));

        if (msg_type == WL_CTL_MSG_ENROLL && (size_t)n == sizeof(struct wl_controller_msg_enroll)) {
            handle_enroll_msg(st, (const struct wl_controller_msg_enroll *)buf);
            continue;
        }
        if (msg_type == WL_CTL_MSG_COMPRESS_ACK &&
            (size_t)n == sizeof(struct wl_controller_msg_compress_ack)) {
            handle_compress_ack_msg(st, (const struct wl_controller_msg_compress_ack *)buf);
            continue;
        }

        fprintf(stderr, "ignoring unknown/short controller datagram size=%zd type=%u\n", n, msg_type);
    }
}

static void process_due_timers(struct controller_state *st)
{
    uint64_t now = now_ns();

    while (!timer_heap_empty(&st->heap)) {
        struct timer_item top = timer_heap_peek(&st->heap);
        struct pid_table_slot *slot;
        struct tracked_proc *p;

        if (top.deadline_ns > now) {
            break;
        }

        (void)timer_heap_pop(&st->heap);

        slot = pid_table_find_slot(&st->table, top.pid);
        if (slot == NULL) {
            continue;
        }
        p = &slot->proc;

        if (p->generation != top.generation) {
            continue;
        }
        if (p->exited || p->compress_sent || p->exec_event_ns == 0) {
            continue;
        }
        if (!p->enrolled || !p->use_mem_arena) {
            p->missed_due_to_no_enroll = 1;
            if (st->verbose) {
                log_proc("deadline_missed_no_enroll", p);
            }
            continue;
        }

        if (kill(p->pid, SIGUSR1) != 0) {
            if (errno == ESRCH) {
                p->exited = 1;
                if (st->verbose) {
                    log_proc("signal_esrch", p);
                }
                maybe_flush_csv_row(st, p);
                pid_table_erase_if_terminal(&st->table, p);
                continue;
            }
            perror("kill(SIGUSR1)");
            continue;
        }

        p->compress_sent = 1;
        p->compress_request_ns = now_ns();

        if (st->verbose) {
            log_proc("compress_signal_sent", p);
        }
    }
}

static int compute_poll_timeout_ms(const struct controller_state *st)
{
    const int max_sleep_ms = 100;

    if (timer_heap_empty(&st->heap)) {
        return max_sleep_ms;
    }

    uint64_t now = now_ns();
    struct timer_item top = timer_heap_peek(&st->heap);

    if (top.deadline_ns <= now) {
        return 0;
    }

    uint64_t diff_ns = top.deadline_ns - now;
    uint64_t diff_ms = diff_ns / 1000000ULL;

    if (diff_ms > (uint64_t)max_sleep_ms) {
        return max_sleep_ms;
    }
    return (int)diff_ms;
}

static void flush_all_csv_rows(struct controller_state *st)
{
    if (st->csv_fp == NULL) {
        return;
    }

    for (size_t i = 0; i < st->table.cap; i++) {
        struct pid_table_slot *slot = &st->table.slots[i];

        if (slot->state != SLOT_USED || slot->proc.csv_flushed) {
            continue;
        }
        csv_write_row(st->csv_fp, &slot->proc);
        slot->proc.csv_flushed = 1;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s [options]\n", prog);
    fprintf(stderr, "  --delay-sec <n>      compression trigger delay after exec (default %d)\n", DEFAULT_DELAY_SEC);
    fprintf(stderr, "  --sock-path <path>   unix datagram socket path (default %s)\n", WL_CONTROLLER_SOCK_DEFAULT);
    fprintf(stderr, "  --csv <path>         write per-process controller CSV\n");
    fprintf(stderr, "  --quiet              disable verbose event logging\n");
}

int main(int argc, char **argv)
{
    struct controller_state st;
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    const char *csv_path = NULL;
    int err = 0;

    memset(&st, 0, sizeof(st));
    st.delay_ns = (uint64_t)DEFAULT_DELAY_SEC * 1000000000ULL;
    st.verbose = 1;
    strncpy(st.sock_path, WL_CONTROLLER_SOCK_DEFAULT, sizeof(st.sock_path) - 1);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--delay-sec") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --delay-sec\n");
                return 2;
            }
            int delay_sec = atoi(argv[++i]);
            if (delay_sec < 0 || delay_sec > 3600) {
                fprintf(stderr, "--delay-sec out of range [0,3600]\n");
                return 2;
            }
            st.delay_ns = (uint64_t)delay_sec * 1000000000ULL;
            continue;
        }
        if (strcmp(argv[i], "--sock-path") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --sock-path\n");
                return 2;
            }
            strncpy(st.sock_path, argv[++i], sizeof(st.sock_path) - 1);
            st.sock_path[sizeof(st.sock_path) - 1] = '\0';
            continue;
        }
        if (strcmp(argv[i], "--csv") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for --csv\n");
                return 2;
            }
            csv_path = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--quiet") == 0) {
            st.verbose = 0;
            continue;
        }
        fprintf(stderr, "unknown arg: %s\n", argv[i]);
        return 2;
    }

    if (csv_path != NULL) {
        st.csv_fp = fopen(csv_path, "w");
        if (st.csv_fp == NULL) {
            perror("fopen(csv)");
            return 1;
        }
        csv_write_header(st.csv_fp);
    }

    if (pid_table_init(&st.table, DEFAULT_HASH_CAP) != 0) {
        fprintf(stderr, "pid table init failed\n");
        err = 1;
        goto out;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        err = 1;
        goto out;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    st.uds_fd = open_uds_server(st.sock_path);
    if (st.uds_fd < 0) {
        err = 1;
        goto out;
    }

    st.skel = proc_lifecycle_bpf__open_and_load();
    if (st.skel == NULL) {
        fprintf(stderr, "failed to open/load proc_lifecycle BPF skeleton (run as root)\n");
        err = 1;
        goto out;
    }

    err = proc_lifecycle_bpf__attach(st.skel);
    if (err != 0) {
        fprintf(stderr, "failed to attach proc_lifecycle BPF skeleton: %d\n", err);
        err = 1;
        goto out;
    }

    st.rb = ring_buffer__new(bpf_map__fd(st.skel->maps.events), on_lifecycle_event, &st, NULL);
    if (st.rb == NULL) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = 1;
        goto out;
    }

    printf("controller running delay_sec=%.3f sock=%s\n",
           (double)st.delay_ns / 1000000000.0,
           st.sock_path);
    printf("press Ctrl+C to exit\n");

    while (!g_stop) {
        int timeout_ms = compute_poll_timeout_ms(&st);
        int poll_err;

        poll_err = ring_buffer__poll(st.rb, timeout_ms);
        if (poll_err < 0 && poll_err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", poll_err);
            err = 1;
            break;
        }

        drain_uds(&st);
        process_due_timers(&st);
    }

out:
    flush_all_csv_rows(&st);

    if (st.rb != NULL) {
        ring_buffer__free(st.rb);
    }
    if (st.skel != NULL) {
        proc_lifecycle_bpf__destroy(st.skel);
    }
    if (st.uds_fd > 0) {
        close(st.uds_fd);
        unlink(st.sock_path);
    }
    if (st.csv_fp != NULL) {
        fclose(st.csv_fp);
    }
    timer_heap_destroy(&st.heap);
    pid_table_destroy(&st.table);

    return err;
}
