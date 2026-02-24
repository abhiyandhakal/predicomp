#include "protocol.h"
#include "pager_damon.h"
#include "mem_arena_codec.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/userfaultfd.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SZ 4096UL
#define DEFAULT_SOCK_PATH "/tmp/predicomp-pager.sock"

#ifndef SYS_pidfd_open
#ifdef __NR_pidfd_open
#define SYS_pidfd_open __NR_pidfd_open
#endif
#endif

#ifndef SYS_process_madvise
#ifdef __NR_process_madvise
#define SYS_process_madvise __NR_process_madvise
#endif
#endif

enum page_state {
    PAGE_STATE_PRESENT = 0,
    PAGE_STATE_COMPRESSED = 1,
};

struct cfg {
    char sock_path[108];
    char csv_path[PATH_MAX];
    int csv_enabled;
    uint64_t soft_cap_bytes;
    uint32_t damon_sample_us;
    uint32_t damon_aggr_us;
    uint32_t damon_update_us;
    uint32_t damon_read_tick_ms;
    uint32_t damon_nr_regions_min;
    uint32_t damon_nr_regions_max;
    uint32_t cold_age_ms;
    uint32_t latency_sample_step;
    uint32_t latency_max_samples;
    FILE *csv_fp;
    int verbose;
};

struct range_desc {
    uint32_t id;
    uint32_t flags;
    uint64_t start;
    uint64_t len;
};

struct page_entry {
    uintptr_t addr;
    uint32_t range_id;
    uint32_t state;
    uint32_t blob_len;
    uint32_t last_damon_accesses;
    uint64_t last_damon_age;
    uint64_t last_damon_seen_ns;
    uint64_t last_compress_ns;
    uint64_t last_restore_ns;
    uint8_t *blob;
    uint8_t is_cold;
    uint8_t wp_active;
    uint8_t dirty;
    uint8_t reserved;
};

struct map_slot {
    uintptr_t key;
    uint32_t idx_plus1;
};

struct latency_collector {
    uint64_t *vals;
    size_t count;
    size_t cap;
};

struct latency_stats {
    uint64_t samples;
    uint64_t p50_ns;
    uint64_t p95_ns;
    uint64_t p99_ns;
    uint64_t max_ns;
    double avg_ns;
};

enum latency_kind {
    LAT_COMPRESS_WALL = 0,
    LAT_COMPRESS_CPU = 1,
    LAT_RESTORE_WALL = 2,
    LAT_RESTORE_CPU = 3,
    LAT_RESTORE_CODEC_WALL = 4,
    LAT_FAULT_ALL = 5,
    LAT_FAULT_MISSING = 6,
    LAT_FAULT_WP = 7,
    LAT_CLIENT_EVICT_RPC = 8,
    LAT_PROCESS_MADVISE = 9,
    LAT_KIND_COUNT = 10,
};

struct metrics {
    uint64_t ranges_registered;
    uint64_t pages_tracked;
    uint64_t damon_setup_ok;
    uint64_t damon_setup_fail;
    uint64_t damon_snapshots_total;
    uint64_t damon_regions_total;
    uint64_t damon_read_errors;
    uint64_t pages_cold_marked;
    uint64_t pages_wp_armed;
    uint64_t compress_attempts;
    uint64_t compress_success;
    uint64_t compress_skips_notbeneficial;
    uint64_t compress_read_failures;
    uint64_t compress_evict_failures;
    uint64_t compress_bytes_in;
    uint64_t compress_bytes_out;
    uint64_t store_bytes_live;
    uint64_t store_bytes_peak;
    uint64_t soft_cap_warnings;
    uint64_t faults_missing_total;
    uint64_t faults_wp_total;
    uint64_t faults_unexpected_total;
    uint64_t restore_success;
    uint64_t restore_failures;
    uint64_t uffdio_copy_failures;
    uint64_t uffdio_wp_failures;
    uint64_t uffdio_zeropage_failures;
    uint64_t process_madvise_failures;
    uint64_t process_madvise_unsupported;
    uint64_t client_evict_success;
    uint64_t client_evict_failures;
    uint64_t compress_wp_only_fallback;
    uint64_t session_start_ns;
    uint64_t session_end_ns;
    uint64_t session_wall_ns;
    uint64_t control_thread_cpu_ns;
    uint64_t bg_thread_cpu_ns;
    uint64_t fault_thread_cpu_ns;
    uint64_t compress_cpu_ns_total;
    uint64_t compress_cpu_ns_max;
    uint64_t restore_cpu_ns_total;
    uint64_t restore_cpu_ns_max;
    uint64_t restore_codec_wall_ns_total;
    uint64_t restore_codec_wall_ns_max;
    uint64_t restore_codec_cpu_ns_total;
    uint64_t restore_codec_cpu_ns_max;
    uint64_t restore_missing_count;
    uint64_t restore_wp_count;
    uint64_t fault_missing_service_ns_total;
    uint64_t fault_missing_service_ns_max;
    uint64_t fault_wp_service_ns_total;
    uint64_t fault_wp_service_ns_max;
    uint64_t client_evict_rpc_ns_total;
    uint64_t client_evict_rpc_ns_max;
    uint64_t process_madvise_ns_total;
    uint64_t process_madvise_ns_max;
    uint64_t latency_samples_dropped;
    uint64_t latency_collector_ooms;
    uint64_t compress_ns_total;
    uint64_t restore_ns_total;
    uint64_t fault_service_ns_total;
    uint64_t fault_service_ns_max;
};

struct session {
    int active;
    int stop;
    int client_fd;
    int rpc_fd;
    int uffd;
    int evict_client_rpc_mode;
    int pidfd;
    pid_t pid;
    pthread_t fault_thread;
    pthread_t bg_thread;
    pthread_mutex_t mu;
    struct cfg cfg;
    struct pager_damon damon;
    struct pager_damon_config damon_cfg;
    struct range_desc *ranges;
    size_t nr_ranges;
    size_t ranges_cap;
    struct page_entry *pages;
    size_t nr_pages;
    struct map_slot *map;
    size_t map_cap;
    uint64_t region_min;
    uint64_t region_max;
    struct metrics m;
    struct latency_collector lat_lc[LAT_KIND_COUNT];
    struct latency_stats lat_stats[LAT_KIND_COUNT];
    uint64_t lat_seen[LAT_KIND_COUNT];
    int evict_wp_only_mode;
    int logged_process_madvise_errno;
};

static volatile sig_atomic_t g_stop = 0;

static void csv_write_header(FILE *fp);
static void csv_write_session_row(FILE *fp, const struct session *s);

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t thread_cpu_now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void lc_init(struct latency_collector *lc)
{
    lc->vals = NULL;
    lc->count = 0;
    lc->cap = 0;
}

static void lc_free(struct latency_collector *lc)
{
    free(lc->vals);
    lc->vals = NULL;
    lc->count = 0;
    lc->cap = 0;
}

static int lc_push_bounded(struct latency_collector *lc, uint64_t ns, size_t max_samples)
{
    uint64_t *next;
    size_t next_cap;

    if (max_samples > 0 && lc->count >= max_samples) {
        errno = ENOSPC;
        return -1;
    }
    if (lc->count == lc->cap) {
        next_cap = (lc->cap == 0) ? 1024U : lc->cap * 2U;
        if (max_samples > 0 && next_cap > max_samples) {
            next_cap = max_samples;
        }
        if (next_cap == lc->cap) {
            errno = ENOSPC;
            return -1;
        }
        next = realloc(lc->vals, next_cap * sizeof(*next));
        if (next == NULL) {
            return -1;
        }
        lc->vals = next;
        lc->cap = next_cap;
    }
    lc->vals[lc->count++] = ns;
    return 0;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t va;
    uint64_t vb;

    va = *(const uint64_t *)a;
    vb = *(const uint64_t *)b;
    if (va < vb) {
        return -1;
    }
    if (va > vb) {
        return 1;
    }
    return 0;
}

static uint64_t percentile_u64(const uint64_t *vals, size_t n, int pct)
{
    size_t idx;

    if (n == 0) {
        return 0;
    }
    if (pct <= 0) {
        return vals[0];
    }
    if (pct >= 100) {
        return vals[n - 1];
    }
    idx = (size_t)(((uint64_t)(n - 1) * (uint64_t)pct + 99U) / 100U);
    if (idx >= n) {
        idx = n - 1;
    }
    return vals[idx];
}

static int finalize_latency(const struct latency_collector *lc, struct latency_stats *out)
{
    uint64_t *tmp;
    size_t i;
    long double sum;

    memset(out, 0, sizeof(*out));
    if (lc->count == 0) {
        return 0;
    }
    tmp = malloc(lc->count * sizeof(*tmp));
    if (tmp == NULL) {
        return -1;
    }
    memcpy(tmp, lc->vals, lc->count * sizeof(*tmp));
    qsort(tmp, lc->count, sizeof(*tmp), cmp_u64);
    out->samples = (uint64_t)lc->count;
    out->max_ns = tmp[lc->count - 1];
    out->p50_ns = percentile_u64(tmp, lc->count, 50);
    out->p95_ns = percentile_u64(tmp, lc->count, 95);
    out->p99_ns = percentile_u64(tmp, lc->count, 99);
    sum = 0.0;
    for (i = 0; i < lc->count; i++) {
        sum += (long double)lc->vals[i];
    }
    out->avg_ns = (double)(sum / (long double)lc->count);
    free(tmp);
    return 0;
}

static void maybe_sample_latency(struct session *s, enum latency_kind kind, uint64_t ns)
{
    uint64_t seen;
    uint32_t step;

    if (s == NULL || kind < 0 || kind >= LAT_KIND_COUNT) {
        return;
    }
    seen = ++s->lat_seen[kind];
    step = s->cfg.latency_sample_step == 0 ? 1U : s->cfg.latency_sample_step;
    if ((seen % step) != 0) {
        return;
    }
    if (lc_push_bounded(&s->lat_lc[kind], ns, (size_t)s->cfg.latency_max_samples) != 0) {
        s->m.latency_samples_dropped++;
        if (errno != ENOSPC) {
            s->m.latency_collector_ooms++;
        }
    }
}

static void on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void log_msg(const struct session *s, const char *fmt, ...)
{
    va_list ap;

    if (s != NULL && !s->cfg.verbose) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static int send_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p;

    p = (const unsigned char *)buf;
    while (len > 0) {
        ssize_t n;

        n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int recv_full(int fd, void *buf, size_t len)
{
    unsigned char *p;

    p = (unsigned char *)buf;
    while (len > 0) {
        ssize_t n;

        n = recv(fd, p, len, 0);
        if (n == 0) {
            errno = ECONNRESET;
            return -1;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int send_ack(int fd, uint32_t ack_type)
{
    struct predicomp_msg_ack ack;

    memset(&ack, 0, sizeof(ack));
    ack.hdr.type = PREDICOMP_MSG_ACK;
    ack.hdr.size = sizeof(ack);
    ack.ack_type = ack_type;
    ack.status = 0;
    return send_all(fd, &ack, sizeof(ack));
}

static int send_error_msg(int fd, uint32_t for_type, int err_no, const char *msg)
{
    struct predicomp_msg_error e;

    memset(&e, 0, sizeof(e));
    e.hdr.type = PREDICOMP_MSG_ERROR;
    e.hdr.size = sizeof(e);
    e.for_type = for_type;
    e.err_no = err_no;
    if (msg != NULL) {
        snprintf(e.message, sizeof(e.message), "%s", msg);
    }
    return send_all(fd, &e, sizeof(e));
}

static uint64_t hash_addr(uintptr_t addr)
{
    uint64_t x;

    x = (uint64_t)addr >> 12;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static int map_init(struct session *s, size_t want_entries)
{
    size_t cap;

    cap = 1;
    while (cap < want_entries * 2 + 1) {
        cap <<= 1;
    }
    s->map = calloc(cap, sizeof(*s->map));
    if (s->map == NULL) {
        return -1;
    }
    s->map_cap = cap;
    return 0;
}

static int map_put(struct session *s, uintptr_t key, uint32_t idx)
{
    size_t mask;
    size_t pos;

    if (s->map == NULL || s->map_cap == 0) {
        errno = EINVAL;
        return -1;
    }
    mask = s->map_cap - 1;
    pos = (size_t)(hash_addr(key) & mask);
    while (s->map[pos].idx_plus1 != 0) {
        if (s->map[pos].key == key) {
            s->map[pos].idx_plus1 = idx + 1;
            return 0;
        }
        pos = (pos + 1) & mask;
    }
    s->map[pos].key = key;
    s->map[pos].idx_plus1 = idx + 1;
    return 0;
}

static struct page_entry *map_get_page(struct session *s, uintptr_t key)
{
    size_t mask;
    size_t pos;

    if (s->map == NULL || s->map_cap == 0) {
        return NULL;
    }
    mask = s->map_cap - 1;
    pos = (size_t)(hash_addr(key) & mask);
    while (s->map[pos].idx_plus1 != 0) {
        if (s->map[pos].key == key) {
            return &s->pages[s->map[pos].idx_plus1 - 1];
        }
        pos = (pos + 1) & mask;
    }
    return NULL;
}

static int ensure_ranges_cap(struct session *s, size_t need)
{
    struct range_desc *tmp;
    size_t new_cap;

    if (need <= s->ranges_cap) {
        return 0;
    }
    new_cap = s->ranges_cap == 0 ? 4 : s->ranges_cap;
    while (new_cap < need) {
        new_cap *= 2;
    }
    tmp = realloc(s->ranges, new_cap * sizeof(*tmp));
    if (tmp == NULL) {
        return -1;
    }
    s->ranges = tmp;
    s->ranges_cap = new_cap;
    return 0;
}

static int add_range(struct session *s, const struct predicomp_msg_range *msg)
{
    struct range_desc *r;

    if (msg->len == 0 || (msg->start % PAGE_SZ) != 0 || (msg->len % PAGE_SZ) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (ensure_ranges_cap(s, s->nr_ranges + 1) != 0) {
        return -1;
    }
    r = &s->ranges[s->nr_ranges++];
    r->id = msg->range_id;
    r->flags = msg->flags;
    r->start = msg->start;
    r->len = msg->len;
    s->m.ranges_registered = s->nr_ranges;
    if (s->region_min == 0 || msg->start < s->region_min) {
        s->region_min = msg->start;
    }
    if (msg->start + msg->len > s->region_max) {
        s->region_max = msg->start + msg->len;
    }
    return 0;
}

static int build_page_table(struct session *s)
{
    size_t i;
    size_t total_pages;
    size_t idx;

    total_pages = 0;
    for (i = 0; i < s->nr_ranges; i++) {
        total_pages += (size_t)(s->ranges[i].len / PAGE_SZ);
    }
    s->pages = calloc(total_pages, sizeof(*s->pages));
    if (s->pages == NULL) {
        return -1;
    }
    if (map_init(s, total_pages) != 0) {
        return -1;
    }

    idx = 0;
    for (i = 0; i < s->nr_ranges; i++) {
        uint64_t off;
        for (off = 0; off < s->ranges[i].len; off += PAGE_SZ) {
            struct page_entry *p;

            p = &s->pages[idx];
            memset(p, 0, sizeof(*p));
            p->addr = (uintptr_t)(s->ranges[i].start + off);
            p->range_id = s->ranges[i].id;
            p->state = PAGE_STATE_PRESENT;
            p->dirty = 0;
            p->last_damon_seen_ns = now_ns();
            if (map_put(s, p->addr, (uint32_t)idx) != 0) {
                return -1;
            }
            idx++;
        }
    }
    s->nr_pages = total_pages;
    s->m.pages_tracked = total_pages;
    return 0;
}

static int pidfd_open_wrap(pid_t pid)
{
#ifdef SYS_pidfd_open
    return (int)syscall(SYS_pidfd_open, pid, 0);
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

static int process_madvise_wrap(int pidfd, void *addr, size_t len, int advice)
{
#ifdef SYS_process_madvise
    struct iovec iov;

    iov.iov_base = addr;
    iov.iov_len = len;
    return (int)syscall(SYS_process_madvise, pidfd, &iov, 1UL, advice, 0UL);
#else
    (void)pidfd;
    (void)addr;
    (void)len;
    (void)advice;
    errno = ENOSYS;
    return -1;
#endif
}

static int uffd_writeprotect_page(struct session *s, uintptr_t addr, int enable)
{
    struct uffdio_writeprotect wp;

    memset(&wp, 0, sizeof(wp));
    wp.range.start = (unsigned long)addr;
    wp.range.len = PAGE_SZ;
    wp.mode = enable ? UFFDIO_WRITEPROTECT_MODE_WP : 0;
    if (ioctl(s->uffd, UFFDIO_WRITEPROTECT, &wp) != 0) {
        s->m.uffdio_wp_failures++;
        return -1;
    }
    return 0;
}

static int recv_start_with_fds(int fd, struct predicomp_msg_start *out_msg, int *out_fds, size_t max_fds, size_t *out_nr_fds)
{
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr hdr;
        unsigned char data[CMSG_SPACE(sizeof(int) * 4)];
    } cbuf;
    struct cmsghdr *cmsg;
    ssize_t n;

    memset(out_msg, 0, sizeof(*out_msg));
    if (out_nr_fds != NULL) {
        *out_nr_fds = 0;
    }
    for (size_t i = 0; i < max_fds; i++) {
        out_fds[i] = -1;
    }
    memset(&msg, 0, sizeof(msg));
    memset(&cbuf, 0, sizeof(cbuf));

    iov.iov_base = out_msg;
    iov.iov_len = sizeof(*out_msg);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.data;
    msg.msg_controllen = sizeof(cbuf.data);

    do {
        n = recvmsg(fd, &msg, MSG_WAITALL);
    } while (n < 0 && errno == EINTR);
    if (n <= 0) {
        if (n == 0) {
            errno = ECONNRESET;
        }
        return -1;
    }
    if ((size_t)n != sizeof(*out_msg)) {
        errno = EPROTO;
        return -1;
    }
    if (out_msg->hdr.type != PREDICOMP_MSG_START || out_msg->hdr.size != sizeof(*out_msg)) {
        errno = EPROTO;
        return -1;
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(int))) {
            size_t data_len;
            size_t nr_fds;

            data_len = cmsg->cmsg_len - CMSG_LEN(0);
            nr_fds = data_len / sizeof(int);
            if (nr_fds > max_fds) {
                nr_fds = max_fds;
            }
            memcpy(out_fds, CMSG_DATA(cmsg), nr_fds * sizeof(int));
            if (out_nr_fds != NULL) {
                *out_nr_fds = nr_fds;
            }
            break;
        }
    }
    if (max_fds == 0 || out_fds[0] < 0) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int client_evict_page_locked(struct session *s, uintptr_t addr, size_t len)
{
    struct predicomp_msg_evict_req req;
    struct predicomp_msg_evict_ack ack;
    uint64_t t0;
    uint64_t dt;

    if (s->rpc_fd < 0) {
        errno = ENOTCONN;
        return -1;
    }
    t0 = now_ns();
    memset(&req, 0, sizeof(req));
    req.hdr.type = PREDICOMP_MSG_EVICT_REQ;
    req.hdr.size = sizeof(req);
    req.addr = (uint64_t)addr;
    req.len = (uint64_t)len;
    req.advice = MADV_DONTNEED;
    if (send_all(s->rpc_fd, &req, sizeof(req)) != 0) {
        return -1;
    }
    if (recv_full(s->rpc_fd, &ack, sizeof(ack)) != 0) {
        return -1;
    }
    if (ack.hdr.type != PREDICOMP_MSG_EVICT_ACK || ack.hdr.size != sizeof(ack) ||
        ack.addr != req.addr || ack.len != req.len) {
        errno = EPROTO;
        return -1;
    }
    if (ack.status != 0) {
        errno = ack.err_no ? ack.err_no : EIO;
        return -1;
    }
    dt = now_ns() - t0;
    s->m.client_evict_rpc_ns_total += dt;
    if (dt > s->m.client_evict_rpc_ns_max) {
        s->m.client_evict_rpc_ns_max = dt;
    }
    maybe_sample_latency(s, LAT_CLIENT_EVICT_RPC, dt);
    return 0;
}

static int zero_fill_fault(struct session *s, uintptr_t addr)
{
    struct uffdio_zeropage zp;

#ifdef UFFDIO_ZEROPAGE
    memset(&zp, 0, sizeof(zp));
    zp.range.start = (unsigned long)addr;
    zp.range.len = PAGE_SZ;
    if (ioctl(s->uffd, UFFDIO_ZEROPAGE, &zp) == 0) {
        return 0;
    }
    s->m.uffdio_zeropage_failures++;
#endif
    {
        unsigned char zeros[PAGE_SZ];
        struct uffdio_copy cp;

        memset(zeros, 0, sizeof(zeros));
        memset(&cp, 0, sizeof(cp));
        cp.src = (unsigned long)zeros;
        cp.dst = (unsigned long)addr;
        cp.len = PAGE_SZ;
        if (ioctl(s->uffd, UFFDIO_COPY, &cp) != 0) {
            s->m.uffdio_copy_failures++;
            return -1;
        }
    }
    return 0;
}

static int handle_missing_fault_locked(struct session *s, struct page_entry *p, uintptr_t addr)
{
    unsigned char pagebuf[PAGE_SZ];
    struct uffdio_copy cp;
    int rc;
    uint64_t t0;
    uint64_t c0;
    uint64_t codec_t0;
    uint64_t codec_c0;
    uint64_t dt;
    uint64_t cpu_dt;
    uint64_t codec_dt;
    uint64_t codec_cpu_dt;

    t0 = now_ns();
    c0 = thread_cpu_now_ns();
    s->m.faults_missing_total++;

    if (p == NULL) {
        s->m.faults_unexpected_total++;
        if (zero_fill_fault(s, addr) != 0) {
            return -1;
        }
        return 0;
    }

    if (p->state == PAGE_STATE_COMPRESSED && p->blob != NULL && p->blob_len > 0) {
        codec_t0 = now_ns();
        codec_c0 = thread_cpu_now_ns();
        rc = mem_arena_lz4_decompress(p->blob, (int)p->blob_len, pagebuf, (int)PAGE_SZ);
        codec_dt = now_ns() - codec_t0;
        codec_cpu_dt = thread_cpu_now_ns() - codec_c0;
        if (rc != (int)PAGE_SZ) {
            s->m.restore_failures++;
            return -1;
        }
        memset(&cp, 0, sizeof(cp));
        cp.src = (unsigned long)pagebuf;
        cp.dst = (unsigned long)addr;
        cp.len = PAGE_SZ;
        if (ioctl(s->uffd, UFFDIO_COPY, &cp) != 0) {
            s->m.uffdio_copy_failures++;
            s->m.restore_failures++;
            return -1;
        }

        s->m.restore_success++;
        dt = now_ns() - t0;
        cpu_dt = thread_cpu_now_ns() - c0;
        s->m.restore_ns_total += dt;
        s->m.restore_cpu_ns_total += cpu_dt;
        s->m.restore_codec_wall_ns_total += codec_dt;
        s->m.restore_codec_cpu_ns_total += codec_cpu_dt;
        if (dt > s->m.restore_cpu_ns_max) {
            /* temp max set below for cpu; keep wall max separate via collectors */
        }
        if (cpu_dt > s->m.restore_cpu_ns_max) {
            s->m.restore_cpu_ns_max = cpu_dt;
        }
        if (codec_dt > s->m.restore_codec_wall_ns_max) {
            s->m.restore_codec_wall_ns_max = codec_dt;
        }
        if (codec_cpu_dt > s->m.restore_codec_cpu_ns_max) {
            s->m.restore_codec_cpu_ns_max = codec_cpu_dt;
        }
        s->m.restore_missing_count++;
        maybe_sample_latency(s, LAT_RESTORE_WALL, dt);
        maybe_sample_latency(s, LAT_RESTORE_CPU, cpu_dt);
        maybe_sample_latency(s, LAT_RESTORE_CODEC_WALL, codec_dt);
        p->last_restore_ns = now_ns();
        if (s->m.store_bytes_live >= p->blob_len) {
            s->m.store_bytes_live -= p->blob_len;
        } else {
            s->m.store_bytes_live = 0;
        }
        free(p->blob);
        p->blob = NULL;
        p->blob_len = 0;
        p->state = PAGE_STATE_PRESENT;
        p->dirty = 0;
        p->is_cold = 0;
        p->wp_active = 0;
        return 0;
    }

    if (zero_fill_fault(s, addr) != 0) {
        s->m.restore_failures++;
        return -1;
    }
    p->state = PAGE_STATE_PRESENT;
    p->dirty = 0;
    p->is_cold = 0;
    p->wp_active = 0;
    return 0;
}

static int handle_wp_fault_locked(struct session *s, struct page_entry *p, uintptr_t addr)
{
    uint64_t t0;
    uint64_t c0;

    s->m.faults_wp_total++;
    if (p == NULL) {
        s->m.faults_unexpected_total++;
        return -1;
    }
    t0 = now_ns();
    c0 = thread_cpu_now_ns();
    if (p->state == PAGE_STATE_COMPRESSED && p->blob != NULL && p->blob_len > 0) {
        unsigned char pagebuf[PAGE_SZ];
        int rc;
        uint64_t codec_t0;
        uint64_t codec_c0;
        uint64_t codec_dt;
        uint64_t codec_cpu_dt;
        uint64_t dt;
        uint64_t cpu_dt;

        codec_t0 = now_ns();
        codec_c0 = thread_cpu_now_ns();
        rc = mem_arena_lz4_decompress(p->blob, (int)p->blob_len, pagebuf, (int)PAGE_SZ);
        codec_dt = now_ns() - codec_t0;
        codec_cpu_dt = thread_cpu_now_ns() - codec_c0;
        if (rc != (int)PAGE_SZ) {
            s->m.restore_failures++;
            return -1;
        }
        s->m.restore_success++;
        dt = now_ns() - t0;
        cpu_dt = thread_cpu_now_ns() - c0;
        s->m.restore_ns_total += dt;
        s->m.restore_cpu_ns_total += cpu_dt;
        s->m.restore_codec_wall_ns_total += codec_dt;
        s->m.restore_codec_cpu_ns_total += codec_cpu_dt;
        if (cpu_dt > s->m.restore_cpu_ns_max) {
            s->m.restore_cpu_ns_max = cpu_dt;
        }
        if (codec_dt > s->m.restore_codec_wall_ns_max) {
            s->m.restore_codec_wall_ns_max = codec_dt;
        }
        if (codec_cpu_dt > s->m.restore_codec_cpu_ns_max) {
            s->m.restore_codec_cpu_ns_max = codec_cpu_dt;
        }
        s->m.restore_wp_count++;
        maybe_sample_latency(s, LAT_RESTORE_WALL, dt);
        maybe_sample_latency(s, LAT_RESTORE_CPU, cpu_dt);
        maybe_sample_latency(s, LAT_RESTORE_CODEC_WALL, codec_dt);
        p->last_restore_ns = now_ns();
        if (s->m.store_bytes_live >= p->blob_len) {
            s->m.store_bytes_live -= p->blob_len;
        } else {
            s->m.store_bytes_live = 0;
        }
        free(p->blob);
        p->blob = NULL;
        p->blob_len = 0;
        p->state = PAGE_STATE_PRESENT;
    }
    if (uffd_writeprotect_page(s, addr, 0) != 0) {
        return -1;
    }
    p->wp_active = 0;
    p->dirty = 1;
    p->is_cold = 0;
    return 0;
}

static void *fault_thread_main(void *arg)
{
    struct session *s;
    struct pollfd pfd;
    uint64_t cpu_start_ns;

    s = (struct session *)arg;
    cpu_start_ns = thread_cpu_now_ns();
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = s->uffd;
    pfd.events = POLLIN;

    while (!g_stop && !s->stop) {
        struct uffd_msg msg;
        int prc;
        uint64_t t0;
        uint64_t dt;

        prc = poll(&pfd, 1, 200);
        if (prc < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (prc == 0) {
            continue;
        }
        if ((pfd.revents & POLLIN) == 0) {
            continue;
        }
        t0 = now_ns();
        if (read(s->uffd, &msg, sizeof(msg)) != (ssize_t)sizeof(msg)) {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            break;
        }
        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            pthread_mutex_lock(&s->mu);
            s->m.faults_unexpected_total++;
            pthread_mutex_unlock(&s->mu);
            continue;
        }

        {
            uintptr_t addr;
            struct page_entry *p;
            int is_wp;

            addr = (uintptr_t)msg.arg.pagefault.address & ~(uintptr_t)(PAGE_SZ - 1);
            is_wp = (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) != 0;

            pthread_mutex_lock(&s->mu);
            p = map_get_page(s, addr);
            if (is_wp) {
                (void)handle_wp_fault_locked(s, p, addr);
            } else {
                (void)handle_missing_fault_locked(s, p, addr);
            }
            dt = now_ns() - t0;
            s->m.fault_service_ns_total += dt;
            if (dt > s->m.fault_service_ns_max) {
                s->m.fault_service_ns_max = dt;
            }
            maybe_sample_latency(s, LAT_FAULT_ALL, dt);
            if (is_wp) {
                s->m.fault_wp_service_ns_total += dt;
                if (dt > s->m.fault_wp_service_ns_max) {
                    s->m.fault_wp_service_ns_max = dt;
                }
                maybe_sample_latency(s, LAT_FAULT_WP, dt);
            } else {
                s->m.fault_missing_service_ns_total += dt;
                if (dt > s->m.fault_missing_service_ns_max) {
                    s->m.fault_missing_service_ns_max = dt;
                }
                maybe_sample_latency(s, LAT_FAULT_MISSING, dt);
            }
            pthread_mutex_unlock(&s->mu);
        }
    }

    pthread_mutex_lock(&s->mu);
    s->m.fault_thread_cpu_ns += thread_cpu_now_ns() - cpu_start_ns;
    pthread_mutex_unlock(&s->mu);
    return NULL;
}

static void apply_damon_snapshot_locked(struct session *s, const struct pager_damon_snapshot *snap)
{
    size_t i;

    if (snap == NULL) {
        return;
    }
    s->m.damon_snapshots_total++;
    s->m.damon_regions_total += snap->count;

    for (i = 0; i < snap->count; i++) {
        uint64_t start;
        uint64_t end;
        uint64_t a;

        start = snap->regions[i].start & ~(PAGE_SZ - 1ULL);
        end = (snap->regions[i].end + PAGE_SZ - 1ULL) & ~(PAGE_SZ - 1ULL);
        if (end <= start) {
            continue;
        }
        for (a = start; a < end; a += PAGE_SZ) {
            struct page_entry *p;

            p = map_get_page(s, (uintptr_t)a);
            if (p == NULL) {
                continue;
            }
            p->last_damon_accesses = (uint32_t)snap->regions[i].nr_accesses;
            p->last_damon_age = snap->regions[i].age;
            if (snap->regions[i].nr_accesses > 0) {
                p->last_damon_seen_ns = now_ns();
                p->is_cold = 0;
            }
        }
    }
}

static void refresh_time_cold_locked(struct session *s, uint64_t now)
{
    uint64_t cold_ns;
    size_t i;

    cold_ns = (uint64_t)s->cfg.cold_age_ms * 1000000ULL;
    if (cold_ns == 0) {
        cold_ns = 500000000ULL;
    }
    for (i = 0; i < s->nr_pages; i++) {
        struct page_entry *p = &s->pages[i];

        if (p->state != PAGE_STATE_PRESENT) {
            continue;
        }
        if (p->wp_active) {
            p->is_cold = 0;
            continue;
        }
        if (now >= p->last_damon_seen_ns + cold_ns) {
            if (!p->is_cold) {
                s->m.pages_cold_marked++;
            }
            p->is_cold = 1;
        }
    }
}

static int maybe_warn_soft_cap_locked(struct session *s)
{
    if (s->cfg.soft_cap_bytes == 0) {
        return 0;
    }
    if (s->m.store_bytes_live > s->cfg.soft_cap_bytes) {
        s->m.soft_cap_warnings++;
        if (s->cfg.verbose) {
            fprintf(stderr,
                    "predicomp_pager: store soft cap exceeded live=%" PRIu64 " cap=%" PRIu64 "\n",
                    s->m.store_bytes_live,
                    s->cfg.soft_cap_bytes);
        }
        return 1;
    }
    return 0;
}

static int finalize_session_latency_stats(struct session *s)
{
    int i;

    for (i = 0; i < LAT_KIND_COUNT; i++) {
        if (finalize_latency(&s->lat_lc[i], &s->lat_stats[i]) != 0) {
            errno = ENOMEM;
            return -1;
        }
    }
    return 0;
}

static int arm_wp_for_candidate_locked(struct session *s, struct page_entry *p)
{
    if (p->state != PAGE_STATE_PRESENT || p->wp_active) {
        return 0;
    }
    if (uffd_writeprotect_page(s, p->addr, 1) != 0) {
        return -1;
    }
    p->wp_active = 1;
    p->dirty = 0;
    s->m.pages_wp_armed++;
    return 1;
}

static int compress_one_page_locked(struct session *s, struct page_entry *p)
{
    unsigned char pagebuf[PAGE_SZ];
    unsigned char compbuf[PAGE_SZ * 2];
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t nread;
    int clen;
    int madv_rc;
    int evict_done;
    uint8_t *new_blob;
    uint64_t t0;
    uint64_t c0;
    uint64_t dt;
    uint64_t cpu_dt;
    uint64_t madv_t0;
    uint64_t madv_dt;

    if (p->state != PAGE_STATE_PRESENT || !p->is_cold || !p->wp_active || p->dirty) {
        return 0;
    }
    if (maybe_warn_soft_cap_locked(s) != 0) {
        return 0;
    }

    t0 = now_ns();
    c0 = thread_cpu_now_ns();
    s->m.compress_attempts++;

    local_iov.iov_base = pagebuf;
    local_iov.iov_len = PAGE_SZ;
    remote_iov.iov_base = (void *)p->addr;
    remote_iov.iov_len = PAGE_SZ;
    nread = process_vm_readv(s->pid, &local_iov, 1, &remote_iov, 1, 0);
    if (nread != (ssize_t)PAGE_SZ) {
        s->m.compress_read_failures++;
        (void)uffd_writeprotect_page(s, p->addr, 0);
        p->wp_active = 0;
        return -1;
    }

    clen = mem_arena_lz4_compress(pagebuf, PAGE_SZ, compbuf, (int)sizeof(compbuf), 1);
    if (clen <= 0 || clen >= (int)PAGE_SZ) {
        s->m.compress_skips_notbeneficial++;
        (void)uffd_writeprotect_page(s, p->addr, 0);
        p->wp_active = 0;
        return 0;
    }

    new_blob = malloc((size_t)clen);
    if (new_blob == NULL) {
        (void)uffd_writeprotect_page(s, p->addr, 0);
        p->wp_active = 0;
        return -1;
    }
    memcpy(new_blob, compbuf, (size_t)clen);

    evict_done = 0;
    if (!s->evict_wp_only_mode && !s->evict_client_rpc_mode) {
        madv_t0 = now_ns();
        madv_rc = process_madvise_wrap(s->pidfd, (void *)p->addr, PAGE_SZ, MADV_DONTNEED);
        madv_dt = now_ns() - madv_t0;
        if (madv_dt > s->m.process_madvise_ns_max) {
            s->m.process_madvise_ns_max = madv_dt;
        }
        s->m.process_madvise_ns_total += madv_dt;
        maybe_sample_latency(s, LAT_PROCESS_MADVISE, madv_dt);
        if (madv_rc < 0) {
            int saved_errno;

            saved_errno = errno;
            s->m.process_madvise_failures++;
            if (!s->logged_process_madvise_errno) {
                log_msg(s,
                        "predicomp_pager: process_madvise(MADV_DONTNEED) failed errno=%d (%s); "
                        "switching to wp-only compressed-page fallback\n",
                        saved_errno,
                        strerror(saved_errno));
                s->logged_process_madvise_errno = 1;
            }
            if (saved_errno == EINVAL || saved_errno == ENOSYS || saved_errno == EOPNOTSUPP) {
                s->m.process_madvise_unsupported++;
                if (s->rpc_fd >= 0) {
                    s->evict_client_rpc_mode = 1;
                    log_msg(s,
                            "predicomp_pager: using client local madvise eviction via rpc fd\n");
                } else {
                    s->evict_wp_only_mode = 1;
                }
            } else {
                free(new_blob);
                s->m.compress_evict_failures++;
                (void)uffd_writeprotect_page(s, p->addr, 0);
                p->wp_active = 0;
                errno = saved_errno;
                return -1;
            }
        } else {
            evict_done = 1;
        }
    }
    if (!evict_done && s->evict_client_rpc_mode) {
        if (client_evict_page_locked(s, p->addr, PAGE_SZ) == 0) {
            evict_done = 1;
            s->m.client_evict_success++;
        } else {
            s->m.client_evict_failures++;
            if (!s->evict_wp_only_mode) {
                log_msg(s,
                        "predicomp_pager: client eviction failed errno=%d (%s); "
                        "falling back to wp-only compressed-page mode\n",
                        errno,
                        strerror(errno));
                s->evict_wp_only_mode = 1;
            }
        }
    }

    if (p->blob != NULL) {
        if (s->m.store_bytes_live >= p->blob_len) {
            s->m.store_bytes_live -= p->blob_len;
        } else {
            s->m.store_bytes_live = 0;
        }
        free(p->blob);
    }
    p->blob = new_blob;
    p->blob_len = (uint32_t)clen;
    p->state = PAGE_STATE_COMPRESSED;
    if (evict_done) {
        p->wp_active = 0;
    } else {
        p->wp_active = 1;
        s->m.compress_wp_only_fallback++;
    }
    p->dirty = 0;
    p->last_compress_ns = now_ns();

    s->m.compress_success++;
    s->m.compress_bytes_in += PAGE_SZ;
    s->m.compress_bytes_out += (uint64_t)clen;
    s->m.store_bytes_live += (uint64_t)clen;
    if (s->m.store_bytes_live > s->m.store_bytes_peak) {
        s->m.store_bytes_peak = s->m.store_bytes_live;
    }
    dt = now_ns() - t0;
    cpu_dt = thread_cpu_now_ns() - c0;
    s->m.compress_ns_total += dt;
    s->m.compress_cpu_ns_total += cpu_dt;
    if (cpu_dt > s->m.compress_cpu_ns_max) {
        s->m.compress_cpu_ns_max = cpu_dt;
    }
    maybe_sample_latency(s, LAT_COMPRESS_WALL, dt);
    maybe_sample_latency(s, LAT_COMPRESS_CPU, cpu_dt);
    return 1;
}

static void *bg_thread_main(void *arg)
{
    struct session *s;
    uint64_t cpu_start_ns;

    s = (struct session *)arg;
    cpu_start_ns = thread_cpu_now_ns();
    while (!g_stop && !s->stop) {
        struct pager_damon_snapshot snap;
        int rc;
        uint64_t tnow;
        size_t i;
        int compressed_this_round;

        tnow = now_ns();
        memset(&snap, 0, sizeof(snap));
        if (s->damon.enabled) {
            rc = pager_damon_poll_snapshot(&s->damon, &s->damon_cfg, tnow, &snap);
            if (rc == 0) {
                pthread_mutex_lock(&s->mu);
                apply_damon_snapshot_locked(s, &snap);
                refresh_time_cold_locked(s, tnow);
                pthread_mutex_unlock(&s->mu);
                pager_damon_snapshot_free(&snap);
            } else if (rc < 0) {
                pthread_mutex_lock(&s->mu);
                s->m.damon_read_errors++;
                pthread_mutex_unlock(&s->mu);
                usleep(200000);
            }
        }

        compressed_this_round = 0;
        pthread_mutex_lock(&s->mu);
        refresh_time_cold_locked(s, tnow);
        for (i = 0; i < s->nr_pages; i++) {
            struct page_entry *p;
            int arm_rc;

            p = &s->pages[i];
            if (!p->is_cold || p->state != PAGE_STATE_PRESENT) {
                continue;
            }
            arm_rc = arm_wp_for_candidate_locked(s, p);
            if (arm_rc < 0) {
                continue;
            }
            if (compress_one_page_locked(s, p) > 0) {
                compressed_this_round++;
                if (compressed_this_round >= 8) {
                    break;
                }
            }
        }
        pthread_mutex_unlock(&s->mu);

        usleep((useconds_t)(s->cfg.damon_read_tick_ms ? s->cfg.damon_read_tick_ms : 200) * 1000U);
    }
    pthread_mutex_lock(&s->mu);
    s->m.bg_thread_cpu_ns += thread_cpu_now_ns() - cpu_start_ns;
    pthread_mutex_unlock(&s->mu);
    return NULL;
}

static void dump_metrics(const struct session *s)
{
    const struct metrics *m;
    double wall_ms;
    double daemon_cpu_pct;
    double bg_cpu_pct;
    double fault_cpu_pct;
    double control_cpu_pct;
    const char *evict_mode;
    const struct latency_stats *fault_all;
    const struct latency_stats *restore_wall;

    m = &s->m;
    wall_ms = (double)m->session_wall_ns / 1000000.0;
    if (m->session_wall_ns > 0) {
        daemon_cpu_pct = 100.0 * (double)(m->control_thread_cpu_ns + m->bg_thread_cpu_ns + m->fault_thread_cpu_ns) /
                         (double)m->session_wall_ns;
        bg_cpu_pct = 100.0 * (double)m->bg_thread_cpu_ns / (double)m->session_wall_ns;
        fault_cpu_pct = 100.0 * (double)m->fault_thread_cpu_ns / (double)m->session_wall_ns;
        control_cpu_pct = 100.0 * (double)m->control_thread_cpu_ns / (double)m->session_wall_ns;
    } else {
        daemon_cpu_pct = 0.0;
        bg_cpu_pct = 0.0;
        fault_cpu_pct = 0.0;
        control_cpu_pct = 0.0;
    }
    if (s->evict_wp_only_mode) {
        evict_mode = "wp_only";
    } else if (s->evict_client_rpc_mode) {
        evict_mode = "client_rpc";
    } else {
        evict_mode = "remote";
    }
    fault_all = &s->lat_stats[LAT_FAULT_ALL];
    restore_wall = &s->lat_stats[LAT_RESTORE_WALL];
    fprintf(stderr,
            "predicomp_pager: session pid=%d ranges=%" PRIu64 " pages=%" PRIu64 " damon_ok=%" PRIu64
            " damon_fail=%" PRIu64 " snapshots=%" PRIu64 " damon_regions=%" PRIu64
            " damon_read_err=%" PRIu64 " cold_marked=%" PRIu64 " wp_armed=%" PRIu64
            " compress_attempts=%" PRIu64 " compress_success=%" PRIu64 " compress_skip=%" PRIu64
            " compress_read_fail=%" PRIu64 " compress_evict_fail=%" PRIu64
            " store_live=%" PRIu64 " store_peak=%" PRIu64 " in=%" PRIu64 " out=%" PRIu64
            " faults_missing=%" PRIu64 " faults_wp=%" PRIu64 " faults_unexpected=%" PRIu64
            " restore_ok=%" PRIu64 " restore_fail=%" PRIu64
            " uffd_copy_fail=%" PRIu64 " uffd_wp_fail=%" PRIu64 " uffd_zero_fail=%" PRIu64
            " process_madvise_fail=%" PRIu64 " process_madvise_unsupported=%" PRIu64
            " client_evict_ok=%" PRIu64 " client_evict_fail=%" PRIu64
            " compress_wp_only_fallback=%" PRIu64
            " evict_mode=%s"
            " session_ms=%.3f cpu_pct_total=%.2f cpu_pct_bg=%.2f cpu_pct_fault=%.2f cpu_pct_ctrl=%.2f"
            " fault_p95=%" PRIu64 " fault_p99=%" PRIu64
            " restore_p95=%" PRIu64 " restore_p99=%" PRIu64
            " fault_ns_total=%" PRIu64 " fault_ns_max=%" PRIu64
            " compress_ns_total=%" PRIu64 " restore_ns_total=%" PRIu64 "\n",
            s->pid,
            m->ranges_registered,
            m->pages_tracked,
            m->damon_setup_ok,
            m->damon_setup_fail,
            m->damon_snapshots_total,
            m->damon_regions_total,
            m->damon_read_errors,
            m->pages_cold_marked,
            m->pages_wp_armed,
            m->compress_attempts,
            m->compress_success,
            m->compress_skips_notbeneficial,
            m->compress_read_failures,
            m->compress_evict_failures,
            m->store_bytes_live,
            m->store_bytes_peak,
            m->compress_bytes_in,
            m->compress_bytes_out,
            m->faults_missing_total,
            m->faults_wp_total,
            m->faults_unexpected_total,
            m->restore_success,
            m->restore_failures,
            m->uffdio_copy_failures,
            m->uffdio_wp_failures,
            m->uffdio_zeropage_failures,
            m->process_madvise_failures,
            m->process_madvise_unsupported,
            m->client_evict_success,
            m->client_evict_failures,
            m->compress_wp_only_fallback,
            evict_mode,
            wall_ms,
            daemon_cpu_pct,
            bg_cpu_pct,
            fault_cpu_pct,
            control_cpu_pct,
            fault_all->p95_ns,
            fault_all->p99_ns,
            restore_wall->p95_ns,
            restore_wall->p99_ns,
            m->fault_service_ns_total,
            m->fault_service_ns_max,
            m->compress_ns_total,
            m->restore_ns_total);
}

static void stop_session(struct session *s)
{
    size_t i;
    int was_active;

    was_active = s->active;
    s->stop = 1;
    if (s->uffd >= 0) {
        close(s->uffd);
        s->uffd = -1;
    }
    if (s->fault_thread) {
        pthread_join(s->fault_thread, NULL);
        s->fault_thread = (pthread_t)0;
    }
    if (s->bg_thread) {
        pthread_join(s->bg_thread, NULL);
        s->bg_thread = (pthread_t)0;
    }
    if (s->damon.enabled) {
        pager_damon_stop(&s->damon);
    }
    if (was_active) {
        s->m.session_end_ns = now_ns();
        if (s->m.session_end_ns >= s->m.session_start_ns) {
            s->m.session_wall_ns = s->m.session_end_ns - s->m.session_start_ns;
        }
        if (finalize_session_latency_stats(s) != 0) {
            s->m.latency_collector_ooms++;
        }
        dump_metrics(s);
        if (s->cfg.csv_fp != NULL) {
            csv_write_session_row(s->cfg.csv_fp, s);
            fflush(s->cfg.csv_fp);
        }
    }

    if (s->pidfd >= 0) {
        close(s->pidfd);
        s->pidfd = -1;
    }
    if (s->client_fd >= 0) {
        close(s->client_fd);
        s->client_fd = -1;
    }
    if (s->rpc_fd >= 0) {
        close(s->rpc_fd);
        s->rpc_fd = -1;
    }
    for (i = 0; i < s->nr_pages; i++) {
        free(s->pages[i].blob);
    }
    free(s->pages);
    s->pages = NULL;
    s->nr_pages = 0;
    free(s->map);
    s->map = NULL;
    s->map_cap = 0;
    free(s->ranges);
    s->ranges = NULL;
    s->nr_ranges = 0;
    s->ranges_cap = 0;
    for (i = 0; i < LAT_KIND_COUNT; i++) {
        lc_free(&s->lat_lc[i]);
        memset(&s->lat_stats[i], 0, sizeof(s->lat_stats[i]));
        s->lat_seen[i] = 0;
    }
    memset(&s->m, 0, sizeof(s->m));
    s->region_min = 0;
    s->region_max = 0;
    s->active = 0;
}

static void reset_session_for_client(struct session *s, int client_fd)
{
    int i;

    memset(s, 0, sizeof(*s));
    s->client_fd = client_fd;
    s->rpc_fd = -1;
    s->uffd = -1;
    s->pidfd = -1;
    pthread_mutex_init(&s->mu, NULL);
    for (i = 0; i < LAT_KIND_COUNT; i++) {
        lc_init(&s->lat_lc[i]);
    }
}

static void destroy_session_struct(struct session *s)
{
    pthread_mutex_destroy(&s->mu);
}

static int start_runtime(struct session *s)
{
    s->pidfd = pidfd_open_wrap(s->pid);
    if (s->pidfd < 0) {
        return -1;
    }
    if (build_page_table(s) != 0) {
        return -1;
    }

    s->damon_cfg.sample_us = s->cfg.damon_sample_us;
    s->damon_cfg.aggr_us = s->cfg.damon_aggr_us;
    s->damon_cfg.update_us = s->cfg.damon_update_us;
    s->damon_cfg.read_tick_ms = s->cfg.damon_read_tick_ms;
    s->damon_cfg.nr_regions_min = s->cfg.damon_nr_regions_min;
    s->damon_cfg.nr_regions_max = s->cfg.damon_nr_regions_max;

    if (pager_damon_setup(&s->damon, s->pid, s->region_min, s->region_max, &s->damon_cfg) == 0) {
        s->m.damon_setup_ok++;
    } else {
        s->m.damon_setup_fail++;
        log_msg(s,
                "predicomp_pager: DAMON setup failed (continuing without DAMON) errno=%d (%s)\n",
                errno,
                strerror(errno));
        memset(&s->damon, 0, sizeof(s->damon));
    }

    s->stop = 0;
    s->active = 1;
    s->m.session_start_ns = now_ns();
    if (pthread_create(&s->fault_thread, NULL, fault_thread_main, s) != 0) {
        return -1;
    }
    if (pthread_create(&s->bg_thread, NULL, bg_thread_main, s) != 0) {
        s->stop = 1;
        close(s->uffd);
        s->uffd = -1;
        pthread_join(s->fault_thread, NULL);
        s->fault_thread = (pthread_t)0;
        return -1;
    }
    return 0;
}

static int handle_client(int client_fd, const struct cfg *daemon_cfg)
{
    struct session s;
    struct predicomp_msg_hello hello;
    struct predicomp_msg_hdr hdr;
    size_t i;
    int rc;
    uint64_t control_cpu_start_ns;

    reset_session_for_client(&s, client_fd);
    s.cfg = *daemon_cfg;
    control_cpu_start_ns = thread_cpu_now_ns();

    rc = recv_full(client_fd, &hello, sizeof(hello));
    if (rc != 0) {
        destroy_session_struct(&s);
        return -1;
    }
    if (hello.hdr.type != PREDICOMP_MSG_HELLO || hello.hdr.size != sizeof(hello) ||
        hello.version != PREDICOMP_PAGER_PROTO_VERSION || hello.nr_ranges == 0) {
        (void)send_error_msg(client_fd, PREDICOMP_MSG_HELLO, EPROTO, "invalid hello");
        destroy_session_struct(&s);
        errno = EPROTO;
        return -1;
    }
    s.pid = (pid_t)hello.pid;
    if (send_ack(client_fd, PREDICOMP_MSG_HELLO) != 0) {
        destroy_session_struct(&s);
        return -1;
    }

    for (i = 0; i < hello.nr_ranges; i++) {
        struct predicomp_msg_range rm;

        if (recv_full(client_fd, &rm, sizeof(rm)) != 0) {
            destroy_session_struct(&s);
            return -1;
        }
        if (rm.hdr.type != PREDICOMP_MSG_RANGE || rm.hdr.size != sizeof(rm)) {
            (void)send_error_msg(client_fd, PREDICOMP_MSG_RANGE, EPROTO, "invalid range message");
            destroy_session_struct(&s);
            errno = EPROTO;
            return -1;
        }
        if (add_range(&s, &rm) != 0) {
            (void)send_error_msg(client_fd, PREDICOMP_MSG_RANGE, errno, "range registration failed");
            destroy_session_struct(&s);
            return -1;
        }
        if (send_ack(client_fd, PREDICOMP_MSG_RANGE) != 0) {
            destroy_session_struct(&s);
            return -1;
        }
    }

    {
        struct predicomp_msg_start start_msg;
        int passed_fds[2];
        size_t nr_passed_fds;

        if (recv_start_with_fds(client_fd, &start_msg, passed_fds, 2, &nr_passed_fds) != 0) {
            (void)send_error_msg(client_fd, PREDICOMP_MSG_START, errno, "missing or invalid uffd fd");
            destroy_session_struct(&s);
            return -1;
        }
        s.uffd = passed_fds[0];
        if ((start_msg.flags & PREDICOMP_START_F_RPC_FD) != 0 && nr_passed_fds >= 2) {
            s.rpc_fd = passed_fds[1];
        }
        if (start_runtime(&s) != 0) {
            (void)send_error_msg(client_fd, PREDICOMP_MSG_START, errno, "session start failed");
            stop_session(&s);
            destroy_session_struct(&s);
            return -1;
        }
        if (send_ack(client_fd, PREDICOMP_MSG_START) != 0) {
            stop_session(&s);
            destroy_session_struct(&s);
            return -1;
        }
    }

    while (!g_stop) {
        ssize_t n;

        n = recv(client_fd, &hdr, sizeof(hdr), MSG_WAITALL);
        if (n == 0) {
            break;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if ((size_t)n != sizeof(hdr)) {
            break;
        }
        if (hdr.size < sizeof(hdr)) {
            break;
        }
        if (hdr.type == PREDICOMP_MSG_STOP) {
            if (hdr.size > sizeof(hdr)) {
                size_t rem;
                unsigned char sink[128];

                rem = hdr.size - sizeof(hdr);
                while (rem > 0) {
                    size_t chunk;

                    chunk = rem > sizeof(sink) ? sizeof(sink) : rem;
                    if (recv_full(client_fd, sink, chunk) != 0) {
                        break;
                    }
                    rem -= chunk;
                }
            }
            break;
        }

        {
            size_t rem;
            unsigned char sink[256];

            rem = hdr.size - sizeof(hdr);
            while (rem > 0) {
                size_t chunk;

                chunk = rem > sizeof(sink) ? sizeof(sink) : rem;
                if (recv_full(client_fd, sink, chunk) != 0) {
                    rem = 0;
                    break;
                }
                rem -= chunk;
            }
            (void)send_error_msg(client_fd, hdr.type, EPROTO, "unexpected message after start");
            break;
        }
    }

    s.m.control_thread_cpu_ns += thread_cpu_now_ns() - control_cpu_start_ns;
    stop_session(&s);
    destroy_session_struct(&s);
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [-s sock_path] [-v] [--csv path] [--cold-age-ms N] [--damon-read-ms N] "
            "[--soft-cap-bytes N] [--latency-sample-step N] [--latency-max-samples N]\n",
            argv0);
}

static int parse_u32(const char *s, uint32_t *out)
{
    char *end;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v > UINT32_MAX) {
        errno = EINVAL;
        return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

static int parse_u64(const char *s, uint64_t *out)
{
    char *end;
    unsigned long long v;

    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        errno = EINVAL;
        return -1;
    }
    *out = (uint64_t)v;
    return 0;
}

static double pct_of(uint64_t part, uint64_t whole)
{
    if (whole == 0) {
        return 0.0;
    }
    return (100.0 * (double)part) / (double)whole;
}

static void csv_write_header(FILE *fp)
{
    fprintf(fp,
            "session_pid,ranges_registered,pages_tracked,"
            "session_start_ns,session_end_ns,session_wall_ns,"
            "cold_age_ms,damon_read_tick_ms,soft_cap_bytes,latency_sample_step,latency_max_samples,"
            "damon_setup_ok,damon_setup_fail,damon_snapshots_total,damon_regions_total,damon_read_errors,pages_cold_marked,"
            "compress_attempts,compress_success,compress_skips_notbeneficial,compress_read_failures,compress_evict_failures,"
            "compress_bytes_in,compress_bytes_out,store_bytes_live,store_bytes_peak,soft_cap_warnings,"
            "faults_missing_total,faults_wp_total,faults_unexpected_total,restore_success,restore_failures,"
            "restore_missing_count,restore_wp_count,uffdio_copy_failures,uffdio_wp_failures,uffdio_zeropage_failures,"
            "process_madvise_failures,process_madvise_unsupported,client_evict_success,client_evict_failures,compress_wp_only_fallback,"
            "evict_mode_remote_ok,evict_mode_client_rpc,evict_mode_wp_only,"
            "control_thread_cpu_ns,bg_thread_cpu_ns,fault_thread_cpu_ns,daemon_cpu_ns_total,"
            "control_thread_cpu_pct,bg_thread_cpu_pct,fault_thread_cpu_pct,daemon_cpu_pct_total,"
            "compress_cpu_ns_total,compress_cpu_ns_max,restore_cpu_ns_total,restore_cpu_ns_max,"
            "restore_codec_wall_ns_total,restore_codec_wall_ns_max,restore_codec_cpu_ns_total,restore_codec_cpu_ns_max,"
            "compress_ns_total,restore_ns_total,fault_service_ns_total,fault_service_ns_max,"
            "fault_missing_service_ns_total,fault_missing_service_ns_max,fault_wp_service_ns_total,fault_wp_service_ns_max,"
            "client_evict_rpc_ns_total,client_evict_rpc_ns_max,process_madvise_ns_total,process_madvise_ns_max,"
            "latency_samples_dropped,latency_collector_ooms,"
            "compress_wall_samples,compress_wall_p50_ns,compress_wall_p95_ns,compress_wall_p99_ns,compress_wall_max_ns,"
            "compress_cpu_samples,compress_cpu_p50_ns,compress_cpu_p95_ns,compress_cpu_p99_ns,compress_cpu_max_ns,"
            "restore_wall_samples,restore_wall_p50_ns,restore_wall_p95_ns,restore_wall_p99_ns,restore_wall_max_ns,"
            "restore_cpu_samples,restore_cpu_p50_ns,restore_cpu_p95_ns,restore_cpu_p99_ns,restore_cpu_max_ns,"
            "restore_codec_wall_samples,restore_codec_wall_p50_ns,restore_codec_wall_p95_ns,restore_codec_wall_p99_ns,restore_codec_wall_max_ns,"
            "fault_all_samples,fault_all_p50_ns,fault_all_p95_ns,fault_all_p99_ns,fault_all_max_ns,"
            "fault_missing_samples,fault_missing_p50_ns,fault_missing_p95_ns,fault_missing_p99_ns,fault_missing_max_ns,"
            "fault_wp_samples,fault_wp_p50_ns,fault_wp_p95_ns,fault_wp_p99_ns,fault_wp_max_ns,"
            "client_evict_rpc_samples,client_evict_rpc_p50_ns,client_evict_rpc_p95_ns,client_evict_rpc_p99_ns,client_evict_rpc_max_ns,"
            "process_madvise_samples,process_madvise_p50_ns,process_madvise_p95_ns,process_madvise_p99_ns,process_madvise_max_ns\n");
}

static void csv_write_latency_group(FILE *fp, const struct latency_stats *st)
{
    fprintf(fp,
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64,
            st->samples,
            st->p50_ns,
            st->p95_ns,
            st->p99_ns,
            st->max_ns);
}

static void csv_write_session_row(FILE *fp, const struct session *s)
{
    const struct metrics *m;
    uint64_t daemon_cpu_ns_total;
    int evict_mode_remote_ok;
    int evict_mode_client_rpc;
    int evict_mode_wp_only;

    m = &s->m;
    daemon_cpu_ns_total = m->control_thread_cpu_ns + m->bg_thread_cpu_ns + m->fault_thread_cpu_ns;
    evict_mode_remote_ok = (m->compress_success > 0 && m->process_madvise_unsupported == 0 && m->client_evict_success == 0 && m->compress_wp_only_fallback == 0) ? 1 : 0;
    evict_mode_client_rpc = (m->client_evict_success > 0) ? 1 : 0;
    evict_mode_wp_only = (m->compress_wp_only_fallback > 0) ? 1 : 0;

    fprintf(fp,
            "%d,%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%u,%u,%" PRIu64 ",%u,%u,"
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%d,%d,%d,"
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%.6f,%.6f,%.6f,%.6f,"
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
            "%" PRIu64 ",%" PRIu64 ",",
            s->pid,
            m->ranges_registered,
            m->pages_tracked,
            m->session_start_ns,
            m->session_end_ns,
            m->session_wall_ns,
            s->cfg.cold_age_ms,
            s->cfg.damon_read_tick_ms,
            s->cfg.soft_cap_bytes,
            s->cfg.latency_sample_step,
            s->cfg.latency_max_samples,
            m->damon_setup_ok,
            m->damon_setup_fail,
            m->damon_snapshots_total,
            m->damon_regions_total,
            m->damon_read_errors,
            m->pages_cold_marked,
            m->compress_attempts,
            m->compress_success,
            m->compress_skips_notbeneficial,
            m->compress_read_failures,
            m->compress_evict_failures,
            m->compress_bytes_in,
            m->compress_bytes_out,
            m->store_bytes_live,
            m->store_bytes_peak,
            m->soft_cap_warnings,
            m->faults_missing_total,
            m->faults_wp_total,
            m->faults_unexpected_total,
            m->restore_success,
            m->restore_failures,
            m->restore_missing_count,
            m->restore_wp_count,
            m->uffdio_copy_failures,
            m->uffdio_wp_failures,
            m->uffdio_zeropage_failures,
            m->process_madvise_failures,
            m->process_madvise_unsupported,
            m->client_evict_success,
            m->client_evict_failures,
            m->compress_wp_only_fallback,
            evict_mode_remote_ok,
            evict_mode_client_rpc,
            evict_mode_wp_only,
            m->control_thread_cpu_ns,
            m->bg_thread_cpu_ns,
            m->fault_thread_cpu_ns,
            daemon_cpu_ns_total,
            pct_of(m->control_thread_cpu_ns, m->session_wall_ns),
            pct_of(m->bg_thread_cpu_ns, m->session_wall_ns),
            pct_of(m->fault_thread_cpu_ns, m->session_wall_ns),
            pct_of(daemon_cpu_ns_total, m->session_wall_ns),
            m->compress_cpu_ns_total,
            m->compress_cpu_ns_max,
            m->restore_cpu_ns_total,
            m->restore_cpu_ns_max,
            m->restore_codec_wall_ns_total,
            m->restore_codec_wall_ns_max,
            m->restore_codec_cpu_ns_total,
            m->restore_codec_cpu_ns_max,
            m->compress_ns_total,
            m->restore_ns_total,
            m->fault_service_ns_total,
            m->fault_service_ns_max,
            m->fault_missing_service_ns_total,
            m->fault_missing_service_ns_max,
            m->fault_wp_service_ns_total,
            m->fault_wp_service_ns_max,
            m->client_evict_rpc_ns_total,
            m->client_evict_rpc_ns_max,
            m->process_madvise_ns_total,
            m->process_madvise_ns_max,
            m->latency_samples_dropped,
            m->latency_collector_ooms);

    csv_write_latency_group(fp, &s->lat_stats[LAT_COMPRESS_WALL]);
    fputc(',', fp);
    csv_write_latency_group(fp, &s->lat_stats[LAT_COMPRESS_CPU]);
    fputc(',', fp);
    csv_write_latency_group(fp, &s->lat_stats[LAT_RESTORE_WALL]);
    fputc(',', fp);
    csv_write_latency_group(fp, &s->lat_stats[LAT_RESTORE_CPU]);
    fputc(',', fp);
    csv_write_latency_group(fp, &s->lat_stats[LAT_RESTORE_CODEC_WALL]);
    fputc(',', fp);
    csv_write_latency_group(fp, &s->lat_stats[LAT_FAULT_ALL]);
    fputc(',', fp);
    csv_write_latency_group(fp, &s->lat_stats[LAT_FAULT_MISSING]);
    fputc(',', fp);
    csv_write_latency_group(fp, &s->lat_stats[LAT_FAULT_WP]);
    fputc(',', fp);
    csv_write_latency_group(fp, &s->lat_stats[LAT_CLIENT_EVICT_RPC]);
    fputc(',', fp);
    csv_write_latency_group(fp, &s->lat_stats[LAT_PROCESS_MADVISE]);
    fputc('\n', fp);
}

static int parse_args(int argc, char **argv, struct cfg *cfg)
{
    int i;

    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->sock_path, sizeof(cfg->sock_path), "%s", DEFAULT_SOCK_PATH);
    cfg->csv_path[0] = '\0';
    cfg->csv_enabled = 0;
    cfg->soft_cap_bytes = 64ULL * 1024ULL * 1024ULL;
    cfg->damon_sample_us = 5000;
    cfg->damon_aggr_us = 100000;
    cfg->damon_update_us = 1000000;
    cfg->damon_read_tick_ms = 200;
    cfg->damon_nr_regions_min = 10;
    cfg->damon_nr_regions_max = 1000;
    cfg->cold_age_ms = 500;
    cfg->latency_sample_step = 1;
    cfg->latency_max_samples = 262144;
    cfg->csv_fp = NULL;
    cfg->verbose = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            cfg->verbose = 1;
            continue;
        }
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            i++;
            if (snprintf(cfg->sock_path, sizeof(cfg->sock_path), "%s", argv[i]) >= (int)sizeof(cfg->sock_path)) {
                errno = ENAMETOOLONG;
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            i++;
            if (snprintf(cfg->csv_path, sizeof(cfg->csv_path), "%s", argv[i]) >= (int)sizeof(cfg->csv_path)) {
                errno = ENAMETOOLONG;
                return -1;
            }
            cfg->csv_enabled = 1;
            continue;
        }
        if (strcmp(argv[i], "--cold-age-ms") == 0 && i + 1 < argc) {
            i++;
            if (parse_u32(argv[i], &cfg->cold_age_ms) != 0) {
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--damon-read-ms") == 0 && i + 1 < argc) {
            i++;
            if (parse_u32(argv[i], &cfg->damon_read_tick_ms) != 0) {
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--soft-cap-bytes") == 0 && i + 1 < argc) {
            i++;
            if (parse_u64(argv[i], &cfg->soft_cap_bytes) != 0) {
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--latency-sample-step") == 0 && i + 1 < argc) {
            i++;
            if (parse_u32(argv[i], &cfg->latency_sample_step) != 0 || cfg->latency_sample_step == 0) {
                errno = EINVAL;
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--latency-max-samples") == 0 && i + 1 < argc) {
            i++;
            if (parse_u32(argv[i], &cfg->latency_max_samples) != 0) {
                return -1;
            }
            continue;
        }
        usage(argv[0]);
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int make_listen_socket(const char *sock_path)
{
    int fd;
    struct sockaddr_un sun;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    if (snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", sock_path) >= (int)sizeof(sun.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    unlink(sock_path);
    if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 4) != 0) {
        close(fd);
        unlink(sock_path);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    struct cfg cfg;
    int lfd;
    FILE *csv_fp;
    struct sigaction sa;

    if (parse_args(argc, argv, &cfg) != 0) {
        perror("predicomp_pager: parse_args");
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    csv_fp = NULL;
    if (cfg.csv_enabled) {
        long pos;

        csv_fp = fopen(cfg.csv_path, "a+");
        if (csv_fp == NULL) {
            perror("predicomp_pager: fopen(csv)");
            return 1;
        }
        if (fseek(csv_fp, 0, SEEK_END) != 0) {
            perror("predicomp_pager: fseek(csv)");
            fclose(csv_fp);
            return 1;
        }
        pos = ftell(csv_fp);
        if (pos < 0) {
            perror("predicomp_pager: ftell(csv)");
            fclose(csv_fp);
            return 1;
        }
        if (pos == 0) {
            csv_write_header(csv_fp);
            fflush(csv_fp);
        }
        cfg.csv_fp = csv_fp;
    }

    lfd = make_listen_socket(cfg.sock_path);
    if (lfd < 0) {
        perror("predicomp_pager: listen socket");
        if (csv_fp != NULL) {
            fclose(csv_fp);
        }
        return 1;
    }
    fprintf(stderr, "predicomp_pager: listening on %s\n", cfg.sock_path);

    while (!g_stop) {
        int cfd;

        cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("predicomp_pager: accept");
            break;
        }
        if (cfg.verbose) {
            fprintf(stderr, "predicomp_pager: client connected\n");
        }
        (void)handle_client(cfd, &cfg);
    }

    close(lfd);
    unlink(cfg.sock_path);
    if (csv_fp != NULL) {
        fclose(csv_fp);
    }
    return 0;
}
