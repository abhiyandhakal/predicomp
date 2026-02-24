#include "protocol.h"
#include "pager_damon.h"
#include "mem_arena_codec.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/userfaultfd.h>
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
    uint64_t soft_cap_bytes;
    uint32_t damon_sample_us;
    uint32_t damon_aggr_us;
    uint32_t damon_update_us;
    uint32_t damon_read_tick_ms;
    uint32_t damon_nr_regions_min;
    uint32_t damon_nr_regions_max;
    uint32_t cold_age_ms;
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
    uint64_t compress_ns_total;
    uint64_t restore_ns_total;
    uint64_t fault_service_ns_total;
    uint64_t fault_service_ns_max;
};

struct session {
    int active;
    int stop;
    int client_fd;
    int uffd;
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
};

static volatile sig_atomic_t g_stop = 0;

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
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
            p->dirty = 1;
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

static int arm_wp_range(struct session *s, uint64_t start, uint64_t len)
{
    struct uffdio_writeprotect wp;

    memset(&wp, 0, sizeof(wp));
    wp.range.start = start;
    wp.range.len = len;
    wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
    if (ioctl(s->uffd, UFFDIO_WRITEPROTECT, &wp) != 0) {
        s->m.uffdio_wp_failures++;
        return -1;
    }
    return 0;
}

static int recv_start_with_fd(int fd, struct predicomp_msg_start *out_msg, int *out_passed_fd)
{
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr hdr;
        unsigned char data[CMSG_SPACE(sizeof(int))];
    } cbuf;
    struct cmsghdr *cmsg;
    ssize_t n;

    memset(out_msg, 0, sizeof(*out_msg));
    *out_passed_fd = -1;
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
            memcpy(out_passed_fd, CMSG_DATA(cmsg), sizeof(int));
            break;
        }
    }
    if (*out_passed_fd < 0) {
        errno = EPROTO;
        return -1;
    }
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

    t0 = now_ns();
    s->m.faults_missing_total++;

    if (p == NULL) {
        s->m.faults_unexpected_total++;
        if (zero_fill_fault(s, addr) != 0) {
            return -1;
        }
        return 0;
    }

    if (p->state == PAGE_STATE_COMPRESSED && p->blob != NULL && p->blob_len > 0) {
        rc = mem_arena_lz4_decompress(p->blob, (int)p->blob_len, pagebuf, (int)PAGE_SZ);
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
        s->m.restore_ns_total += now_ns() - t0;
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
        if (uffd_writeprotect_page(s, addr, 1) == 0) {
            p->wp_active = 1;
            p->dirty = 0;
            s->m.pages_wp_armed++;
        }
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
    if (uffd_writeprotect_page(s, addr, 1) == 0) {
        p->wp_active = 1;
        s->m.pages_wp_armed++;
    }
    return 0;
}

static int handle_wp_fault_locked(struct session *s, struct page_entry *p, uintptr_t addr)
{
    s->m.faults_wp_total++;
    if (p == NULL) {
        s->m.faults_unexpected_total++;
        return -1;
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

    s = (struct session *)arg;
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
            pthread_mutex_unlock(&s->mu);
        }
    }

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
            p->last_damon_seen_ns = now_ns();
            if (snap->regions[i].nr_accesses == 0 && snap->regions[i].age >= s->cfg.cold_age_ms) {
                if (!p->is_cold) {
                    s->m.pages_cold_marked++;
                }
                p->is_cold = 1;
            } else {
                p->is_cold = 0;
            }
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
    uint8_t *new_blob;
    uint64_t t0;

    if (p->state != PAGE_STATE_PRESENT || !p->is_cold || !p->wp_active || p->dirty) {
        return 0;
    }
    if (maybe_warn_soft_cap_locked(s) != 0) {
        return 0;
    }

    t0 = now_ns();
    s->m.compress_attempts++;

    local_iov.iov_base = pagebuf;
    local_iov.iov_len = PAGE_SZ;
    remote_iov.iov_base = (void *)p->addr;
    remote_iov.iov_len = PAGE_SZ;
    nread = process_vm_readv(s->pid, &local_iov, 1, &remote_iov, 1, 0);
    if (nread != (ssize_t)PAGE_SZ) {
        s->m.compress_read_failures++;
        return -1;
    }

    clen = mem_arena_lz4_compress(pagebuf, PAGE_SZ, compbuf, (int)sizeof(compbuf), 1);
    if (clen <= 0 || clen >= (int)PAGE_SZ) {
        s->m.compress_skips_notbeneficial++;
        return 0;
    }

    new_blob = malloc((size_t)clen);
    if (new_blob == NULL) {
        return -1;
    }
    memcpy(new_blob, compbuf, (size_t)clen);

    madv_rc = process_madvise_wrap(s->pidfd, (void *)p->addr, PAGE_SZ, MADV_DONTNEED);
    if (madv_rc < 0) {
        free(new_blob);
        s->m.process_madvise_failures++;
        s->m.compress_evict_failures++;
        return -1;
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
    p->wp_active = 0;
    p->dirty = 0;
    p->last_compress_ns = now_ns();

    s->m.compress_success++;
    s->m.compress_bytes_in += PAGE_SZ;
    s->m.compress_bytes_out += (uint64_t)clen;
    s->m.store_bytes_live += (uint64_t)clen;
    if (s->m.store_bytes_live > s->m.store_bytes_peak) {
        s->m.store_bytes_peak = s->m.store_bytes_live;
    }
    s->m.compress_ns_total += now_ns() - t0;
    return 1;
}

static void *bg_thread_main(void *arg)
{
    struct session *s;

    s = (struct session *)arg;
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
            if (arm_rc > 0) {
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
    return NULL;
}

static void dump_metrics(const struct session *s)
{
    const struct metrics *m;

    m = &s->m;
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
            " process_madvise_fail=%" PRIu64
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
        dump_metrics(s);
    }

    if (s->pidfd >= 0) {
        close(s->pidfd);
        s->pidfd = -1;
    }
    if (s->client_fd >= 0) {
        close(s->client_fd);
        s->client_fd = -1;
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
    memset(&s->m, 0, sizeof(s->m));
    s->region_min = 0;
    s->region_max = 0;
    s->active = 0;
}

static void reset_session_for_client(struct session *s, int client_fd)
{
    memset(s, 0, sizeof(*s));
    s->client_fd = client_fd;
    s->uffd = -1;
    s->pidfd = -1;
    pthread_mutex_init(&s->mu, NULL);
}

static void destroy_session_struct(struct session *s)
{
    pthread_mutex_destroy(&s->mu);
}

static int start_runtime(struct session *s)
{
    size_t i;

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

    for (i = 0; i < s->nr_ranges; i++) {
        if (arm_wp_range(s, s->ranges[i].start, s->ranges[i].len) == 0) {
            uint64_t a;
            for (a = s->ranges[i].start; a < s->ranges[i].start + s->ranges[i].len; a += PAGE_SZ) {
                struct page_entry *p;

                p = map_get_page(s, (uintptr_t)a);
                if (p != NULL) {
                    p->wp_active = 1;
                    p->dirty = 0;
                    s->m.pages_wp_armed++;
                }
            }
        }
    }

    s->stop = 0;
    s->active = 1;
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

    reset_session_for_client(&s, client_fd);
    s.cfg = *daemon_cfg;

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
        int passed_fd;

        if (recv_start_with_fd(client_fd, &start_msg, &passed_fd) != 0) {
            (void)send_error_msg(client_fd, PREDICOMP_MSG_START, errno, "missing or invalid uffd fd");
            destroy_session_struct(&s);
            return -1;
        }
        s.uffd = passed_fd;
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

    stop_session(&s);
    destroy_session_struct(&s);
    return 0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [-s sock_path] [-v] [--cold-age-ms N] [--damon-read-ms N] [--soft-cap-bytes N]\n",
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

static int parse_args(int argc, char **argv, struct cfg *cfg)
{
    int i;

    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->sock_path, sizeof(cfg->sock_path), "%s", DEFAULT_SOCK_PATH);
    cfg->soft_cap_bytes = 64ULL * 1024ULL * 1024ULL;
    cfg->damon_sample_us = 5000;
    cfg->damon_aggr_us = 100000;
    cfg->damon_update_us = 1000000;
    cfg->damon_read_tick_ms = 200;
    cfg->damon_nr_regions_min = 10;
    cfg->damon_nr_regions_max = 1000;
    cfg->cold_age_ms = 500;
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

    lfd = make_listen_socket(cfg.sock_path);
    if (lfd < 0) {
        perror("predicomp_pager: listen socket");
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
    return 0;
}
