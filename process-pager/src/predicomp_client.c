#include "predicomp_client.h"
#include "protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifndef UFFD_API
#define UFFD_API ((__u64)0xAA)
#endif

struct predicomp_range_desc {
    uint64_t start;
    uint64_t len;
    uint32_t flags;
    uint32_t id;
};

struct predicomp_client {
    char sock_path[108];
    int daemon_fd;
    int uffd;
    int started;
    int enable_wp;
    int enable_missing;
    struct predicomp_range_desc *ranges;
    size_t nr_ranges;
    size_t ranges_cap;
    uint32_t next_range_id;
};

static int send_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p = (const unsigned char *)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
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
    unsigned char *p = (unsigned char *)buf;
    while (len > 0) {
        ssize_t n = recv(fd, p, len, 0);
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

static int send_with_fd(int fd, const void *buf, size_t len, int pass_fd)
{
    struct msghdr msg;
    struct iovec iov;
    union {
        struct cmsghdr hdr;
        unsigned char data[CMSG_SPACE(sizeof(int))];
    } cmsgbuf;
    struct cmsghdr *cmsg;

    memset(&msg, 0, sizeof(msg));
    memset(&cmsgbuf, 0, sizeof(cmsgbuf));

    iov.iov_base = (void *)buf;
    iov.iov_len = len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf.data;
    msg.msg_controllen = sizeof(cmsgbuf.data);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &pass_fd, sizeof(int));
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    if (sendmsg(fd, &msg, 0) < 0) {
        return -1;
    }
    return 0;
}

static int recv_ack_or_error(int fd, uint32_t expect_type)
{
    struct predicomp_msg_hdr hdr;

    if (recv_full(fd, &hdr, sizeof(hdr)) != 0) {
        return -1;
    }
    if (hdr.size < sizeof(hdr)) {
        errno = EPROTO;
        return -1;
    }
    if (hdr.type == PREDICOMP_MSG_ACK) {
        struct predicomp_msg_ack ack;
        if (hdr.size != sizeof(ack)) {
            errno = EPROTO;
            return -1;
        }
        memcpy(&ack, &hdr, sizeof(hdr));
        if (recv_full(fd, ((unsigned char *)&ack) + sizeof(hdr), sizeof(ack) - sizeof(hdr)) != 0) {
            return -1;
        }
        if (ack.ack_type != expect_type || ack.status != 0) {
            errno = EPROTO;
            return -1;
        }
        return 0;
    }
    if (hdr.type == PREDICOMP_MSG_ERROR) {
        struct predicomp_msg_error errm;
        size_t rem;
        if (hdr.size > sizeof(errm)) {
            errno = EPROTO;
            return -1;
        }
        memcpy(&errm, &hdr, sizeof(hdr));
        rem = hdr.size - sizeof(hdr);
        if (recv_full(fd, ((unsigned char *)&errm) + sizeof(hdr), rem) != 0) {
            return -1;
        }
        if (errm.message[0] != '\0') {
            fprintf(stderr, "predicomp_client: daemon error for type=%u: %s\n", errm.for_type, errm.message);
        }
        errno = errm.err_no ? errm.err_no : EPROTO;
        return -1;
    }
    errno = EPROTO;
    return -1;
}

static int create_uffd(int enable_wp, int enable_missing, int *out_uffd)
{
    int uffd;
    struct uffdio_api api;
    (void)enable_missing;

    uffd = (int)syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd < 0) {
        return -1;
    }
    memset(&api, 0, sizeof(api));
    api.api = UFFD_API;
    if (enable_wp) {
        api.features |= UFFD_FEATURE_PAGEFAULT_FLAG_WP;
    }
    if (ioctl(uffd, UFFDIO_API, &api) != 0) {
        close(uffd);
        return -1;
    }
    if (enable_wp && (api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP) == 0) {
        close(uffd);
        errno = ENOTSUP;
        return -1;
    }
    *out_uffd = uffd;
    return 0;
}

int predicomp_client_open(struct predicomp_client **out_client, const struct predicomp_client_config *cfg)
{
    struct predicomp_client *c;
    const char *sock_path;

    if (out_client == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out_client = NULL;
    c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return -1;
    }
    sock_path = (cfg != NULL && cfg->daemon_sock_path != NULL) ? cfg->daemon_sock_path : "/tmp/predicomp-pager.sock";
    if (snprintf(c->sock_path, sizeof(c->sock_path), "%s", sock_path) >= (int)sizeof(c->sock_path)) {
        free(c);
        errno = ENAMETOOLONG;
        return -1;
    }
    c->daemon_fd = -1;
    c->uffd = -1;
    c->enable_wp = (cfg == NULL) ? 1 : cfg->enable_wp;
    c->enable_missing = (cfg == NULL) ? 1 : cfg->enable_missing;
    c->next_range_id = 1;
    *out_client = c;
    return 0;
}

int predicomp_client_register_range(struct predicomp_client *client, void *addr, size_t len, uint32_t flags, struct predicomp_range_handle *out_handle)
{
    struct predicomp_range_desc *r;
    uintptr_t start;

    if (client == NULL || addr == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }
    if (client->started) {
        errno = EBUSY;
        return -1;
    }
    start = (uintptr_t)addr;
    if ((start % PAGE_SIZE) != 0 || (len % PAGE_SIZE) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (client->nr_ranges == client->ranges_cap) {
        size_t new_cap = client->ranges_cap == 0 ? 4 : client->ranges_cap * 2;
        void *tmp = realloc(client->ranges, new_cap * sizeof(*client->ranges));
        if (tmp == NULL) {
            return -1;
        }
        client->ranges = tmp;
        client->ranges_cap = new_cap;
    }
    r = &client->ranges[client->nr_ranges++];
    r->start = (uint64_t)start;
    r->len = (uint64_t)len;
    r->flags = flags;
    r->id = client->next_range_id++;
    if (out_handle != NULL) {
        out_handle->id = (int)r->id;
        out_handle->addr = addr;
        out_handle->len = len;
    }
    return 0;
}

static int register_uffd_ranges(struct predicomp_client *client)
{
    size_t i;
    for (i = 0; i < client->nr_ranges; i++) {
        struct uffdio_register reg;
        memset(&reg, 0, sizeof(reg));
        reg.range.start = client->ranges[i].start;
        reg.range.len = client->ranges[i].len;
        if (client->enable_missing) {
            reg.mode |= UFFDIO_REGISTER_MODE_MISSING;
        }
        if (client->enable_wp) {
            reg.mode |= UFFDIO_REGISTER_MODE_WP;
        }
        if (ioctl(client->uffd, UFFDIO_REGISTER, &reg) != 0) {
            return -1;
        }
    }
    return 0;
}

static int connect_daemon(const char *sock_path)
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
    if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int predicomp_client_start(struct predicomp_client *client)
{
    size_t i;
    struct predicomp_msg_hello hello;
    struct predicomp_msg_start start_msg;

    if (client == NULL || client->started) {
        errno = EINVAL;
        return -1;
    }
    if (client->nr_ranges == 0) {
        errno = EINVAL;
        return -1;
    }
    if (create_uffd(client->enable_wp, client->enable_missing, &client->uffd) != 0) {
        perror("predicomp_client: userfaultfd");
        return -1;
    }
    if (register_uffd_ranges(client) != 0) {
        perror("predicomp_client: UFFDIO_REGISTER");
        close(client->uffd);
        client->uffd = -1;
        return -1;
    }
    client->daemon_fd = connect_daemon(client->sock_path);
    if (client->daemon_fd < 0) {
        perror("predicomp_client: connect daemon");
        close(client->uffd);
        client->uffd = -1;
        return -1;
    }

    memset(&hello, 0, sizeof(hello));
    hello.hdr.type = PREDICOMP_MSG_HELLO;
    hello.hdr.size = sizeof(hello);
    hello.version = PREDICOMP_PAGER_PROTO_VERSION;
    hello.pid = (uint32_t)getpid();
    hello.nr_ranges = (uint32_t)client->nr_ranges;
    hello.flags = (client->enable_wp ? 1U : 0U) | (client->enable_missing ? 2U : 0U);
    if (send_all(client->daemon_fd, &hello, sizeof(hello)) != 0 || recv_ack_or_error(client->daemon_fd, PREDICOMP_MSG_HELLO) != 0) {
        goto fail;
    }

    for (i = 0; i < client->nr_ranges; i++) {
        struct predicomp_msg_range msg;
        memset(&msg, 0, sizeof(msg));
        msg.hdr.type = PREDICOMP_MSG_RANGE;
        msg.hdr.size = sizeof(msg);
        msg.range_id = client->ranges[i].id;
        msg.flags = client->ranges[i].flags;
        msg.start = client->ranges[i].start;
        msg.len = client->ranges[i].len;
        if (send_all(client->daemon_fd, &msg, sizeof(msg)) != 0 || recv_ack_or_error(client->daemon_fd, PREDICOMP_MSG_RANGE) != 0) {
            goto fail;
        }
    }

    memset(&start_msg, 0, sizeof(start_msg));
    start_msg.hdr.type = PREDICOMP_MSG_START;
    start_msg.hdr.size = sizeof(start_msg);
    if (send_with_fd(client->daemon_fd, &start_msg, sizeof(start_msg), client->uffd) != 0 ||
        recv_ack_or_error(client->daemon_fd, PREDICOMP_MSG_START) != 0) {
        goto fail;
    }

    client->started = 1;
    return 0;

fail:
    perror("predicomp_client: daemon handshake");
    if (client->daemon_fd >= 0) {
        close(client->daemon_fd);
        client->daemon_fd = -1;
    }
    if (client->uffd >= 0) {
        close(client->uffd);
        client->uffd = -1;
    }
    return -1;
}

int predicomp_client_stop(struct predicomp_client *client)
{
    struct predicomp_msg_stop stop_msg;

    if (client == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (!client->started) {
        return 0;
    }
    memset(&stop_msg, 0, sizeof(stop_msg));
    stop_msg.hdr.type = PREDICOMP_MSG_STOP;
    stop_msg.hdr.size = sizeof(stop_msg);
    (void)send_all(client->daemon_fd, &stop_msg, sizeof(stop_msg));
    client->started = 0;
    if (client->daemon_fd >= 0) {
        close(client->daemon_fd);
        client->daemon_fd = -1;
    }
    if (client->uffd >= 0) {
        close(client->uffd);
        client->uffd = -1;
    }
    return 0;
}

void predicomp_client_close(struct predicomp_client *client)
{
    if (client == NULL) {
        return;
    }
    (void)predicomp_client_stop(client);
    free(client->ranges);
    free(client);
}
