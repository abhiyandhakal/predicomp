#include "controller_client.h"

#include <workload_control_protocol.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

const char *wl_controller_sock_default_if_null(const char *sock_path)
{
    if (sock_path == NULL) {
        return WL_CONTROLLER_SOCK_DEFAULT;
    }
    return sock_path;
}

static int controller_send_datagram(const char *sock_path, const void *buf, size_t len)
{
    int fd;
    struct sockaddr_un addr;
    ssize_t sent;

    if (sock_path == NULL) {
        return 0;
    }

    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(controller)");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sock_path) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "controller socket path too long: %s\n", sock_path);
        close(fd);
        return -1;
    }
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    sent = sendto(fd, buf, len, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (sent < 0) {
        fprintf(stderr, "sendto(controller) failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    if ((size_t)sent != len) {
        fprintf(stderr, "short sendto(controller): %zd/%zu\n", sent, len);
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int wl_controller_send_enroll(
    const char *sock_path,
    const char *workload_name,
    int arena_cap_mb,
    int arena_min_savings_pct,
    int region_mb
)
{
    struct wl_controller_msg_enroll msg;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = WL_CTL_MSG_ENROLL;
    msg.pid = (uint32_t)getpid();
    msg.use_mem_arena = 1;
    msg.arena_cap_mb = (uint32_t)arena_cap_mb;
    msg.arena_min_savings_pct = (uint32_t)arena_min_savings_pct;
    msg.region_mb = (uint32_t)region_mb;
    strncpy(msg.workload_name, workload_name, sizeof(msg.workload_name) - 1);

    return controller_send_datagram(sock_path, &msg, sizeof(msg));
}

int wl_controller_send_compress_ack(
    const char *sock_path,
    const char *workload_name,
    uint64_t trigger_count,
    const struct mem_arena_stats *stats,
    uint64_t event_ns
)
{
    struct wl_controller_msg_compress_ack msg;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = WL_CTL_MSG_COMPRESS_ACK;
    msg.pid = (uint32_t)getpid();
    msg.event_ns = event_ns;
    msg.trigger_count = trigger_count;
    strncpy(msg.workload_name, workload_name, sizeof(msg.workload_name) - 1);
    msg.total_input_bytes_attempted = stats->total_input_bytes_attempted;
    msg.chunks_admitted = stats->chunks_admitted;
    msg.logical_input_bytes = stats->logical_input_bytes;
    msg.compressed_bytes_live = stats->compressed_bytes_live;
    msg.pool_bytes_live = stats->pool_bytes_live;
    msg.pool_bytes_free = stats->pool_bytes_free;
    msg.pool_compactions = stats->pool_compactions;
    msg.compress_ops = stats->compress_ops;
    msg.decompress_ops = stats->decompress_ops;
    msg.evictions_lru = stats->evictions_lru;
    msg.incompressible_chunks = stats->incompressible_chunks;

    return controller_send_datagram(sock_path, &msg, sizeof(msg));
}
