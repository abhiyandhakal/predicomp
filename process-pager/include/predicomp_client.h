#ifndef PREDICOMP_CLIENT_H
#define PREDICOMP_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#define PREDICOMP_CLIENT_RANGE_F_ANON_PRIVATE 0x1U
#define PREDICOMP_CLIENT_RANGE_F_WRITABLE     0x2U

struct predicomp_client;

struct predicomp_client_config {
    const char *daemon_sock_path;
    int enable_wp;
    int enable_missing;
};

struct predicomp_range_handle {
    int id;
    void *addr;
    size_t len;
};

int predicomp_client_open(
    struct predicomp_client **out_client,
    const struct predicomp_client_config *cfg
);

int predicomp_client_register_range(
    struct predicomp_client *client,
    void *addr,
    size_t len,
    uint32_t flags,
    struct predicomp_range_handle *out_handle
);

int predicomp_client_register_range_live(
    struct predicomp_client *client,
    void *addr,
    size_t len,
    uint32_t flags,
    struct predicomp_range_handle *out_handle
);

int predicomp_client_unregister_range_live(
    struct predicomp_client *client,
    const struct predicomp_range_handle *handle
);

int predicomp_client_start(struct predicomp_client *client);
int predicomp_client_stop(struct predicomp_client *client);
void predicomp_client_close(struct predicomp_client *client);

#endif
