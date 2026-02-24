#ifndef PREDICOMP_PAGER_PROTOCOL_H
#define PREDICOMP_PAGER_PROTOCOL_H

#include <stdint.h>

#define PREDICOMP_PAGER_PROTO_VERSION 1U

#define PREDICOMP_MSG_HELLO 1U
#define PREDICOMP_MSG_RANGE 2U
#define PREDICOMP_MSG_START 3U
#define PREDICOMP_MSG_STOP 4U
#define PREDICOMP_MSG_ACK 5U
#define PREDICOMP_MSG_ERROR 6U

#define PREDICOMP_RANGE_F_ANON_PRIVATE 0x1U
#define PREDICOMP_RANGE_F_WRITABLE     0x2U

struct predicomp_msg_hdr {
    uint32_t type;
    uint32_t size;
};

struct predicomp_msg_hello {
    struct predicomp_msg_hdr hdr;
    uint32_t version;
    uint32_t pid;
    uint32_t nr_ranges;
    uint32_t flags;
};

struct predicomp_msg_range {
    struct predicomp_msg_hdr hdr;
    uint32_t range_id;
    uint32_t flags;
    uint64_t start;
    uint64_t len;
};

struct predicomp_msg_start {
    struct predicomp_msg_hdr hdr;
    uint32_t flags;
    uint32_t reserved;
};

struct predicomp_msg_stop {
    struct predicomp_msg_hdr hdr;
    uint32_t reason;
    uint32_t reserved;
};

struct predicomp_msg_ack {
    struct predicomp_msg_hdr hdr;
    uint32_t ack_type;
    uint32_t status;
};

struct predicomp_msg_error {
    struct predicomp_msg_hdr hdr;
    uint32_t for_type;
    int32_t err_no;
    char message[96];
};

#endif
