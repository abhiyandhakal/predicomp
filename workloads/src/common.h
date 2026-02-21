#ifndef WORKLOADS_COMMON_H
#define WORKLOADS_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WL_DEFAULT_DURATION_SEC 20
#define WL_MAX_DURATION_SEC 300
#define WL_DEFAULT_WORKERS 4
#define WL_MAX_WORKERS 512

struct wl_common_opts {
    int duration_sec;
    int workers;
    uint64_t seed;
    bool json;
    bool unsafe_allow_long;
};

int wl_parse_int_arg(const char *name, const char *value, int min_v, int max_v);
uint64_t wl_parse_u64_arg(const char *name, const char *value);
void wl_init_common_opts(struct wl_common_opts *opts);
bool wl_parse_common_arg(struct wl_common_opts *opts, const char *arg, const char *value);
int wl_validate_common_opts(const struct wl_common_opts *opts);
uint64_t wl_now_ns(void);
void wl_sleep_ns(uint64_t ns);
void wl_print_common_help(void);
void wl_print_json_kv_str(const char *key, const char *value, bool last);
void wl_print_json_kv_u64(const char *key, uint64_t value, bool last);
void wl_print_json_kv_double(const char *key, double value, bool last);

#endif
