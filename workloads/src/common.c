#include "common.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int wl_parse_int_arg(const char *name, const char *value, int min_v, int max_v)
{
    char *end = NULL;
    long parsed = strtol(value, &end, 10);

    if (end == value || *end != '\0') {
        fprintf(stderr, "invalid integer for %s: %s\n", name, value);
        exit(2);
    }
    if (parsed < min_v || parsed > max_v) {
        fprintf(stderr, "%s out of range [%d,%d]: %ld\n", name, min_v, max_v, parsed);
        exit(2);
    }
    return (int)parsed;
}

uint64_t wl_parse_u64_arg(const char *name, const char *value)
{
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);

    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "invalid uint64 for %s: %s\n", name, value);
        exit(2);
    }
    return (uint64_t)parsed;
}

void wl_init_common_opts(struct wl_common_opts *opts)
{
    opts->duration_sec = WL_DEFAULT_DURATION_SEC;
    opts->workers = WL_DEFAULT_WORKERS;
    opts->seed = 12345;
    opts->json = false;
    opts->unsafe_allow_long = false;
}

bool wl_parse_common_arg(struct wl_common_opts *opts, const char *arg, const char *value)
{
    if (strcmp(arg, "--duration-sec") == 0) {
        opts->duration_sec = wl_parse_int_arg("--duration-sec", value, 1, 3600);
        return true;
    }
    if (strcmp(arg, "--workers") == 0) {
        opts->workers = wl_parse_int_arg("--workers", value, 1, 4096);
        return true;
    }
    if (strcmp(arg, "--seed") == 0) {
        opts->seed = wl_parse_u64_arg("--seed", value);
        return true;
    }
    if (strcmp(arg, "--json") == 0) {
        opts->json = true;
        return true;
    }
    if (strcmp(arg, "--unsafe-allow-long") == 0) {
        opts->unsafe_allow_long = true;
        return true;
    }
    return false;
}

int wl_validate_common_opts(const struct wl_common_opts *opts)
{
    if (opts->duration_sec > WL_MAX_DURATION_SEC && !opts->unsafe_allow_long) {
        fprintf(stderr,
                "duration %d exceeds safe max %d; pass --unsafe-allow-long to override\n",
                opts->duration_sec,
                WL_MAX_DURATION_SEC);
        return -1;
    }
    if (opts->workers > WL_MAX_WORKERS && !opts->unsafe_allow_long) {
        fprintf(stderr,
                "workers %d exceeds safe max %d; pass --unsafe-allow-long to override\n",
                opts->workers,
                WL_MAX_WORKERS);
        return -1;
    }
    return 0;
}

uint64_t wl_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void wl_sleep_ns(uint64_t ns)
{
    struct timespec req;
    req.tv_sec = (time_t)(ns / 1000000000ULL);
    req.tv_nsec = (long)(ns % 1000000000ULL);
    nanosleep(&req, NULL);
}

void wl_print_common_help(void)
{
    fprintf(stderr,
            "common options:\n"
            "  --duration-sec <n>\n"
            "  --workers <n>\n"
            "  --seed <n>\n"
            "  --json\n"
            "  --unsafe-allow-long\n");
}

void wl_print_json_kv_str(const char *key, const char *value, bool last)
{
    printf("\"%s\":\"%s\"%s", key, value, last ? "" : ",");
}

void wl_print_json_kv_u64(const char *key, uint64_t value, bool last)
{
    printf("\"%s\":%" PRIu64 "%s", key, value, last ? "" : ",");
}

void wl_print_json_kv_double(const char *key, double value, bool last)
{
    printf("\"%s\":%.6f%s", key, value, last ? "" : ",");
}
