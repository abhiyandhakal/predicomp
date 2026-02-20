#define _GNU_SOURCE

#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <lz4.h>
#include <lz4hc.h>
#include <zstd.h>

#define RESULTS_CSV "compressor-monitor/results.csv"
#define SAMPLES_DIR "compressor-monitor/samples"
#define DEFAULT_RUNS 5
#define DEFAULT_WARMUPS 2
#define DEFAULT_MAX_SIZE (16U * 1024U * 1024U)
#define MIN_SIZE 1024U
#define MIX_BLOCK_SIZE 4096U
#define MAX_PROFILES 64

enum dataset_kind {
    DATASET_REPETITIVE = 0,
    DATASET_UNIQUE = 1,
    DATASET_MIXED_50_50 = 2,
};

enum codec_kind {
    CODEC_LZ4 = 0,
    CODEC_ZSTD = 1,
};

struct options {
    int runs;
    int warmups;
    size_t max_size;
    int use_cpu_pin;
    long cpu_id;
    int use_lz4;
    int use_zstd;
};

struct profile {
    enum codec_kind codec;
    const char *codec_name;
    const char *mode_name;
    int level;
};

struct phase_metrics {
    double wall_ms;
    double thread_cpu_ms;
    double process_cpu_ms;
};

struct run_metrics {
    struct phase_metrics compress;
    struct phase_metrics decompress;
    unsigned long long compressed_bytes;
    double ratio;
    int validation_pass;
};

struct case_summary {
    const char *codec;
    const char *mode;
    int level;
    const char *dataset_type;
    size_t size_bytes;
    unsigned long long compressed_bytes_median;
    double ratio_median;
    double comp_wall_ms_median;
    double decomp_wall_ms_median;
    double comp_thread_cpu_ms_median;
    double decomp_thread_cpu_ms_median;
    double comp_proc_cpu_ms_median;
    double decomp_proc_cpu_ms_median;
    double comp_mib_per_s_median;
    double decomp_mib_per_s_median;
    int all_validation_pass;
};

struct clock_snapshot {
    struct timespec wall;
    struct timespec thread_cpu;
    struct timespec process_cpu;
};

struct repetitive_state {
    size_t offset;
};

struct unique_state {
    uint64_t state;
    unsigned int byte_index;
};

static void print_usage(const char *prog)
{
    printf(
        "Usage: %s [--cpu <id>] [--runs <n>] [--warmups <n>] [--max-size <bytes>] [--codecs lz4,zstd] [--full-sweep]\n",
        prog
    );
}

static int parse_positive_int(const char *value, int *out)
{
    char *end = NULL;
    long parsed;

    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed <= 0 || parsed > 1000000L) {
        return -1;
    }

    *out = (int)parsed;
    return 0;
}

static int parse_non_negative_long(const char *value, long *out)
{
    char *end = NULL;
    long parsed;

    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < 0L) {
        return -1;
    }

    *out = parsed;
    return 0;
}

static int parse_positive_size(const char *value, size_t *out)
{
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0ULL) {
        return -1;
    }

    *out = (size_t)parsed;
    return 0;
}

static int parse_codec_list(const char *value, int *use_lz4, int *use_zstd)
{
    if (strcmp(value, "lz4") == 0) {
        *use_lz4 = 1;
        *use_zstd = 0;
        return 0;
    }

    if (strcmp(value, "zstd") == 0) {
        *use_lz4 = 0;
        *use_zstd = 1;
        return 0;
    }

    if (strcmp(value, "lz4,zstd") == 0 || strcmp(value, "zstd,lz4") == 0) {
        *use_lz4 = 1;
        *use_zstd = 1;
        return 0;
    }

    return -1;
}

static int parse_options(int argc, char **argv, struct options *opts)
{
    int i;

    opts->runs = DEFAULT_RUNS;
    opts->warmups = DEFAULT_WARMUPS;
    opts->max_size = DEFAULT_MAX_SIZE;
    opts->use_cpu_pin = 0;
    opts->cpu_id = -1;
    opts->use_lz4 = 1;
    opts->use_zstd = 1;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cpu") == 0) {
            if (i + 1 >= argc || parse_non_negative_long(argv[i + 1], &opts->cpu_id) != 0) {
                return -1;
            }
            opts->use_cpu_pin = 1;
            i++;
        } else if (strcmp(argv[i], "--runs") == 0) {
            if (i + 1 >= argc || parse_positive_int(argv[i + 1], &opts->runs) != 0) {
                return -1;
            }
            i++;
        } else if (strcmp(argv[i], "--warmups") == 0) {
            if (i + 1 >= argc) {
                return -1;
            }
            {
                long parsed = 0;
                if (parse_non_negative_long(argv[i + 1], &parsed) != 0 || parsed > 1000000L) {
                    return -1;
                }
                opts->warmups = (int)parsed;
            }
            i++;
        } else if (strcmp(argv[i], "--max-size") == 0) {
            if (i + 1 >= argc || parse_positive_size(argv[i + 1], &opts->max_size) != 0) {
                return -1;
            }
            i++;
        } else if (strcmp(argv[i], "--codecs") == 0) {
            if (i + 1 >= argc || parse_codec_list(argv[i + 1], &opts->use_lz4, &opts->use_zstd) != 0) {
                return -1;
            }
            i++;
        } else if (strcmp(argv[i], "--full-sweep") == 0) {
            /* Default behavior is already full sweep. */
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            return -1;
        }
    }

    if (opts->max_size < MIN_SIZE) {
        return -1;
    }

    if (!opts->use_lz4 && !opts->use_zstd) {
        return -1;
    }

    return 0;
}

static int pin_to_cpu(long cpu_id)
{
    cpu_set_t set;

    if (cpu_id < 0 || cpu_id >= CPU_SETSIZE) {
        errno = EINVAL;
        return -1;
    }

    CPU_ZERO(&set);
    CPU_SET((int)cpu_id, &set);

    return sched_setaffinity(0, sizeof(set), &set);
}

static int ensure_dir_exists(const char *path)
{
    if (mkdir(path, 0755) == 0) {
        return 0;
    }

    if (errno == EEXIST) {
        return 0;
    }

    return -1;
}

static int file_size_bytes(const char *path, unsigned long long *size_out)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        return -1;
    }

    *size_out = (unsigned long long)st.st_size;
    return 0;
}

static uint64_t xorshift64star(uint64_t *state)
{
    uint64_t x;

    x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

static void repetitive_state_init(struct repetitive_state *st)
{
    st->offset = 0;
}

static int write_repetitive_bytes(FILE *fp, size_t bytes, struct repetitive_state *st)
{
    static const char pattern[] = "PREDICOMP_REPETITIVE_PATTERN_0123456789abcdefghijklmnopqrstuvwxyz\n";
    const size_t pattern_len = sizeof(pattern) - 1;
    size_t remaining = bytes;

    while (remaining > 0) {
        size_t to_end = pattern_len - st->offset;
        size_t chunk = remaining < to_end ? remaining : to_end;

        if (fwrite(pattern + st->offset, 1, chunk, fp) != chunk) {
            return -1;
        }

        remaining -= chunk;
        st->offset = (st->offset + chunk) % pattern_len;
    }

    return 0;
}

static void unique_state_init(struct unique_state *st)
{
    st->state = 0x12345678ABCDEF00ULL;
    st->byte_index = 0;
}

static unsigned char next_unique_byte(struct unique_state *st)
{
    unsigned char out;

    if (st->byte_index == 0U) {
        st->state = xorshift64star(&st->state);
    }

    out = (unsigned char)((st->state >> (st->byte_index * 8U)) & 0xFFU);
    st->byte_index = (st->byte_index + 1U) & 7U;
    return out;
}

static int write_unique_bytes(FILE *fp, size_t bytes, struct unique_state *st)
{
    unsigned char buffer[4096];
    size_t remaining = bytes;

    while (remaining > 0) {
        size_t i;
        size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);

        for (i = 0; i < chunk; i++) {
            buffer[i] = next_unique_byte(st);
        }

        if (fwrite(buffer, 1, chunk, fp) != chunk) {
            return -1;
        }

        remaining -= chunk;
    }

    return 0;
}

static const char *dataset_name(enum dataset_kind kind)
{
    if (kind == DATASET_REPETITIVE) {
        return "repetitive";
    }
    if (kind == DATASET_UNIQUE) {
        return "unique";
    }
    return "mixed_50_50";
}

static int generate_sample_by_kind(FILE *fp, enum dataset_kind kind, size_t size_bytes)
{
    struct repetitive_state rep;
    struct unique_state uni;

    repetitive_state_init(&rep);
    unique_state_init(&uni);

    if (kind == DATASET_REPETITIVE) {
        return write_repetitive_bytes(fp, size_bytes, &rep);
    }

    if (kind == DATASET_UNIQUE) {
        return write_unique_bytes(fp, size_bytes, &uni);
    }

    {
        size_t rep_remaining = size_bytes / 2;
        size_t uni_remaining = size_bytes - rep_remaining;
        int turn_rep = 1;

        while (rep_remaining > 0 || uni_remaining > 0) {
            size_t chunk;

            if (turn_rep && rep_remaining > 0) {
                chunk = rep_remaining < MIX_BLOCK_SIZE ? rep_remaining : MIX_BLOCK_SIZE;
                if (write_repetitive_bytes(fp, chunk, &rep) != 0) {
                    return -1;
                }
                rep_remaining -= chunk;
            } else if (!turn_rep && uni_remaining > 0) {
                chunk = uni_remaining < MIX_BLOCK_SIZE ? uni_remaining : MIX_BLOCK_SIZE;
                if (write_unique_bytes(fp, chunk, &uni) != 0) {
                    return -1;
                }
                uni_remaining -= chunk;
            } else if (rep_remaining > 0) {
                chunk = rep_remaining < MIX_BLOCK_SIZE ? rep_remaining : MIX_BLOCK_SIZE;
                if (write_repetitive_bytes(fp, chunk, &rep) != 0) {
                    return -1;
                }
                rep_remaining -= chunk;
            } else {
                chunk = uni_remaining < MIX_BLOCK_SIZE ? uni_remaining : MIX_BLOCK_SIZE;
                if (write_unique_bytes(fp, chunk, &uni) != 0) {
                    return -1;
                }
                uni_remaining -= chunk;
            }

            turn_rep = !turn_rep;
        }
    }

    return 0;
}

static int generate_sample_if_needed(
    enum dataset_kind kind,
    size_t size_bytes,
    char *path,
    size_t path_len
)
{
    FILE *fp;
    int rc;
    unsigned long long existing_size = 0;

    rc = snprintf(path, path_len, "%s/%s_%zu.bin", SAMPLES_DIR, dataset_name(kind), size_bytes);
    if (rc < 0 || (size_t)rc >= path_len) {
        return -1;
    }

    if (file_size_bytes(path, &existing_size) == 0 && existing_size == (unsigned long long)size_bytes) {
        return 0;
    }

    fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }

    rc = generate_sample_by_kind(fp, kind, size_bytes);
    fclose(fp);

    return rc;
}

static int read_file_into_buffer(const char *path, unsigned char *buf, size_t size_bytes)
{
    FILE *fp;
    size_t read_len;

    fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }

    read_len = fread(buf, 1, size_bytes, fp);
    fclose(fp);

    if (read_len != size_bytes) {
        return -1;
    }

    return 0;
}

static int cmp_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;

    if (da < db) {
        return -1;
    }
    if (da > db) {
        return 1;
    }
    return 0;
}

static int cmp_ull(const void *a, const void *b)
{
    unsigned long long ua = *(const unsigned long long *)a;
    unsigned long long ub = *(const unsigned long long *)b;

    if (ua < ub) {
        return -1;
    }
    if (ua > ub) {
        return 1;
    }
    return 0;
}

static int median_double(const double *values, size_t n, double *out)
{
    double *tmp;

    tmp = malloc(n * sizeof(*tmp));
    if (!tmp) {
        return -1;
    }

    memcpy(tmp, values, n * sizeof(*tmp));
    qsort(tmp, n, sizeof(*tmp), cmp_double);
    *out = tmp[n / 2];
    free(tmp);
    return 0;
}

static int median_ull(const unsigned long long *values, size_t n, unsigned long long *out)
{
    unsigned long long *tmp;

    tmp = malloc(n * sizeof(*tmp));
    if (!tmp) {
        return -1;
    }

    memcpy(tmp, values, n * sizeof(*tmp));
    qsort(tmp, n, sizeof(*tmp), cmp_ull);
    *out = tmp[n / 2];
    free(tmp);
    return 0;
}

static int capture_clocks(struct clock_snapshot *snap)
{
    if (clock_gettime(CLOCK_MONOTONIC, &snap->wall) != 0) {
        return -1;
    }
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &snap->thread_cpu) != 0) {
        return -1;
    }
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &snap->process_cpu) != 0) {
        return -1;
    }
    return 0;
}

static double diff_ms(const struct timespec *start, const struct timespec *end)
{
    time_t sec = end->tv_sec - start->tv_sec;
    long nsec = end->tv_nsec - start->tv_nsec;

    return ((double)sec * 1000.0) + ((double)nsec / 1000000.0);
}

static int measure_lz4_compress(
    const struct profile *profile,
    const unsigned char *input,
    int input_size,
    unsigned char *compressed,
    int compressed_capacity,
    int *compressed_size,
    struct phase_metrics *metrics
)
{
    struct clock_snapshot start;
    struct clock_snapshot end;
    int out_size;

    if (capture_clocks(&start) != 0) {
        return -1;
    }

    if (strcmp(profile->mode_name, "fast") == 0) {
        out_size = LZ4_compress_fast(
            (const char *)input,
            (char *)compressed,
            input_size,
            compressed_capacity,
            profile->level
        );
    } else {
        out_size = LZ4_compress_HC(
            (const char *)input,
            (char *)compressed,
            input_size,
            compressed_capacity,
            profile->level
        );
    }

    if (capture_clocks(&end) != 0) {
        return -1;
    }

    if (out_size <= 0) {
        return -1;
    }

    metrics->wall_ms = diff_ms(&start.wall, &end.wall);
    metrics->thread_cpu_ms = diff_ms(&start.thread_cpu, &end.thread_cpu);
    metrics->process_cpu_ms = diff_ms(&start.process_cpu, &end.process_cpu);
    *compressed_size = out_size;

    return 0;
}

static int measure_lz4_decompress(
    const unsigned char *compressed,
    int compressed_size,
    unsigned char *decompressed,
    int expected_decompressed_size,
    struct phase_metrics *metrics
)
{
    struct clock_snapshot start;
    struct clock_snapshot end;
    int out_size;

    if (capture_clocks(&start) != 0) {
        return -1;
    }

    out_size = LZ4_decompress_safe(
        (const char *)compressed,
        (char *)decompressed,
        compressed_size,
        expected_decompressed_size
    );

    if (capture_clocks(&end) != 0) {
        return -1;
    }

    if (out_size != expected_decompressed_size) {
        return -1;
    }

    metrics->wall_ms = diff_ms(&start.wall, &end.wall);
    metrics->thread_cpu_ms = diff_ms(&start.thread_cpu, &end.thread_cpu);
    metrics->process_cpu_ms = diff_ms(&start.process_cpu, &end.process_cpu);

    return 0;
}

static int measure_zstd_compress(
    const struct profile *profile,
    const unsigned char *input,
    size_t input_size,
    unsigned char *compressed,
    size_t compressed_capacity,
    size_t *compressed_size,
    struct phase_metrics *metrics
)
{
    struct clock_snapshot start;
    struct clock_snapshot end;
    size_t out_size;

    if (capture_clocks(&start) != 0) {
        return -1;
    }

    out_size = ZSTD_compress(compressed, compressed_capacity, input, input_size, profile->level);

    if (capture_clocks(&end) != 0) {
        return -1;
    }

    if (ZSTD_isError(out_size)) {
        return -1;
    }

    metrics->wall_ms = diff_ms(&start.wall, &end.wall);
    metrics->thread_cpu_ms = diff_ms(&start.thread_cpu, &end.thread_cpu);
    metrics->process_cpu_ms = diff_ms(&start.process_cpu, &end.process_cpu);
    *compressed_size = out_size;

    return 0;
}

static int measure_zstd_decompress(
    const unsigned char *compressed,
    size_t compressed_size,
    unsigned char *decompressed,
    size_t expected_decompressed_size,
    struct phase_metrics *metrics
)
{
    struct clock_snapshot start;
    struct clock_snapshot end;
    size_t out_size;

    if (capture_clocks(&start) != 0) {
        return -1;
    }

    out_size = ZSTD_decompress(decompressed, expected_decompressed_size, compressed, compressed_size);

    if (capture_clocks(&end) != 0) {
        return -1;
    }

    if (ZSTD_isError(out_size) || out_size != expected_decompressed_size) {
        return -1;
    }

    metrics->wall_ms = diff_ms(&start.wall, &end.wall);
    metrics->thread_cpu_ms = diff_ms(&start.thread_cpu, &end.thread_cpu);
    metrics->process_cpu_ms = diff_ms(&start.process_cpu, &end.process_cpu);

    return 0;
}

static int run_one_iteration(
    const struct profile *profile,
    const unsigned char *input,
    size_t input_size,
    unsigned char *compressed,
    size_t compressed_capacity,
    unsigned char *decompressed,
    struct run_metrics *out
)
{
    memset(out, 0, sizeof(*out));

    if (profile->codec == CODEC_LZ4) {
        int compressed_size = 0;

        if (measure_lz4_compress(
            profile,
            input,
            (int)input_size,
            compressed,
            (int)compressed_capacity,
            &compressed_size,
            &out->compress
        ) != 0) {
            return -1;
        }

        if (measure_lz4_decompress(
            compressed,
            compressed_size,
            decompressed,
            (int)input_size,
            &out->decompress
        ) != 0) {
            return -1;
        }

        out->compressed_bytes = (unsigned long long)compressed_size;
    } else {
        size_t compressed_size = 0;

        if (measure_zstd_compress(
            profile,
            input,
            input_size,
            compressed,
            compressed_capacity,
            &compressed_size,
            &out->compress
        ) != 0) {
            return -1;
        }

        if (measure_zstd_decompress(
            compressed,
            compressed_size,
            decompressed,
            input_size,
            &out->decompress
        ) != 0) {
            return -1;
        }

        out->compressed_bytes = (unsigned long long)compressed_size;
    }

    out->ratio = (double)out->compressed_bytes / (double)input_size;
    out->validation_pass = (memcmp(input, decompressed, input_size) == 0);

    return out->validation_pass ? 0 : -1;
}

static int summarize_case(
    const struct profile *profile,
    const char *dataset_type,
    size_t size_bytes,
    const struct run_metrics *runs,
    int run_count,
    struct case_summary *summary
)
{
    double *comp_wall = NULL;
    double *decomp_wall = NULL;
    double *comp_thread_cpu = NULL;
    double *decomp_thread_cpu = NULL;
    double *comp_proc_cpu = NULL;
    double *decomp_proc_cpu = NULL;
    double *ratio = NULL;
    unsigned long long *compressed_bytes = NULL;
    int i;

    comp_wall = calloc((size_t)run_count, sizeof(*comp_wall));
    decomp_wall = calloc((size_t)run_count, sizeof(*decomp_wall));
    comp_thread_cpu = calloc((size_t)run_count, sizeof(*comp_thread_cpu));
    decomp_thread_cpu = calloc((size_t)run_count, sizeof(*decomp_thread_cpu));
    comp_proc_cpu = calloc((size_t)run_count, sizeof(*comp_proc_cpu));
    decomp_proc_cpu = calloc((size_t)run_count, sizeof(*decomp_proc_cpu));
    ratio = calloc((size_t)run_count, sizeof(*ratio));
    compressed_bytes = calloc((size_t)run_count, sizeof(*compressed_bytes));

    if (!comp_wall || !decomp_wall || !comp_thread_cpu || !decomp_thread_cpu ||
        !comp_proc_cpu || !decomp_proc_cpu || !ratio || !compressed_bytes) {
        free(comp_wall);
        free(decomp_wall);
        free(comp_thread_cpu);
        free(decomp_thread_cpu);
        free(comp_proc_cpu);
        free(decomp_proc_cpu);
        free(ratio);
        free(compressed_bytes);
        return -1;
    }

    summary->codec = profile->codec_name;
    summary->mode = profile->mode_name;
    summary->level = profile->level;
    summary->dataset_type = dataset_type;
    summary->size_bytes = size_bytes;
    summary->all_validation_pass = 1;

    for (i = 0; i < run_count; i++) {
        comp_wall[i] = runs[i].compress.wall_ms;
        decomp_wall[i] = runs[i].decompress.wall_ms;
        comp_thread_cpu[i] = runs[i].compress.thread_cpu_ms;
        decomp_thread_cpu[i] = runs[i].decompress.thread_cpu_ms;
        comp_proc_cpu[i] = runs[i].compress.process_cpu_ms;
        decomp_proc_cpu[i] = runs[i].decompress.process_cpu_ms;
        ratio[i] = runs[i].ratio;
        compressed_bytes[i] = runs[i].compressed_bytes;
        if (!runs[i].validation_pass) {
            summary->all_validation_pass = 0;
        }
    }

    if (median_double(comp_wall, (size_t)run_count, &summary->comp_wall_ms_median) != 0 ||
        median_double(decomp_wall, (size_t)run_count, &summary->decomp_wall_ms_median) != 0 ||
        median_double(comp_thread_cpu, (size_t)run_count, &summary->comp_thread_cpu_ms_median) != 0 ||
        median_double(decomp_thread_cpu, (size_t)run_count, &summary->decomp_thread_cpu_ms_median) != 0 ||
        median_double(comp_proc_cpu, (size_t)run_count, &summary->comp_proc_cpu_ms_median) != 0 ||
        median_double(decomp_proc_cpu, (size_t)run_count, &summary->decomp_proc_cpu_ms_median) != 0 ||
        median_double(ratio, (size_t)run_count, &summary->ratio_median) != 0 ||
        median_ull(compressed_bytes, (size_t)run_count, &summary->compressed_bytes_median) != 0) {
        free(comp_wall);
        free(decomp_wall);
        free(comp_thread_cpu);
        free(decomp_thread_cpu);
        free(comp_proc_cpu);
        free(decomp_proc_cpu);
        free(ratio);
        free(compressed_bytes);
        return -1;
    }

    summary->comp_mib_per_s_median =
        ((double)size_bytes / 1048576.0) / (summary->comp_wall_ms_median / 1000.0);
    summary->decomp_mib_per_s_median =
        ((double)size_bytes / 1048576.0) / (summary->decomp_wall_ms_median / 1000.0);

    free(comp_wall);
    free(decomp_wall);
    free(comp_thread_cpu);
    free(decomp_thread_cpu);
    free(comp_proc_cpu);
    free(decomp_proc_cpu);
    free(ratio);
    free(compressed_bytes);

    return 0;
}

static int build_size_ladder(size_t max_size, size_t **out_sizes, size_t *out_count)
{
    size_t count = 0;
    size_t value = MIN_SIZE;
    size_t *sizes;
    size_t idx = 0;

    while (value <= max_size) {
        count++;
        if (value > (SIZE_MAX / 2)) {
            break;
        }
        value *= 2;
    }

    if (count == 0) {
        return -1;
    }

    sizes = calloc(count, sizeof(*sizes));
    if (!sizes) {
        return -1;
    }

    value = MIN_SIZE;
    while (idx < count) {
        sizes[idx++] = value;
        value *= 2;
    }

    *out_sizes = sizes;
    *out_count = count;
    return 0;
}

static int build_profiles(const struct options *opts, struct profile *profiles, size_t *count)
{
    size_t idx = 0;
    static const int lz4_fast_levels[] = {1, 2, 4, 8, 16};
    static const int lz4_hc_levels[] = {3, 6, 9, 12};
    int i;

    if (opts->use_lz4) {
        for (i = 0; i < (int)(sizeof(lz4_fast_levels) / sizeof(lz4_fast_levels[0])); i++) {
            if (idx >= MAX_PROFILES) {
                return -1;
            }
            profiles[idx].codec = CODEC_LZ4;
            profiles[idx].codec_name = "lz4";
            profiles[idx].mode_name = "fast";
            profiles[idx].level = lz4_fast_levels[i];
            idx++;
        }

        for (i = 0; i < (int)(sizeof(lz4_hc_levels) / sizeof(lz4_hc_levels[0])); i++) {
            if (idx >= MAX_PROFILES) {
                return -1;
            }
            profiles[idx].codec = CODEC_LZ4;
            profiles[idx].codec_name = "lz4";
            profiles[idx].mode_name = "hc";
            profiles[idx].level = lz4_hc_levels[i];
            idx++;
        }
    }

    if (opts->use_zstd) {
        for (i = 1; i <= 19; i++) {
            if (idx >= MAX_PROFILES) {
                return -1;
            }
            profiles[idx].codec = CODEC_ZSTD;
            profiles[idx].codec_name = "zstd";
            profiles[idx].mode_name = "level";
            profiles[idx].level = i;
            idx++;
        }
    }

    if (idx == 0) {
        return -1;
    }

    *count = idx;
    return 0;
}

static void print_table_header(void)
{
    printf(
        "%-6s %-6s %-5s %-12s %-10s %-9s %-11s %-11s %-10s\n",
        "codec",
        "mode",
        "level",
        "dataset",
        "size_bytes",
        "ratio",
        "comp_ms",
        "decomp_ms",
        "valid"
    );
    printf(
        "%-6s %-6s %-5s %-12s %-10s %-9s %-11s %-11s %-10s\n",
        "------",
        "------",
        "-----",
        "------------",
        "----------",
        "---------",
        "-----------",
        "-----------",
        "----------"
    );
}

static void print_case_summary(const struct case_summary *s)
{
    printf(
        "%-6s %-6s %-5d %-12s %-10zu %-9.4f %-11.4f %-11.4f %-10s\n",
        s->codec,
        s->mode,
        s->level,
        s->dataset_type,
        s->size_bytes,
        s->ratio_median,
        s->comp_wall_ms_median,
        s->decomp_wall_ms_median,
        s->all_validation_pass ? "PASS" : "FAIL"
    );
}

static int write_csv_header(FILE *csv)
{
    return fprintf(
        csv,
        "codec,mode,level,dataset_type,size_bytes,runs,warmups,"
        "compressed_bytes_median,ratio_median,"
        "comp_wall_ms_median,decomp_wall_ms_median,"
        "comp_thread_cpu_ms_median,decomp_thread_cpu_ms_median,"
        "comp_proc_cpu_ms_median,decomp_proc_cpu_ms_median,"
        "comp_mib_per_s_median,decomp_mib_per_s_median,validation\n"
    ) < 0 ? -1 : 0;
}

static int append_csv_row(FILE *csv, const struct case_summary *s, const struct options *opts)
{
    return fprintf(
        csv,
        "%s,%s,%d,%s,%zu,%d,%d,%llu,%.8f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%s\n",
        s->codec,
        s->mode,
        s->level,
        s->dataset_type,
        s->size_bytes,
        opts->runs,
        opts->warmups,
        s->compressed_bytes_median,
        s->ratio_median,
        s->comp_wall_ms_median,
        s->decomp_wall_ms_median,
        s->comp_thread_cpu_ms_median,
        s->decomp_thread_cpu_ms_median,
        s->comp_proc_cpu_ms_median,
        s->decomp_proc_cpu_ms_median,
        s->comp_mib_per_s_median,
        s->decomp_mib_per_s_median,
        s->all_validation_pass ? "PASS" : "FAIL"
    ) < 0 ? -1 : 0;
}

int main(int argc, char **argv)
{
    static const enum dataset_kind datasets[] = {
        DATASET_REPETITIVE,
        DATASET_UNIQUE,
        DATASET_MIXED_50_50,
    };

    struct options opts;
    struct profile profiles[MAX_PROFILES];
    size_t profile_count = 0;
    size_t *sizes = NULL;
    size_t size_count = 0;
    FILE *csv = NULL;
    int had_failure = 0;
    size_t p;
    size_t d;
    size_t s;

    if (parse_options(argc, argv, &opts) != 0) {
        print_usage(argv[0]);
        return 1;
    }

    if (opts.use_cpu_pin && pin_to_cpu(opts.cpu_id) != 0) {
        fprintf(stderr, "error: failed to pin to cpu %ld: %s\n", opts.cpu_id, strerror(errno));
        return 1;
    }

    if (build_profiles(&opts, profiles, &profile_count) != 0) {
        fprintf(stderr, "error: failed to build codec profiles\n");
        return 1;
    }

    if (ensure_dir_exists(SAMPLES_DIR) != 0) {
        fprintf(stderr, "error: failed to create '%s': %s\n", SAMPLES_DIR, strerror(errno));
        return 1;
    }

    if (build_size_ladder(opts.max_size, &sizes, &size_count) != 0) {
        fprintf(stderr, "error: failed to build size ladder\n");
        return 1;
    }

    csv = fopen(RESULTS_CSV, "w");
    if (!csv) {
        fprintf(stderr, "error: failed to open '%s': %s\n", RESULTS_CSV, strerror(errno));
        free(sizes);
        return 1;
    }

    if (write_csv_header(csv) != 0) {
        fprintf(stderr, "error: failed to write csv header\n");
        fclose(csv);
        free(sizes);
        return 1;
    }

    printf("=== compressor-monitor level sweep ===\n");
    printf(
        "profiles=%zu datasets=3 sizes=%zu runs=%d warmups=%d",
        profile_count,
        size_count,
        opts.runs,
        opts.warmups
    );
    if (opts.use_cpu_pin) {
        printf(" cpu_pin=%ld", opts.cpu_id);
    }
    printf("\n\n");

    print_table_header();

    for (p = 0; p < profile_count; p++) {
        const struct profile *profile = &profiles[p];

        for (d = 0; d < (sizeof(datasets) / sizeof(datasets[0])); d++) {
            enum dataset_kind kind = datasets[d];

            for (s = 0; s < size_count; s++) {
                size_t size_bytes = sizes[s];
                const char *name = dataset_name(kind);
                char sample_path[512];
                unsigned long long sample_size = 0;
                unsigned char *input_buf = NULL;
                unsigned char *compressed_buf = NULL;
                unsigned char *decompressed_buf = NULL;
                struct run_metrics *measured_runs = NULL;
                size_t compressed_capacity;
                int lz4_bound;
                size_t zstd_bound;
                int total_iterations;
                int iter;
                int measured_idx = 0;
                struct case_summary summary;

                if (generate_sample_if_needed(kind, size_bytes, sample_path, sizeof(sample_path)) != 0) {
                    fprintf(stderr, "error: failed to generate sample %s size=%zu\n", name, size_bytes);
                    fclose(csv);
                    free(sizes);
                    return 1;
                }

                if (file_size_bytes(sample_path, &sample_size) != 0 || sample_size != (unsigned long long)size_bytes) {
                    fprintf(stderr, "error: sample size mismatch for %s size=%zu\n", name, size_bytes);
                    fclose(csv);
                    free(sizes);
                    return 1;
                }

                input_buf = malloc(size_bytes);
                if (!input_buf) {
                    fprintf(stderr, "error: input allocation failed size=%zu\n", size_bytes);
                    fclose(csv);
                    free(sizes);
                    return 1;
                }

                if (read_file_into_buffer(sample_path, input_buf, size_bytes) != 0) {
                    fprintf(stderr, "error: failed to read sample '%s'\n", sample_path);
                    free(input_buf);
                    fclose(csv);
                    free(sizes);
                    return 1;
                }

                lz4_bound = LZ4_compressBound((int)size_bytes);
                if (lz4_bound <= 0) {
                    fprintf(stderr, "error: LZ4_compressBound failed for size=%zu\n", size_bytes);
                    free(input_buf);
                    fclose(csv);
                    free(sizes);
                    return 1;
                }
                zstd_bound = ZSTD_compressBound(size_bytes);
                compressed_capacity = (size_t)lz4_bound > zstd_bound ? (size_t)lz4_bound : zstd_bound;
                compressed_buf = malloc(compressed_capacity);
                decompressed_buf = malloc(size_bytes);
                measured_runs = calloc((size_t)opts.runs, sizeof(*measured_runs));

                if (!compressed_buf || !decompressed_buf || !measured_runs) {
                    fprintf(stderr, "error: buffer allocation failed for size=%zu\n", size_bytes);
                    free(input_buf);
                    free(compressed_buf);
                    free(decompressed_buf);
                    free(measured_runs);
                    fclose(csv);
                    free(sizes);
                    return 1;
                }

                total_iterations = opts.warmups + opts.runs;
                for (iter = 0; iter < total_iterations; iter++) {
                    struct run_metrics run;

                    if (run_one_iteration(
                        profile,
                        input_buf,
                        size_bytes,
                        compressed_buf,
                        compressed_capacity,
                        decompressed_buf,
                        &run
                    ) != 0) {
                        fprintf(
                            stderr,
                            "error: benchmark failed codec=%s mode=%s level=%d dataset=%s size=%zu iteration=%d\n",
                            profile->codec_name,
                            profile->mode_name,
                            profile->level,
                            name,
                            size_bytes,
                            iter
                        );
                        free(input_buf);
                        free(compressed_buf);
                        free(decompressed_buf);
                        free(measured_runs);
                        fclose(csv);
                        free(sizes);
                        return 1;
                    }

                    if (iter >= opts.warmups) {
                        measured_runs[measured_idx++] = run;
                    }
                }

                if (summarize_case(profile, name, size_bytes, measured_runs, opts.runs, &summary) != 0) {
                    fprintf(
                        stderr,
                        "error: failed to summarize case codec=%s mode=%s level=%d dataset=%s size=%zu\n",
                        profile->codec_name,
                        profile->mode_name,
                        profile->level,
                        name,
                        size_bytes
                    );
                    free(input_buf);
                    free(compressed_buf);
                    free(decompressed_buf);
                    free(measured_runs);
                    fclose(csv);
                    free(sizes);
                    return 1;
                }

                print_case_summary(&summary);

                if (append_csv_row(csv, &summary, &opts) != 0) {
                    fprintf(stderr, "error: failed to write csv row\n");
                    free(input_buf);
                    free(compressed_buf);
                    free(decompressed_buf);
                    free(measured_runs);
                    fclose(csv);
                    free(sizes);
                    return 1;
                }

                if (!summary.all_validation_pass) {
                    had_failure = 1;
                }

                free(input_buf);
                free(compressed_buf);
                free(decompressed_buf);
                free(measured_runs);
            }
        }
    }

    fclose(csv);
    free(sizes);

    printf("\nresults_csv: %s\n", RESULTS_CSV);

    if (had_failure) {
        fprintf(stderr, "error: one or more cases failed validation\n");
        return 1;
    }

    return 0;
}
