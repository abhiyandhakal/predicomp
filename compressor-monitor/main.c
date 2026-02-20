#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define RESULTS_CSV "compressor-monitor/results.csv"
#define SAMPLES_DIR "compressor-monitor/samples"
#define RUNS_PER_CASE 5

struct sched_snapshot {
    double vruntime;
    double sum_exec_runtime;
    unsigned long long nr_switches;
    unsigned long long nr_voluntary_switches;
    unsigned long long nr_involuntary_switches;
};

struct sched_delta {
    double vruntime;
    double sum_exec_runtime;
    long long nr_switches;
    long long nr_voluntary_switches;
    long long nr_involuntary_switches;
};

struct run_metrics {
    double compression_ms;
    double decompression_ms;
    unsigned long long input_bytes;
    unsigned long long compressed_bytes;
    double ratio;
    struct sched_delta compress_sched;
    struct sched_delta decompress_sched;
    int validation_pass;
};

struct case_summary {
    const char *dataset_type;
    size_t size_bytes;
    double compression_ms_median;
    double decompression_ms_median;
    unsigned long long compressed_bytes_median;
    double ratio_median;
    struct sched_delta compress_sched_median;
    struct sched_delta decompress_sched_median;
    int all_validation_pass;
};

static int check_lz4_available(void)
{
    int rc;

    rc = system("command -v lz4 >/dev/null 2>&1");
    if (rc != 0) {
        return -1;
    }

    return 0;
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

static int compare_files(const char *path_a, const char *path_b)
{
    FILE *fa;
    FILE *fb;
    unsigned char buf_a[4096];
    unsigned char buf_b[4096];
    size_t na;
    size_t nb;

    fa = fopen(path_a, "rb");
    if (!fa) {
        return -1;
    }

    fb = fopen(path_b, "rb");
    if (!fb) {
        fclose(fa);
        return -1;
    }

    while (1) {
        na = fread(buf_a, 1, sizeof(buf_a), fa);
        nb = fread(buf_b, 1, sizeof(buf_b), fb);

        if (na != nb) {
            fclose(fa);
            fclose(fb);
            return 0;
        }

        if (na == 0) {
            break;
        }

        if (memcmp(buf_a, buf_b, na) != 0) {
            fclose(fa);
            fclose(fb);
            return 0;
        }
    }

    fclose(fa);
    fclose(fb);
    return 1;
}

static int parse_sched_snapshot(struct sched_snapshot *out)
{
    FILE *fp;
    char line[512];
    int got_vruntime = 0;
    int got_sum_exec_runtime = 0;
    int got_nr_switches = 0;
    int got_nr_voluntary = 0;
    int got_nr_involuntary = 0;

    memset(out, 0, sizeof(*out));

    fp = fopen("/proc/self/sched", "r");
    if (!fp) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "se.vruntime%*[^:]: %lf", &out->vruntime) == 1) {
            got_vruntime = 1;
        } else if (sscanf(line, "se.sum_exec_runtime%*[^:]: %lf", &out->sum_exec_runtime) == 1) {
            got_sum_exec_runtime = 1;
        } else if (sscanf(line, "nr_switches%*[^:]: %llu", &out->nr_switches) == 1) {
            got_nr_switches = 1;
        } else if (sscanf(
            line,
            "nr_voluntary_switches%*[^:]: %llu",
            &out->nr_voluntary_switches
        ) == 1) {
            got_nr_voluntary = 1;
        } else if (sscanf(
            line,
            "nr_involuntary_switches%*[^:]: %llu",
            &out->nr_involuntary_switches
        ) == 1) {
            got_nr_involuntary = 1;
        }
    }

    fclose(fp);

    if (!got_vruntime ||
        !got_sum_exec_runtime ||
        !got_nr_switches ||
        !got_nr_voluntary ||
        !got_nr_involuntary) {
        return -1;
    }

    return 0;
}

static struct sched_delta compute_delta(
    const struct sched_snapshot *before,
    const struct sched_snapshot *after
)
{
    struct sched_delta d;

    d.vruntime = after->vruntime - before->vruntime;
    d.sum_exec_runtime = after->sum_exec_runtime - before->sum_exec_runtime;
    d.nr_switches = (long long)after->nr_switches - (long long)before->nr_switches;
    d.nr_voluntary_switches =
        (long long)after->nr_voluntary_switches - (long long)before->nr_voluntary_switches;
    d.nr_involuntary_switches =
        (long long)after->nr_involuntary_switches - (long long)before->nr_involuntary_switches;

    return d;
}

static int run_timed_command(const char *cmd, double *elapsed_ms)
{
    struct timespec start;
    struct timespec end;
    long sec_diff;
    long nsec_diff;
    int rc;

    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        return -1;
    }

    rc = system(cmd);

    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
        return -1;
    }

    sec_diff = end.tv_sec - start.tv_sec;
    nsec_diff = end.tv_nsec - start.tv_nsec;
    *elapsed_ms = ((double)sec_diff * 1000.0) + ((double)nsec_diff / 1000000.0);

    if (rc != 0) {
        return rc;
    }

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

static int write_repetitive_sample(FILE *fp, size_t size_bytes)
{
    static const char pattern[] = "PREDICOMP_REPETITIVE_PATTERN_0123456789abcdefghijklmnopqrstuvwxyz\n";
    size_t pattern_len = sizeof(pattern) - 1;
    size_t written = 0;

    while (written < size_bytes) {
        size_t chunk = pattern_len;

        if (chunk > (size_bytes - written)) {
            chunk = size_bytes - written;
        }

        if (fwrite(pattern, 1, chunk, fp) != chunk) {
            return -1;
        }

        written += chunk;
    }

    return 0;
}

static int write_unique_sample(FILE *fp, size_t size_bytes)
{
    unsigned char buffer[4096];
    size_t written = 0;
    uint64_t state = 0x12345678ABCDEF00ULL;

    while (written < size_bytes) {
        size_t i;
        size_t chunk = sizeof(buffer);

        if (chunk > (size_bytes - written)) {
            chunk = size_bytes - written;
        }

        for (i = 0; i < chunk; i++) {
            if ((i % 8) == 0) {
                state = xorshift64star(&state);
            }
            buffer[i] = (unsigned char)((state >> ((i % 8) * 8)) & 0xFF);
        }

        if (fwrite(buffer, 1, chunk, fp) != chunk) {
            return -1;
        }

        written += chunk;
    }

    return 0;
}

static int generate_sample_if_needed(const char *dataset_type, size_t size_bytes, char *path, size_t path_len)
{
    FILE *fp;
    unsigned long long existing_size = 0;
    int rc;

    rc = snprintf(path, path_len, "%s/%s_%zu.bin", SAMPLES_DIR, dataset_type, size_bytes);
    if (rc < 0 || (size_t)rc >= path_len) {
        return -1;
    }

    if (file_size_bytes(path, &existing_size) == 0) {
        if (existing_size == (unsigned long long)size_bytes) {
            return 0;
        }
    }

    fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }

    if (strcmp(dataset_type, "repetitive") == 0) {
        rc = write_repetitive_sample(fp, size_bytes);
    } else if (strcmp(dataset_type, "unique") == 0) {
        rc = write_unique_sample(fp, size_bytes);
    } else {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    if (rc != 0) {
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

static int cmp_ll(const void *a, const void *b)
{
    long long la = *(const long long *)a;
    long long lb = *(const long long *)b;

    if (la < lb) {
        return -1;
    }
    if (la > lb) {
        return 1;
    }
    return 0;
}

static double median_double(const double *values, size_t n)
{
    double tmp[RUNS_PER_CASE];

    memcpy(tmp, values, n * sizeof(double));
    qsort(tmp, n, sizeof(double), cmp_double);
    return tmp[n / 2];
}

static unsigned long long median_ull(const unsigned long long *values, size_t n)
{
    unsigned long long tmp[RUNS_PER_CASE];

    memcpy(tmp, values, n * sizeof(unsigned long long));
    qsort(tmp, n, sizeof(unsigned long long), cmp_ull);
    return tmp[n / 2];
}

static long long median_ll(const long long *values, size_t n)
{
    long long tmp[RUNS_PER_CASE];

    memcpy(tmp, values, n * sizeof(long long));
    qsort(tmp, n, sizeof(long long), cmp_ll);
    return tmp[n / 2];
}

static struct sched_delta median_sched_delta(const struct sched_delta *deltas, size_t n)
{
    struct sched_delta out;
    double vruntime_vals[RUNS_PER_CASE];
    double sum_exec_vals[RUNS_PER_CASE];
    long long switches_vals[RUNS_PER_CASE];
    long long voluntary_vals[RUNS_PER_CASE];
    long long involuntary_vals[RUNS_PER_CASE];
    size_t i;

    for (i = 0; i < n; i++) {
        vruntime_vals[i] = deltas[i].vruntime;
        sum_exec_vals[i] = deltas[i].sum_exec_runtime;
        switches_vals[i] = deltas[i].nr_switches;
        voluntary_vals[i] = deltas[i].nr_voluntary_switches;
        involuntary_vals[i] = deltas[i].nr_involuntary_switches;
    }

    out.vruntime = median_double(vruntime_vals, n);
    out.sum_exec_runtime = median_double(sum_exec_vals, n);
    out.nr_switches = median_ll(switches_vals, n);
    out.nr_voluntary_switches = median_ll(voluntary_vals, n);
    out.nr_involuntary_switches = median_ll(involuntary_vals, n);

    return out;
}

static int benchmark_one_run(
    const char *input_path,
    const char *compressed_path,
    const char *decompressed_path,
    struct run_metrics *out
)
{
    struct sched_snapshot compress_before;
    struct sched_snapshot compress_after;
    struct sched_snapshot decompress_before;
    struct sched_snapshot decompress_after;
    unsigned long long decompressed_size;
    int cmp;
    int rc;
    char cmd[1024];

    memset(out, 0, sizeof(*out));

    if (file_size_bytes(input_path, &out->input_bytes) != 0) {
        return -1;
    }

    if (parse_sched_snapshot(&compress_before) != 0) {
        return -1;
    }

    rc = snprintf(
        cmd,
        sizeof(cmd),
        "lz4 -q -f '%s' '%s' >/dev/null 2>&1",
        input_path,
        compressed_path
    );
    if (rc < 0 || (size_t)rc >= sizeof(cmd)) {
        return -1;
    }

    rc = run_timed_command(cmd, &out->compression_ms);
    if (rc != 0) {
        return -1;
    }

    if (parse_sched_snapshot(&compress_after) != 0) {
        return -1;
    }

    if (parse_sched_snapshot(&decompress_before) != 0) {
        return -1;
    }

    rc = snprintf(
        cmd,
        sizeof(cmd),
        "lz4 -q -d -f '%s' '%s' >/dev/null 2>&1",
        compressed_path,
        decompressed_path
    );
    if (rc < 0 || (size_t)rc >= sizeof(cmd)) {
        return -1;
    }

    rc = run_timed_command(cmd, &out->decompression_ms);
    if (rc != 0) {
        return -1;
    }

    if (parse_sched_snapshot(&decompress_after) != 0) {
        return -1;
    }

    if (file_size_bytes(compressed_path, &out->compressed_bytes) != 0) {
        return -1;
    }

    if (file_size_bytes(decompressed_path, &decompressed_size) != 0) {
        return -1;
    }

    if (decompressed_size != out->input_bytes) {
        out->validation_pass = 0;
    }

    cmp = compare_files(input_path, decompressed_path);
    if (cmp < 0) {
        return -1;
    }
    out->validation_pass = (cmp == 1);

    out->ratio = (double)out->compressed_bytes / (double)out->input_bytes;
    out->compress_sched = compute_delta(&compress_before, &compress_after);
    out->decompress_sched = compute_delta(&decompress_before, &decompress_after);

    return 0;
}

static int summarize_case(
    const char *dataset_type,
    size_t size_bytes,
    const struct run_metrics *runs,
    struct case_summary *summary
)
{
    double compression_ms_vals[RUNS_PER_CASE];
    double decompression_ms_vals[RUNS_PER_CASE];
    unsigned long long compressed_bytes_vals[RUNS_PER_CASE];
    double ratio_vals[RUNS_PER_CASE];
    struct sched_delta compress_deltas[RUNS_PER_CASE];
    struct sched_delta decompress_deltas[RUNS_PER_CASE];
    size_t i;

    summary->dataset_type = dataset_type;
    summary->size_bytes = size_bytes;
    summary->all_validation_pass = 1;

    for (i = 0; i < RUNS_PER_CASE; i++) {
        compression_ms_vals[i] = runs[i].compression_ms;
        decompression_ms_vals[i] = runs[i].decompression_ms;
        compressed_bytes_vals[i] = runs[i].compressed_bytes;
        ratio_vals[i] = runs[i].ratio;
        compress_deltas[i] = runs[i].compress_sched;
        decompress_deltas[i] = runs[i].decompress_sched;

        if (!runs[i].validation_pass) {
            summary->all_validation_pass = 0;
        }
    }

    summary->compression_ms_median = median_double(compression_ms_vals, RUNS_PER_CASE);
    summary->decompression_ms_median = median_double(decompression_ms_vals, RUNS_PER_CASE);
    summary->compressed_bytes_median = median_ull(compressed_bytes_vals, RUNS_PER_CASE);
    summary->ratio_median = median_double(ratio_vals, RUNS_PER_CASE);
    summary->compress_sched_median = median_sched_delta(compress_deltas, RUNS_PER_CASE);
    summary->decompress_sched_median = median_sched_delta(decompress_deltas, RUNS_PER_CASE);

    return 0;
}

static void print_table_header(void)
{
    printf(
        "%-11s %-10s %-10s %-12s %-12s %-10s\n",
        "type",
        "size_bytes",
        "ratio",
        "comp_ms",
        "decomp_ms",
        "validation"
    );
    printf(
        "%-11s %-10s %-10s %-12s %-12s %-10s\n",
        "-----------",
        "----------",
        "----------",
        "------------",
        "------------",
        "----------"
    );
}

static void print_case_summary_row(const struct case_summary *s)
{
    printf(
        "%-11s %-10zu %-10.4f %-12.4f %-12.4f %-10s\n",
        s->dataset_type,
        s->size_bytes,
        s->ratio_median,
        s->compression_ms_median,
        s->decompression_ms_median,
        s->all_validation_pass ? "PASS" : "FAIL"
    );
}

static void print_sched_medians(const struct case_summary *s)
{
    printf(
        "  sched-compress: vruntime=%.6f sum_exec=%.6f switches=%lld voluntary=%lld involuntary=%lld\n",
        s->compress_sched_median.vruntime,
        s->compress_sched_median.sum_exec_runtime,
        s->compress_sched_median.nr_switches,
        s->compress_sched_median.nr_voluntary_switches,
        s->compress_sched_median.nr_involuntary_switches
    );
    printf(
        "  sched-decomp  : vruntime=%.6f sum_exec=%.6f switches=%lld voluntary=%lld involuntary=%lld\n",
        s->decompress_sched_median.vruntime,
        s->decompress_sched_median.sum_exec_runtime,
        s->decompress_sched_median.nr_switches,
        s->decompress_sched_median.nr_voluntary_switches,
        s->decompress_sched_median.nr_involuntary_switches
    );
}

static int write_csv_header(FILE *csv)
{
    int rc;

    rc = fprintf(
        csv,
        "dataset_type,size_bytes,runs,"
        "compression_ms_median,decompression_ms_median,"
        "compressed_bytes_median,ratio_median,validation,"
        "compress_vruntime_median,compress_sum_exec_runtime_median,"
        "compress_nr_switches_median,compress_nr_voluntary_switches_median,"
        "compress_nr_involuntary_switches_median,"
        "decompress_vruntime_median,decompress_sum_exec_runtime_median,"
        "decompress_nr_switches_median,decompress_nr_voluntary_switches_median,"
        "decompress_nr_involuntary_switches_median\n"
    );

    return rc < 0 ? -1 : 0;
}

static int append_csv_row(FILE *csv, const struct case_summary *s)
{
    int rc;

    rc = fprintf(
        csv,
        "%s,%zu,%d,%.6f,%.6f,%llu,%.8f,%s,"
        "%.6f,%.6f,%lld,%lld,%lld,"
        "%.6f,%.6f,%lld,%lld,%lld\n",
        s->dataset_type,
        s->size_bytes,
        RUNS_PER_CASE,
        s->compression_ms_median,
        s->decompression_ms_median,
        s->compressed_bytes_median,
        s->ratio_median,
        s->all_validation_pass ? "PASS" : "FAIL",
        s->compress_sched_median.vruntime,
        s->compress_sched_median.sum_exec_runtime,
        s->compress_sched_median.nr_switches,
        s->compress_sched_median.nr_voluntary_switches,
        s->compress_sched_median.nr_involuntary_switches,
        s->decompress_sched_median.vruntime,
        s->decompress_sched_median.sum_exec_runtime,
        s->decompress_sched_median.nr_switches,
        s->decompress_sched_median.nr_voluntary_switches,
        s->decompress_sched_median.nr_involuntary_switches
    );

    return rc < 0 ? -1 : 0;
}

int main(void)
{
    static const size_t sizes[] = {
        1024,
        2048,
        4096,
        8192,
        16384,
        32768,
        65536,
        131072,
        262144,
        524288,
        1048576,
        2097152,
        4194304,
        8388608,
        16777216
    };
    static const char *dataset_types[] = {"repetitive", "unique"};

    size_t t;
    size_t s;
    int had_failure = 0;
    FILE *csv;

    if (check_lz4_available() != 0) {
        fprintf(stderr, "error: lz4 CLI not found in PATH\n");
        fprintf(stderr, "hint: install lz4 and re-run\n");
        return 1;
    }

    if (ensure_dir_exists(SAMPLES_DIR) != 0) {
        fprintf(stderr, "error: failed to create '%s': %s\n", SAMPLES_DIR, strerror(errno));
        return 1;
    }

    /* Clean old single-file artifacts to avoid confusion with suite outputs. */
    unlink("compressor-monitor/test.txt.lz4");
    unlink("compressor-monitor/test.txt.out");

    csv = fopen(RESULTS_CSV, "w");
    if (!csv) {
        fprintf(stderr, "error: failed to open results CSV '%s': %s\n", RESULTS_CSV, strerror(errno));
        return 1;
    }

    if (write_csv_header(csv) != 0) {
        fprintf(stderr, "error: failed to write CSV header\n");
        fclose(csv);
        return 1;
    }

    printf("=== compressor-monitor synthetic benchmark (LZ4) ===\n");
    printf("runs_per_case=%d sizes=1KB..16MB datasets=repetitive,unique\n\n", RUNS_PER_CASE);
    print_table_header();

    for (t = 0; t < (sizeof(dataset_types) / sizeof(dataset_types[0])); t++) {
        for (s = 0; s < (sizeof(sizes) / sizeof(sizes[0])); s++) {
            const char *dataset_type = dataset_types[t];
            size_t size_bytes = sizes[s];
            char input_path[512];
            char compressed_path[512];
            char decompressed_path[512];
            struct run_metrics runs[RUNS_PER_CASE];
            struct case_summary summary;
            size_t r;

            if (generate_sample_if_needed(dataset_type, size_bytes, input_path, sizeof(input_path)) != 0) {
                fprintf(
                    stderr,
                    "error: failed to generate sample type=%s size=%zu\n",
                    dataset_type,
                    size_bytes
                );
                fclose(csv);
                return 1;
            }

            if (snprintf(compressed_path, sizeof(compressed_path), "%s.lz4.tmp", input_path) >= (int)sizeof(compressed_path)) {
                fclose(csv);
                return 1;
            }

            if (snprintf(decompressed_path, sizeof(decompressed_path), "%s.out.tmp", input_path) >= (int)sizeof(decompressed_path)) {
                fclose(csv);
                return 1;
            }

            for (r = 0; r < RUNS_PER_CASE; r++) {
                if (benchmark_one_run(input_path, compressed_path, decompressed_path, &runs[r]) != 0) {
                    fprintf(
                        stderr,
                        "error: benchmark run failed type=%s size=%zu run=%zu\n",
                        dataset_type,
                        size_bytes,
                        r + 1
                    );
                    unlink(compressed_path);
                    unlink(decompressed_path);
                    fclose(csv);
                    return 1;
                }

                unlink(compressed_path);
                unlink(decompressed_path);
            }

            summarize_case(dataset_type, size_bytes, runs, &summary);
            print_case_summary_row(&summary);
            print_sched_medians(&summary);

            if (append_csv_row(csv, &summary) != 0) {
                fprintf(stderr, "error: failed to write CSV row\n");
                fclose(csv);
                return 1;
            }

            if (!summary.all_validation_pass) {
                had_failure = 1;
            }
        }
    }

    fclose(csv);
    printf("\nresults_csv: %s\n", RESULTS_CSV);

    if (had_failure) {
        fprintf(stderr, "error: one or more benchmark cases failed validation\n");
        return 1;
    }

    return 0;
}
