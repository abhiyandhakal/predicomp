#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define INPUT_PATH "compressor-monitor/test.txt"
#define COMPRESSED_PATH "compressor-monitor/test.txt.lz4"
#define DECOMPRESSED_PATH "compressor-monitor/test.txt.out"

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
        } else if (sscanf(
            line,
            "se.sum_exec_runtime%*[^:]: %lf",
            &out->sum_exec_runtime
        ) == 1) {
            got_sum_exec_runtime = 1;
        } else if (sscanf(
            line,
            "nr_switches%*[^:]: %llu",
            &out->nr_switches
        ) == 1) {
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

static int check_lz4_available(void)
{
    int rc;

    rc = system("command -v lz4 >/dev/null 2>&1");
    if (rc != 0) {
        return -1;
    }

    return 0;
}

int main(void)
{
    struct sched_snapshot compress_before;
    struct sched_snapshot compress_after;
    struct sched_snapshot decompress_before;
    struct sched_snapshot decompress_after;
    struct sched_delta compress_delta;
    struct sched_delta decompress_delta;
    unsigned long long input_size = 0;
    unsigned long long compressed_size = 0;
    unsigned long long decompressed_size = 0;
    double compression_ms = 0.0;
    double decompression_ms = 0.0;
    int cmp;
    int rc;

    if (check_lz4_available() != 0) {
        fprintf(stderr, "error: lz4 CLI not found in PATH\n");
        fprintf(stderr, "hint: install lz4 and re-run\n");
        return 1;
    }

    if (file_size_bytes(INPUT_PATH, &input_size) != 0) {
        fprintf(stderr, "error: failed to stat input file '%s': %s\n", INPUT_PATH, strerror(errno));
        return 1;
    }

    if (parse_sched_snapshot(&compress_before) != 0) {
        fprintf(stderr, "error: failed to parse /proc/self/sched before compression\n");
        return 1;
    }

    rc = run_timed_command(
        "lz4 -q -f compressor-monitor/test.txt compressor-monitor/test.txt.lz4 >/dev/null 2>&1",
        &compression_ms
    );
    if (rc != 0) {
        fprintf(stderr, "error: compression command failed (rc=%d)\n", rc);
        return 1;
    }

    if (parse_sched_snapshot(&compress_after) != 0) {
        fprintf(stderr, "error: failed to parse /proc/self/sched after compression\n");
        return 1;
    }

    if (parse_sched_snapshot(&decompress_before) != 0) {
        fprintf(stderr, "error: failed to parse /proc/self/sched before decompression\n");
        return 1;
    }

    rc = run_timed_command(
        "lz4 -q -d -f compressor-monitor/test.txt.lz4 compressor-monitor/test.txt.out >/dev/null 2>&1",
        &decompression_ms
    );
    if (rc != 0) {
        fprintf(stderr, "error: decompression command failed (rc=%d)\n", rc);
        return 1;
    }

    if (parse_sched_snapshot(&decompress_after) != 0) {
        fprintf(stderr, "error: failed to parse /proc/self/sched after decompression\n");
        return 1;
    }

    if (file_size_bytes(COMPRESSED_PATH, &compressed_size) != 0) {
        fprintf(stderr, "error: failed to stat compressed file '%s': %s\n", COMPRESSED_PATH, strerror(errno));
        return 1;
    }

    if (file_size_bytes(DECOMPRESSED_PATH, &decompressed_size) != 0) {
        fprintf(stderr, "error: failed to stat decompressed file '%s': %s\n", DECOMPRESSED_PATH, strerror(errno));
        return 1;
    }

    cmp = compare_files(INPUT_PATH, DECOMPRESSED_PATH);
    if (cmp < 0) {
        fprintf(stderr, "error: failed to compare files\n");
        return 1;
    }

    compress_delta = compute_delta(&compress_before, &compress_after);
    decompress_delta = compute_delta(&decompress_before, &decompress_after);

    printf("=== compressor-monitor (LZ4) ===\n");
    printf("input_file          : %s\n", INPUT_PATH);
    printf("compressed_file     : %s\n", COMPRESSED_PATH);
    printf("decompressed_file   : %s\n", DECOMPRESSED_PATH);
    printf("\n");

    printf("[file sizes]\n");
    printf("input_bytes         : %llu\n", input_size);
    printf("compressed_bytes    : %llu\n", compressed_size);
    printf("decompressed_bytes  : %llu\n", decompressed_size);
    printf("\n");

    printf("[timings]\n");
    printf("compression_ms      : %.6f\n", compression_ms);
    printf("decompression_ms    : %.6f\n", decompression_ms);
    printf("\n");

    printf("[sched delta - compression]\n");
    printf("se.vruntime         : %.6f\n", compress_delta.vruntime);
    printf("se.sum_exec_runtime : %.6f\n", compress_delta.sum_exec_runtime);
    printf("nr_switches         : %lld\n", compress_delta.nr_switches);
    printf("nr_voluntary        : %lld\n", compress_delta.nr_voluntary_switches);
    printf("nr_involuntary      : %lld\n", compress_delta.nr_involuntary_switches);
    printf("\n");

    printf("[sched delta - decompression]\n");
    printf("se.vruntime         : %.6f\n", decompress_delta.vruntime);
    printf("se.sum_exec_runtime : %.6f\n", decompress_delta.sum_exec_runtime);
    printf("nr_switches         : %lld\n", decompress_delta.nr_switches);
    printf("nr_voluntary        : %lld\n", decompress_delta.nr_voluntary_switches);
    printf("nr_involuntary      : %lld\n", decompress_delta.nr_involuntary_switches);
    printf("\n");

    printf("validation          : %s\n", cmp == 1 ? "PASS" : "FAIL");

    if (cmp != 1) {
        return 1;
    }

    return 0;
}
