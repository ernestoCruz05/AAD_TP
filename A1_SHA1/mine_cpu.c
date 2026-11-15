#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "aad_data_types.h"
#include "aad_utilities.h"
#include "mine_file.h"
#include "mine_scalar.h"
#include "mine_avx.h"

#define MINE_STEP (1ul << 20)

typedef u32_t (*mine_engine_t)(const mine_job_t *job, u32_t zero_bits,
                               u64_t first, u64_t count, u64_t *hits,
                               u32_t max_hits);

static const struct {
    const char *name;
    mine_engine_t run;
} engines[] = {
    {"scalar", mine_scalar},
#if defined(__AVX__)
    {"avx", mine_avx},
#endif
#if defined(__AVX2__)
    {"avx2", mine_avx2},
#endif
};

static void usage(void) {
    fprintf(
        stderr,
        "usage: mine_cpu [-e scalar|avx|avx2] [-b zero_bits] input output\n");
    fprintf(stderr, "       mine_cpu [-e scalar|avx|avx2] [-b zero_bits] -t "
                    "seconds input\n");
    exit(1);
}

int main(int argc, char **argv) {
    size_t engine = 0u;
    u32_t zero_bits = 32u;
    double seconds = 0.0;
    char *end;
    int opt;

    while ((opt = getopt(argc, argv, "e:b:t:")) != -1)
        switch (opt) {
        case 'e':
            for (engine = 0u; engine < sizeof(engines) / sizeof(engines[0]) &&
                              strcmp(optarg, engines[engine].name) != 0;
                 engine++)
                ;
            if (engine == sizeof(engines) / sizeof(engines[0]))
                usage();
            break;
        case 'b': {
            unsigned long bits = strtoul(optarg, &end, 10);

            if (*optarg == '\0' || *end != '\0' || bits < 1ul || bits > 32ul)
                usage();
            zero_bits = (u32_t)bits;
            break;
        }
        case 't':
            seconds = strtod(optarg, &end);
            if (*optarg == '\0' || *end != '\0' || !(seconds > 0.0))
                usage();
            break;
        default:
            usage();
        }
    const int bench = seconds > 0.0;
    if (argc - optind != (bench ? 1 : 2))
        usage();

    mine_file_t f;
    mine_job_t job;
    if (mine_load(argv[optind], &f) != 0)
        return 1;
    mine_make_job(&f, &job);

    u64_t first = 0u, total_hits = 0u, hit = 0u;
    double elapsed = 0.0;
    time_measurement();
    for (;;) {
        u32_t n_hits =
            engines[engine].run(&job, zero_bits, first, MINE_STEP, &hit, 1u);

        first += MINE_STEP;
        total_hits += n_hits;
        time_measurement();
        elapsed += wall_time_delta();
        if (bench ? elapsed >= seconds : n_hits > 0u)
            break;
    }
    const u64_t attempts = first * job.n_blocks;
    printf("%s %s: %lu attempts in %.2f seconds, %.0f per minute, %lu hit%s\n",
           engines[engine].name, argv[optind], attempts, elapsed,
           60.0 * (double)attempts / elapsed, total_hits,
           (total_hits == 1u) ? "" : "s");

    int status = 0;
    if (!bench) {
        u32_t hash[5];

        mine_set_nonce(&f, hit);
        mine_sha1(f.data, f.data_size, hash);
        assert((hash[4] & mine_mask(zero_bits)) == 0u);
        status = (mine_save(argv[optind + 1], &f) != 0);
        if (status == 0)
            printf("%08x%08x%08x%08x%08x  %s\n", hash[0], hash[1], hash[2],
                   hash[3], hash[4], argv[optind + 1]);
    }
    free(f.data);
    return status;
}
