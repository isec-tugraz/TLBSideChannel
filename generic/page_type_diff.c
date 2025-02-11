#include "utils.h"
#include "cacheutils.h"
#include "ulkm.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <assert.h>
#include <linux/kernel-page-flags.h>
#include <errno.h>
#include "../include/tlb_flush.h"

#define HIT 29
#define TRIES 1000000
#define HIST_SIZE 120

#define STACK_SIZE (1 << 14)

//-----
#define fail(...)                     \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        exit(EXIT_FAILURE);           \
    } while (0)
#define PAGE_SIZE (1 << 12)
#define HPAGE_SIZE (1 << 21)

// See <https://www.kernel.org/doc/Documentation/vm/pagemap.txt> for
// format which these bitmasks refer to
#define PAGEMAP_PRESENT(ent) (((ent) & (1ull << 63)) != 0)
#define PAGEMAP_PFN(ent) ((ent) & ((1ull << 55) - 1))

#define NEXP 4
size_t print_hist(size_t addr_stack, size_t addr_large)
{
    printf("[*] addr %016zx\n", addr_stack);
    size_t time = 0;
    size_t time_n1 = 0;

    size_t hist[NEXP][HIST_SIZE];
    size_t hist_n1[NEXP][HIST_SIZE];

    memset(hist, 0, sizeof(hist));
    memset(hist_n1, 0, sizeof(hist_n1));
    // memset(hist_n4, 0, sizeof(hist_n4));
    /* leaking */
    for (size_t i = 0; i < TRIES * NEXP; ++i) {
        // stack/4k hit vs 4k miss
        if (i % NEXP == 0) {
            asm volatile("lfence");
            asm volatile("mfence");
            prefetch2((void *)addr_stack);
            time = onlyreload(addr_stack);
            time_n1 = flushreload(addr_stack);
        // unmapped (stack+1) hit/miss
        } else if (i % NEXP == 1) {
            asm volatile("lfence");
            asm volatile("mfence");
            prefetch2((void *)(addr_stack + (1 << 12)));
            time = onlyreload(addr_stack + (1 << 12));
            time_n1 = flushreload(addr_stack + (1 << 12));
        // stack hit/unmapped miss by syscall
        } else if (i % NEXP == 2) {
            asm volatile("lfence");
            asm volatile("mfence");
            time = flushsysreload(addr_stack);
            time_n1 = onlyreload(addr_stack + (1 << 12));
            asm volatile("lfence");
            asm volatile("mfence");
        // 2MB hit/miss
        } else if (i % NEXP == 3) {
            asm volatile("lfence");
            asm volatile("mfence");
            prefetch2((void *)(addr_large + 512));
            time = onlyreload(addr_large + 512);
            FLUSH_TLB_2M(addr_large + 512);
            time_n1 = onlyreload(addr_large + 512);
        }
        hist[i % NEXP][MIN(HIST_SIZE - 2, time)]++;
        hist_n1[i % NEXP][MIN(HIST_SIZE - 2, time_n1)]++;
    }
    size_t sum[NEXP * 2] = {0};
    printf("time,4k hit,4k miss,4k UM hit,4k UM miss,4k stack hit,4k UM hit,2MB hit,2MB miss"); // csv
    for (size_t i = 20; i < HIST_SIZE; i += 2) {
        printf("\n%zd", i);
        for (int j = 0; j < NEXP; j++) {
            sum[j * 2] += hist[j][i];
            sum[j * 2 + 1] += hist_n1[j][i];
            // printf("% 6.1f % 6.1f ", (float)(sum[j*2])/TRIES*100, (float)(sum[j*2+1])/TRIES*100);
            // printf("%zd\t %zd \t", hist[j][i], hist_n1[j][i]);
            printf(",%zd,%zd", hist[j][i], hist_n1[j][i]); // csv
        }
    }
    puts("");

    return (time < HIT && time_n1 > HIT);
}

DualThreshold meta_threshold_detection(size_t addr_mapped, size_t addr_unmapped)
{
    size_t threshold_hist_lower[HIST_SIZE] = {0};
    size_t threshold_hist_upper[HIST_SIZE] = {0};
    printf("Detecting mapped/unmapped threshold..\n");
    for (unsigned i = 0; i < 1000; i++) {
        DualThreshold t = detect_threshold_single(addr_mapped, addr_unmapped);
        threshold_hist_lower[t.lower]++;
        threshold_hist_upper[t.upper]++;
    }

    unsigned threshold_l = 0;
    unsigned threshold_l_i = 0;
    unsigned threshold_u = 0;
    unsigned threshold_u_i = 0;
    for (size_t i = 0; i < HIST_SIZE; i += 2) {
        if (threshold_hist_lower[i] > threshold_l) {
            threshold_l = threshold_hist_lower[i];
            threshold_l_i = i;
        }
        if (threshold_hist_upper[i] > threshold_u) {
            threshold_u = threshold_hist_upper[i];
            threshold_u_i = i;
        }
    }
    for (size_t i = 20; i < HIST_SIZE; i += 2) {
        if (i == threshold_l_i)
            printf("% 4zd: \033[31m% 4zd\033[0m % 4zd\n", i, threshold_hist_lower[i], threshold_hist_upper[i]);
        else if (i == threshold_u_i)
            printf("% 4zd: % 4zd \033[31m% 4zd\033[0m\n", i, threshold_hist_lower[i], threshold_hist_upper[i]);
        else
            printf("% 4zd: % 4zd % 4zd\n", i, threshold_hist_lower[i], threshold_hist_upper[i]);
    }

    printf("Median Thresholds: %d %d\n", threshold_l_i, threshold_u_i);

    DualThreshold t = {threshold_l_i, threshold_u_i};

    return t;
}

int main(int argc, char **argv)
{
    pin_to_core(2);
    lkm_init();

    size_t addr_large;
    if (argc == 2) {
        addr_large = strtoull(argv[1], NULL, 16);
    } else {
        lkm_dpm_leak((size_t)&addr_large);
        addr_large += (1 << 12);
    }
    printf("stlb set: %lx: %lu\n", addr_large, STLB_SET_4K(addr_large));

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    init_tlb_flush();

    size_t stack;
    lkm_stack_leak((size_t)&stack);

    meta_threshold_detection(stack + (3 << 12), stack + (4 << 12));

    printf("flush set range: %p - %p\n", flush_set, flush_set + FLUSH_SET_SIZE);

    printf("[*] current->stack %016zx\n", stack);
    printf("[*] 2MB page %016zx\n", addr_large);
    printf("=======================================\n");
    print_hist(stack + (3 << 12), addr_large);
}