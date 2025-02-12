#ifndef TLB_FLUSH_H
#define TLB_FLUSH_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "cacheutils.h"

/**
 * todo set this THRESHOLD depending on your system
 */
unsigned THRESHOLD = 30;
unsigned THRESHOLD2 = 32;

#define PAGESIZE_4K 12
#define PAGESIZE_2M 21

#define HUGEPAGES 128

/**
 * TLB settings
 */
#define STLB_HASHSIZE_4K 8
#define STLB_HASHSIZE_2M 8
#define DTLB_HASHSIZE_4K 4
#define DTLB_HASHSIZE_2M 3
#define STLB_WAYS_4K 12
#define STLB_WAYS_2M 8
#define DTLB_WAYS_4K 6
#define DTLB_WAYS_2M 4
#define STLB_HASHMASK_4K ((1 << STLB_HASHSIZE_4K) - 1)
#define STLB_HASHMASK_2M ((1 << STLB_HASHSIZE_2M) - 1)
#define DTLB_HASHMASK_4K ((1 << DTLB_HASHSIZE_4K) - 1)
#define DTLB_HASHMASK_2M ((1 << DTLB_HASHSIZE_2M) - 1)
#define STLB_SET_4K(addr) (((addr >> PAGESIZE_4K) ^ (addr >> (PAGESIZE_4K + STLB_HASHSIZE_4K))) & STLB_HASHMASK_4K)
#define STLB_SET_2M(addr) (((addr >> PAGESIZE_2M)) & STLB_HASHMASK_2M)
#define DTLB_SET_4K(addr) ((addr >> PAGESIZE_4K) & DTLB_HASHMASK_4K)
#define DTLB_SET_2M(addr) ((addr >> PAGESIZE_2M) & DTLB_HASHMASK_2M)

#define FLUSH_SET_SIZE ((1UL << (PAGESIZE_4K + STLB_HASHSIZE_4K * 2))) * 2 // 12bit page size + enough space for 14 bit xor
#define TLB_EVICTION_SIZE (1UL << (PAGESIZE_4K + 12))                      // 12bit page size 4096 times to cover up to 3072 TLB entries

#define TIMER(x) rdtsc_##x

#define FLUSH_TLB_ALL flush_tlb_4k
#define FLUSH_TLB_T_4K flush_tlb_targeted_4k
#define FLUSH_TLB_T_2M flush_tlb_targeted_2M

#define TIMER_START TIMER(begin)
#define TIMER_END TIMER(end)
#define FLUSH_TLB_4K FLUSH_TLB_T_4K
#define FLUSH_TLB_2M FLUSH_TLB_T_2M

typedef enum
{
    PAGE_4K,
    PAGE_2M
} PageType;

uint8_t *flush_set;
uint8_t *flush_set_2M;

void init_tlb_flush(void)
{
    flush_set = mmap(0, FLUSH_SET_SIZE, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (flush_set == MAP_FAILED) {
        perror("mmap(flush_set)");
        exit(-1);
    }

    if (posix_memalign((void **)&flush_set_2M, 1 << PAGESIZE_2M, (HUGEPAGES + 1) << PAGESIZE_2M) != 0) {
        perror("mmap(flush_set_2M)");
        exit(-1);
    }
    madvise(flush_set_2M, (HUGEPAGES + 1) << PAGESIZE_2M, MADV_HUGEPAGE);

    for (unsigned i = 0; i < HUGEPAGES + 1; i++) {
        flush_set_2M[i << PAGESIZE_2M] = 1;
        // check the page is indeed huge
        // check_huge_page(buf);
    }
}

/**
 * Flush 4k TLBs with up to 4k entries, doesn't flush L1 DTLB for 2M
 */
void flush_tlb_4k(__attribute__((unused)) size_t addr)
{
    for (size_t _i = 0; _i < TLB_EVICTION_SIZE; _i += (1 << 12))
        *(volatile char *)(flush_set + _i);
}

void flush_tlb_targeted_4k(size_t addr)
{
    size_t stlb_set = STLB_SET_4K(addr);
    size_t dtlb_set = DTLB_SET_4K(addr);
    size_t flush_base = (size_t)flush_set;
    flush_base = (((flush_base >> (PAGESIZE_4K + STLB_HASHSIZE_4K * 2))) << (PAGESIZE_4K + STLB_HASHSIZE_4K * 2)) + (1UL << (PAGESIZE_4K + STLB_HASHSIZE_4K * 2));

    // dtlb
    for (size_t i = 0; i < DTLB_WAYS_4K * 2; i++) {
        size_t evict_addr = (flush_base + (dtlb_set << PAGESIZE_4K)) ^ (i << (PAGESIZE_4K + DTLB_HASHSIZE_4K));
        // printf("base: %p, evict_addr: %lx, dset: %d, target dset: %d\n", flush_base, evict_addr, DTLB_SET_4K(evict_addr), DTLB_SET_4K(addr));
        maccess((void *)evict_addr);
    }

    // stlb
    for (size_t i = 0; i < STLB_WAYS_4K * 2; i++) {
        size_t evict_addr = (flush_base + (stlb_set << PAGESIZE_4K)) ^ (((i << STLB_HASHSIZE_4K) + i) << PAGESIZE_4K);
        // printf("base: %p, evict_addr: %lx, set: %d, target set: %d\n", flush_base, evict_addr, STLB_SET_4K(evict_addr), STLB_SET_4K(addr));
        maccess((void *)evict_addr);
    }
}

void flush_tlb_targeted_2M(size_t addr)
{
    size_t stlb_set = STLB_SET_2M(addr);
    // size_t dtlb_set = DTLB_SET_2M(addr);
    size_t flush_base = (size_t)flush_set;
    flush_base = (((flush_base >> (PAGESIZE_4K + STLB_HASHSIZE_4K * 2))) << (PAGESIZE_4K + STLB_HASHSIZE_4K * 2)) + (1UL << (PAGESIZE_4K + STLB_HASHSIZE_4K * 2));

    // dtlb
    for (size_t i = 0; i < HUGEPAGES; i++)
        maccess((void *)(flush_set_2M + (i << PAGESIZE_2M)));

    // stlb
    for (size_t i = 0; i < STLB_WAYS_4K * 2; i++) {
        size_t evict_addr = (flush_base + (stlb_set << PAGESIZE_4K)) ^ (((i << STLB_HASHSIZE_4K) + i) << PAGESIZE_4K);
        // printf("base: %p, evict_addr: %lx, set: %d, target set: %d\n", flush_base, evict_addr, STLB_SET_4K(evict_addr), STLB_SET_4K(addr));
        maccess((void *)evict_addr);
    }
}

void flush_tlb_targeted(size_t addr, PageType type)
{
    if (type == PAGE_4K)
        flush_tlb_targeted_4k(addr);
    else
        flush_tlb_targeted_2M(addr);
}

/**
 * Timed access
 */
size_t __attribute__((noinline, aligned(4096))) onlyreload(size_t addr)
{
    size_t t = TIMER_START();
    prefetch2((void *)addr);
    // prefetcht0((void*)addr);
    // prefetcht1((void*)addr);
    // prefetcht2((void*)addr);
    // prefetchnta((void*)addr);
    return TIMER_END() - t;
}

size_t __attribute__((noinline, aligned(4096))) flushreload(size_t addr)
{
    FLUSH_TLB_4K(addr);
    size_t t = TIMER_START();
    asm volatile("" ::: "memory");
    // prefetcht0((void*)addr);
    // prefetcht1((void*)addr);
    // prefetcht2((void*)addr);
    // prefetchnta((void*)addr);
    prefetch2((void *)addr);
    asm volatile("" ::: "memory");
    return TIMER_END() - t;
}

size_t __attribute__((noinline, aligned(4096))) flushsysreload(size_t addr)
{
    FLUSH_TLB_4K(addr);
    syscall(-1);
    size_t t = TIMER_START();
    asm volatile("" ::: "memory");
    // prefetcht0((void*)addr);
    // prefetcht1((void*)addr);
    // prefetcht2((void*)addr);
    // prefetchnta((void*)addr);
    prefetch2((void *)addr);
    asm volatile("" ::: "memory");
    return TIMER_END() - t;
}

#define HIST_SIZE_THRESHOLD 100

typedef struct DualThreshold_
{
    unsigned lower;
    unsigned upper;
} DualThreshold;

/**
 * Autodetect a good threshold to distinguish mapped from unmapped pages
 * best used via detect_threshold
 */ 
DualThreshold __attribute__((noinline, aligned(4096))) detect_threshold_single(size_t addr_mapped, size_t addr_unmapped)
{
    const unsigned reps = 10000;
    size_t time_m;
    size_t time_um;
    size_t hist_m[HIST_SIZE_THRESHOLD] = {0};
    size_t hist_um[HIST_SIZE_THRESHOLD] = {0};

    /* leaking */
    for (size_t i = 0; i < reps; ++i) {
        prefetch2((void *)addr_mapped);
        asm volatile("lfence");
        asm volatile("mfence");
        time_m = onlyreload(addr_mapped);
        time_um = onlyreload(addr_unmapped);
        asm volatile("lfence");
        asm volatile("mfence");
        hist_m[MIN(HIST_SIZE_THRESHOLD - 2, time_m)]++;
        hist_um[MIN(HIST_SIZE_THRESHOLD - 2, time_um)]++;
    }

    size_t sum[2] = {0};
    unsigned max = 0;
    unsigned threshold_i = 0;
    unsigned limit1 = 0;
    unsigned limit2 = 0;
    for (size_t i = 0; i < HIST_SIZE_THRESHOLD; i += 2) {
        sum[0] += hist_m[i];
        sum[1] += hist_um[i];
        if ((sum[0] - sum[1]) > max)
            max = (sum[0] - sum[1]);
    }
    sum[0] = 0;
    sum[1] = 0;
    for (size_t i = 0; i < HIST_SIZE_THRESHOLD; i += 2) {
        sum[0] += hist_m[i];
        sum[1] += hist_um[i];
        if (!limit1 && (sum[0] - sum[1]) >= 0.97 * max)
            limit1 = i;
        if (limit1 && !limit2 && (sum[0] - sum[1]) <= 0.97 * max) {
            limit2 = i;
            threshold_i = (limit1 + limit2) / 2;
            threshold_i += threshold_i % 2;
        }
    }
    DualThreshold t = {limit1, limit2};

    return t;
}

/**
 * Autodetect a good threshold to distinguish mapped from unmapped pages
 * thresholds are inclusive, i.e use as <= Lower, >= Upper
 */
DualThreshold detect_threshold(size_t addr_mapped, size_t addr_unmapped, const unsigned reps)
{
    size_t threshold_hist_lower[HIST_SIZE_THRESHOLD] = {0};
    size_t threshold_hist_upper[HIST_SIZE_THRESHOLD] = {0};
    // printf("Detecting mapped/unmapped threshold..\n");

    // warmup
    for (unsigned i = 0; i < 20; i++)
        detect_threshold_single(addr_mapped, addr_unmapped);

    for (unsigned i = 0; i < reps; i++) {
        DualThreshold t = detect_threshold_single(addr_mapped, addr_unmapped);
        threshold_hist_lower[t.lower]++;
        threshold_hist_upper[t.upper]++;
    }

    unsigned threshold_l = 0;
    unsigned threshold_l_i = 0;
    unsigned threshold_u = 0;
    unsigned threshold_u_i = 0;
    for (size_t i = 0; i < HIST_SIZE_THRESHOLD; i += 2) {
        if (threshold_hist_lower[i] > threshold_l) {
            threshold_l = threshold_hist_lower[i];
            threshold_l_i = i;
        }
        if (threshold_hist_upper[i] > threshold_u) {
            threshold_u = threshold_hist_upper[i];
            threshold_u_i = i;
        }
        // printf("%02ld: % 5ld % 5ld\n", i, threshold_hist_lower[i], threshold_hist_upper[i]);
    }

    DualThreshold t = {threshold_l_i, threshold_u_i};

    return t;
}

int comp(const void *e1, const void *e2)
{
    return *(size_t *)e1 > *(size_t *)e2;
}

size_t hit(size_t addr, size_t tries)
{
    size_t time;
    /* leaking */
    prefetch2((void *)addr);
    for (size_t i = 0; i < tries; ++i) {
        time = onlyreload(addr);
        if (time <= THRESHOLD)
            return 1;
    }
    return 0;
}

size_t hit_accurate(size_t addr, size_t tries)
{
    size_t time;
    size_t times[tries];
    /* leaking */
    prefetch2((void *)addr);
    for (size_t i = 0; i < tries; ++i) {
        time = onlyreload(addr);
        times[i] = time;
    }
    qsort(times, tries, sizeof(size_t), comp);
    time = times[tries / 4];
    return time <= THRESHOLD;
}

#endif