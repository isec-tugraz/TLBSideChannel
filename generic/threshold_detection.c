#include "utils.h"
#include "ulkm.h"
#include "tlb_flush.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#define HIST_SIZE 60
#define TRIES 500

/**
 * Does the page return hits after calling syscall, and does it have unmapped guard pages after it
 */
void hit_flush(size_t addr, size_t tries)
{
    size_t time;
    size_t time_n;
    size_t times[tries];
    size_t times_n[tries];
    size_t hist[HIST_SIZE] = {0};
    size_t hist_n[HIST_SIZE] = {0};
    /* leaking */
    for (size_t i = 0; i < tries; ++i) {
        prefetch2((void *)addr);
        asm volatile("lfence");
        asm volatile("mfence");
        time = onlyreload(addr);
        time_n = onlyreload(addr+(1<<12));
        asm volatile("lfence");
        asm volatile("mfence");
        
        times[i] = time;
        times_n[i] = time_n;
        hist[MIN(time,HIST_SIZE-2)]++;
        hist_n[MIN(time_n,HIST_SIZE-2)]++;
    }
    qsort(times, tries, sizeof(size_t), comp);
    qsort(times_n, tries, sizeof(size_t), comp);
    for (size_t i = 20; i < HIST_SIZE; i += 2)
        printf("%02ld: % 5ld % 5ld\n", i, hist[i], hist_n[i]);
}

int main(void)
{
    printf("[*] start\n");
    set_limit();
    lkm_init();
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    pin_to_core(0);
    init_tlb_flush();
    get_total_memory();

    size_t stack;
    lkm_stack_leak((size_t)&stack);
    DualThreshold t = detect_threshold(stack + 0x3000, stack + 0x4000, 100);
    unsigned THRESHOLD = t.lower;
    unsigned THRESHOLD2 = (t.lower+t.upper*2)/3;
    printf("[+] detected thresholds: %d %d\n", THRESHOLD, THRESHOLD2);

    hit_flush(stack + 0x3000, TRIES);
}
