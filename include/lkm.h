#pragma once

#define LKM_READ				100
#define LKM_WRITE				101
#define LKM_DPM_TEST			102
#define LKM_ACCESS_PRIMITIVE	103
#define LKM_MSG_MSG_LEAK		104
#define LKM_DPM_LEAK			105
#define LKM_VIRTUAL_BASE_LEAK 	106
#define LKM_STACK_LEAK			107
#define LKM_CODE_LEAK			108
#define LKM_VMEMMAP_LEAK		109
#define LKM_VMALLOC_BASE_LEAK	110
#define LKM_SEQ_FILE_LEAK		111
#define LKM_CRED_LEAK			112
#define LKM_FILE_LEAK			113
#define LKM_ARB_FREE			114
#define LKM_PIPE_BUFFER_LEAK	115
#define LKM_PAGETABLE_WALK		116
#define LKM_IS_4KB				117

typedef union {
	struct write {
		size_t kaddr;
		size_t value;
	} wr;
	struct read {
		size_t kaddr;
		size_t uaddr;
	} rd;
	struct access_primitive {
		size_t addr;
	} ap;
	struct dpm_split {
		size_t size;
	} dpms;
    struct msg_msg_rd {
        size_t uaddr;
        size_t msqid;
        size_t mtype;
    } mrd;
	struct dpm_rd {
		size_t uaddr;
	} drd;
	struct alloc {
		size_t id;
		size_t size;
	} al;
	struct free {
		size_t id;
	} fr;
	struct file_rd {
		size_t fd;
		size_t uaddr;
	} frd;
	struct pipe_buffer_rd {
		size_t fd;
		size_t uaddr;
		size_t rdend;
	} pbrd;
	struct arb_free {
		size_t kaddr;
	} af;
	struct pagetable_walk {
		size_t uaddr;
		size_t pgde;
		size_t p4de;
		size_t pude;
		size_t pmde;
		size_t pte;
	} ptw;
} msg_t;