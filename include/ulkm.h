#pragma once
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "lkm.h"

static int lkm_fd = -1;
void lkm_init(void)
{
    lkm_fd = open("/dev/lkm", O_RDWR);
    if (lkm_fd < 0) {
        perror("open(/dev/lkm)");
        _exit(-1);
    }
}

size_t __lkm_read(size_t kaddr, size_t uaddr)
{
    msg_t msg = {
        .rd = {
            .kaddr = kaddr,
            .uaddr = uaddr,
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
    return ioctl(lkm_fd, LKM_READ, (size_t)&msg);
}
void lkm_read(size_t kaddr, size_t uaddr)
{
    int ret = __lkm_read(kaddr, uaddr);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

size_t __lkm_write(size_t kaddr, size_t value)
{
    msg_t msg = {
        .wr = {
            .kaddr = kaddr,
            .value = value,
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
    return ioctl(lkm_fd, LKM_WRITE, (size_t)&msg);
}
void lkm_write(size_t kaddr, size_t value)
{
    int ret = __lkm_write(kaddr, value);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

size_t __lkm_access_primitive(size_t addr)
{
    msg_t msg = {
        .ap = {
            .addr = addr
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
    return ioctl(lkm_fd, LKM_ACCESS_PRIMITIVE, (size_t)&msg);
}
void lkm_access_primitive(size_t addr)
{
    int ret = __lkm_access_primitive(addr);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

size_t __lkm_dpm_test(void)
{
    msg_t msg;
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
    return ioctl(lkm_fd, LKM_DPM_TEST, (size_t)&msg);
}
void lkm_dpm_test(void)
{
    int ret = __lkm_dpm_test();
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

int __lkm_msg_msg_leak(size_t uaddr, size_t msqid, size_t mtype)
{
    msg_t msg = {
        .mrd = {
            .uaddr = uaddr,
            .msqid = msqid,
            .mtype = mtype,
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
	return ioctl(lkm_fd, LKM_MSG_MSG_LEAK, (unsigned long)&msg);
}
void lkm_msg_msg_leak(size_t uaddr, size_t msqid, size_t mtype)
{
    int ret = __lkm_msg_msg_leak(uaddr, msqid, mtype);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

int __lkm_seq_file_leak(size_t uaddr, size_t fd)
{
    msg_t msg = {
        .frd = {
            .uaddr = uaddr,
            .fd = fd,
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
	return ioctl(lkm_fd, LKM_SEQ_FILE_LEAK, (unsigned long)&msg);
}
void lkm_seq_file_leak(size_t uaddr, size_t fd)
{
    int ret = __lkm_seq_file_leak(uaddr, fd);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

int __lkm_file_leak(size_t uaddr, size_t fd)
{
    msg_t msg = {
        .frd = {
            .uaddr = uaddr,
            .fd = fd,
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
	return ioctl(lkm_fd, LKM_FILE_LEAK, (unsigned long)&msg);
}
void lkm_file_leak(size_t uaddr, size_t fd)
{
    int ret = __lkm_file_leak(uaddr, fd);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

int __lkm_pipe_buffer_leak(size_t uaddr, size_t fd, size_t rdend)
{
    msg_t msg = {
        .pbrd = {
            .uaddr = uaddr,
            .fd = fd,
            .rdend = rdend,
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
	return ioctl(lkm_fd, LKM_PIPE_BUFFER_LEAK, (unsigned long)&msg);
}
void lkm_pipe_buffer_leak(size_t uaddr, size_t fd, size_t rdend)
{
    int ret = __lkm_pipe_buffer_leak(uaddr, fd, rdend);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

int __lkm_cred_leak(size_t uaddr)
{
    msg_t msg = {
        .drd = {
            .uaddr = uaddr,
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
	return ioctl(lkm_fd, LKM_CRED_LEAK, (unsigned long)&msg);
}
void lkm_cred_leak(size_t uaddr)
{
    int ret = __lkm_cred_leak(uaddr);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

int __lkm_dpm_leak(size_t uaddr)
{
    msg_t msg = {
        .drd = {
            .uaddr = uaddr,
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
	return ioctl(lkm_fd, LKM_DPM_LEAK, (unsigned long)&msg);
}
void lkm_dpm_leak(size_t uaddr)
{
    int ret = __lkm_dpm_leak(uaddr);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

size_t __lkm_virt_base_leak(size_t uaddr)
{
    msg_t msg = {
        .drd = {
            .uaddr = uaddr
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
    return ioctl(lkm_fd, LKM_VIRTUAL_BASE_LEAK, (size_t)&msg);
}
void lkm_virt_base_leak(size_t uaddr)
{
    int ret = __lkm_virt_base_leak(uaddr);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

size_t __lkm_stack_leak(size_t uaddr)
{
    msg_t msg = {
        .drd = {
            .uaddr = uaddr
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
    return ioctl(lkm_fd, LKM_STACK_LEAK, (size_t)&msg);
}
void lkm_stack_leak(size_t uaddr)
{
    int ret = __lkm_stack_leak(uaddr);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

size_t __lkm_code_leak(size_t uaddr)
{
    msg_t msg = {
        .drd = {
            .uaddr = uaddr
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
    return ioctl(lkm_fd, LKM_CODE_LEAK, (size_t)&msg);
}
void lkm_code_leak(size_t uaddr)
{
    int ret = __lkm_code_leak(uaddr);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

size_t __lkm_vmemmap_leak(size_t uaddr)
{
    msg_t msg = {
        .drd = {
            .uaddr = uaddr
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
    return ioctl(lkm_fd, LKM_VMEMMAP_LEAK, (size_t)&msg);
}
void lkm_vmemmap_leak(size_t uaddr)
{
    int ret = __lkm_vmemmap_leak(uaddr);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

size_t __lkm_vmalloc_base_leak(size_t uaddr)
{
    msg_t msg = {
        .drd = {
            .uaddr = uaddr
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
    return ioctl(lkm_fd, LKM_VMALLOC_BASE_LEAK, (size_t)&msg);
}
void lkm_vmalloc_base_leak(size_t uaddr)
{
    int ret = __lkm_vmalloc_base_leak(uaddr);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

size_t __lkm_arb_free(size_t kaddr)
{
    msg_t msg = {
        .af = {
            .kaddr = kaddr,
        }
    };
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
    return ioctl(lkm_fd, LKM_ARB_FREE, (size_t)&msg);
}
void lkm_arb_free(size_t kaddr)
{
    int ret = __lkm_arb_free(kaddr);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

int __lkm_arb_pagetable_wald(size_t uaddr, size_t *pgde, size_t *pude, size_t *pmde, size_t *pte)
{
    msg_t msg = {
		.ptw = {
			.uaddr = uaddr,
		}
	};
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
	int ret = ioctl(lkm_fd, LKM_PAGETABLE_WALK, (unsigned long)&msg);
	if (!ret) {
		if (pgde) *pgde = msg.ptw.pgde;
		if (pude) *pude = msg.ptw.pude;
		if (pmde) *pmde = msg.ptw.pmde;
		if (pte) *pte = msg.ptw.pte;
	}
	return ret;
}
void lkm_arb_pagetable_wald(size_t uaddr, size_t *pgde, size_t *pude, size_t *pmde, size_t *pte)
{
    int ret = __lkm_arb_pagetable_wald(uaddr, pgde, pude, pmde, pte);
    if (ret < 0) {
        printf("[!] ret %d\n", ret);
        _exit(-1);
    }
}

int lkm_is_4kb(size_t addr)
{
    msg_t msg = {
		.ap = {
			.addr = addr,
		}
	};
    if (lkm_fd < 0) {
        printf("[!] lkm not init\n");
        _exit(-1);
    }
	return ioctl(lkm_fd, LKM_IS_4KB, (unsigned long)&msg);
}
