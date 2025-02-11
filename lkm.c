#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/io.h>
#include <linux/slab.h>
#include <linux/pgtable.h>
#include <asm/pgtable_64.h>
#include <linux/kprobes.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/pipe_fs_i.h>

#include "include/lkm.h"

#define DEVICE_NAME "lkm"
#define CLASS_NAME "lkmclass"

int lkm_init_device_driver(void);
static int lkm_init(void);
static void lkm_cleanup(void);
int lkm_open(struct inode *inode, struct file *filp);
int lkm_release(struct inode *inode, struct file *filep);
long lkm_ioctl(struct file *file, unsigned int num, long unsigned int param);
pte_t *page_walk_pte(size_t addr);
void dpm_test(void);

static struct file_operations lkm_fops = {
	.owner = THIS_MODULE,
	.open = lkm_open,
	.release = lkm_release,
	.unlocked_ioctl = lkm_ioctl,
};

static int lkm_major;
static struct class *lkm_class;
static struct device *lkm_device;

static pgd_t *_init_top_pgt;
struct msg_queue;
struct msg_queue *(*ipc_obtain_object_check)(struct ipc_ids *ns, int id);
unsigned long slub_addr_base;
unsigned long __text;
unsigned long vmemmap_base;
unsigned long vmalloc_base;
unsigned long __end;
static struct kprobe kp = {
	.symbol_name = "init_top_pgt"
};
static struct kprobe kp1 = {
	.symbol_name = "ipc_obtain_object_check"
};
static struct kprobe kp2 = {
	.symbol_name = "slub_addr_base"
};
static struct kprobe kp3 = {
	.symbol_name = "_text"
};
static struct kprobe kp4 = {
	.symbol_name = "vmemmap_base"
};
static struct kprobe kp5 = {
	.symbol_name = "vmalloc_base"
};

/*
 * Initialization device driver
 */
// #define V5_15
// #define V6_5
// #define V6_6
#define V6_8
int lkm_init_device_driver(void)
{
	int ret;
	printk(KERN_INFO "lkm:init_device_driver: start\n");

	ret = register_chrdev(0, DEVICE_NAME, &lkm_fops);
	if (ret < 0) goto ERROR;
	lkm_major = ret;
#if defined(V6_5) || defined(V6_8) || defined(V6_6)
	lkm_class = class_create(CLASS_NAME);
#else
	lkm_class = class_create(0, CLASS_NAME);
#endif
	if (IS_ERR(lkm_class)) {
		ret = PTR_ERR(lkm_class);
		goto ERROR1;
	}

	lkm_device = device_create(lkm_class, 0, MKDEV(lkm_major, 0), 0, DEVICE_NAME);
	if (IS_ERR(lkm_device)) {
		ret = PTR_ERR(lkm_device);
		goto ERROR2;
	}

	printk(KERN_INFO "lkm:init_device_driver: done '/dev/%s c %d' 0 created\n", DEVICE_NAME, lkm_major);
	return 0;

ERROR2:
	printk(KERN_ERR "lkm:init_device_driver: class destroy\n");
	class_unregister(lkm_class);
	class_destroy(lkm_class);
ERROR1:
	printk(KERN_ERR "lkm:init_device_driver: unregister chrdev\n");
	unregister_chrdev(lkm_major, CLASS_NAME);
ERROR:
	printk(KERN_ERR "lkm:init_device_driver: fail %d\n", ret);
	lkm_device = 0;
	lkm_class = 0;
	lkm_major = -1;
	return ret;
}

/*
 * Initialization
 */
static int lkm_init(void)
{
	int ret;
	printk(KERN_INFO "lkm:init: start\n");

	ret = lkm_init_device_driver();
	if (ret) goto ERROR;

    register_kprobe(&kp);
	_init_top_pgt = (void *)kp.addr;
    register_kprobe(&kp1);
	ipc_obtain_object_check = (struct msg_queue *(*)(struct ipc_ids *, int))kp1.addr;
    register_kprobe(&kp2);
	slub_addr_base = *(unsigned long *)kp2.addr;
    register_kprobe(&kp3);
	__text = (unsigned long)kp3.addr;
    register_kprobe(&kp4);
	vmemmap_base = *(unsigned long *)kp4.addr;
    register_kprobe(&kp5);
	vmalloc_base = *(unsigned long *)kp5.addr;

	printk(KERN_INFO "lkm:init: init_top_pgt %016zx\n", (size_t)_init_top_pgt);
	printk(KERN_INFO "lkm:init: lkm_class    %016zx\n", (size_t)lkm_class);
	printk(KERN_INFO "lkm:init: lkm_ioctl    %016zx\n", (size_t)lkm_ioctl);

	printk(KERN_INFO "lkm:init: done\n");
	return 0;

ERROR:
	printk(KERN_ERR "lkm:init: error\n");
	return ret;
}

/*
 * Cleanup
 */
static void lkm_cleanup(void)
{
	printk(KERN_INFO "lkm:cleanup\n");
    unregister_kprobe(&kp);
    unregister_kprobe(&kp1);
    unregister_kprobe(&kp2);
    unregister_kprobe(&kp3);
    unregister_kprobe(&kp4);
    unregister_kprobe(&kp5);
	device_destroy(lkm_class, MKDEV(lkm_major, 0));
	class_unregister(lkm_class);
	class_destroy(lkm_class);
	unregister_chrdev(lkm_major, DEVICE_NAME);
}

/*
 * Close "/dev/lkm"
 */
int lkm_release(struct inode *inode, struct file *filep)
{
	printk(KERN_INFO "lkm:release\n");
	module_put(THIS_MODULE);
	return 0;
}
EXPORT_SYMBOL(lkm_release);

/*
 * Open "/dev/lkm"
 */
int lkm_open(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO "lkm:open\n");
	try_module_get(THIS_MODULE);
	return 0;
}
EXPORT_SYMBOL(lkm_open);

pte_t *page_walk_pte(size_t addr)
{
	unsigned long above = ((long)addr) >> __VIRTUAL_MASK_SHIFT;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (above != 0 && above != -1UL)
		return 0;

	pgd = pgd_offset_pgd(_init_top_pgt, addr);
	if (pgd_none(*pgd))
		return 0;

	p4d = p4d_offset(pgd, addr);
	if (!p4d_present(*p4d))
		return 0;

	pud = pud_offset(p4d, addr);
	if (!pud_present(*pud))
		return 0;

	if (pud_large(*pud))
		return 0;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd))
		return 0;

	if (pmd_large(*pmd))
		return 0;

	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return 0;

	return pte;
}
pmd_t *page_walk_pmd(size_t addr)
{
	unsigned long above = ((long)addr) >> __VIRTUAL_MASK_SHIFT;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (above != 0 && above != -1UL)
		return 0;

	pgd = pgd_offset_pgd(_init_top_pgt, addr);
	if (pgd_none(*pgd))
		return 0;

	p4d = p4d_offset(pgd, addr);
	if (!p4d_present(*p4d))
		return 0;

	pud = pud_offset(p4d, addr);
	if (!pud_present(*pud))
		return 0;

	if (pud_large(*pud))
		return 0;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd))
		return 0;

	return pmd;
}

bool isLargePage(size_t addr)
{
	unsigned long above = ((long)addr) >> __VIRTUAL_MASK_SHIFT;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (above != 0 && above != -1UL)
		return 0;

	pgd = pgd_offset_pgd(_init_top_pgt, addr);
	if (pgd_none(*pgd))
		return 0;

	p4d = p4d_offset(pgd, addr);
	if (!p4d_present(*p4d))
		return 0;

	pud = pud_offset(p4d, addr);
	if (!pud_present(*pud))
		return 0;

	if (pud_large(*pud))
		return 0;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(*pmd))
		return 0;

	if (pmd_large(*pmd))
		return 1;

	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return 0;

	return 0;
}

void dpm_test(void)
{
  int max_large = 10;
	size_t start = 0;
	size_t end = 32ULL*1024ULL*1024ULL*1024ULL;
	printk(KERN_INFO "lkm:dpm_test: physical mapping paddr [%016zx - %016zx] vaddr [%016zx - %016zx]\n", 
		start, end, (size_t)__va(start), (size_t)__va(end));
	size_t count = 0;
	size_t paddr;
	for (paddr = start; paddr < end; paddr += PMD_SIZE) {
		size_t vaddr = (size_t)phys_to_virt(paddr);
		pte_t *pte = page_walk_pte(vaddr);
		if (pte) {
			size_t diff = 0;
			size_t writable = 0;
			size_t pagecachedisabled = 0;
			size_t global = 0;
			size_t _paddr;
			for (_paddr = paddr; _paddr < paddr + PMD_SIZE; _paddr += PAGE_SIZE) {
				size_t vaddr = (size_t)phys_to_virt(_paddr);
				pte_t *pte = page_walk_pte(vaddr);
				if (!pte) {
					// printk(KERN_DEBUG "lkm:dpm_test: vaddr %016zx pte 0\n", vaddr);
					continue;
				}
				diff += !!((pte->pte & 0xfff) ^ 0x163);
				writable += !!(pte->pte & _PAGE_RW);
				pagecachedisabled += !!(pte->pte & _PAGE_PCD);
				global += !!(pte->pte & _PAGE_GLOBAL);
				// printk(KERN_DEBUG "lkm:dpm_test: vaddr %016zx pte %016zx\n", vaddr, pte->pte);
				count++;
			}
			printk(KERN_DEBUG "lkm:dpm_test: vaddr %016zx with [%4zd diff] [%4zd wr] [%4zd pcd] [%4zd g]\n", vaddr, diff, writable, pagecachedisabled, global);
		}
		else if (max_large > 0 && isLargePage(vaddr))
		{
			max_large--;
			printk(KERN_DEBUG "lkm:dpm_test: 2MB: vaddr %016zx\n", vaddr);
		}
	}
	printk(KERN_INFO "lkm:dpm_test: count/max   %5zu/%zu\n", count, (end - start) / PAGE_SIZE);

	pmd_t *_text_pmd = page_walk_pmd(__text);
	pmd_t *_end_pmd = page_walk_pmd(__end);
	printk(KERN_INFO "lkm:dpm_text: _text %016zx\n", __text);
	printk(KERN_INFO "lkm:dpm_text: _end  %016zx\n", __end);
	size_t _text_pa = (size_t)__va(_text_pmd->pmd & 0xfffffffff000);
	size_t _end_pa = (size_t)__va(_end_pmd->pmd & 0xfffffffff000);
	printk(KERN_INFO "lkm:dpm_text: _text_pa %016zx %s\n", _text_pa, isLargePage(_text_pa) ? "2MB page" : "4k page");
	printk(KERN_INFO "lkm:dpm_text: _end_pa  %016zx %s\n", _end_pa, isLargePage(_end_pa) ? "2MB page" : "4k page");
}

struct msg_queue {
	struct kern_ipc_perm q_perm;
	time64_t q_stime;
	time64_t q_rtime;
	time64_t q_ctime;
	unsigned long q_cbytes;
	unsigned long q_qnum;
	unsigned long q_qbytes;
	struct pid *q_lspid;
	struct pid *q_lrpid;
	struct list_head q_messages;
	struct list_head q_receivers;
	struct list_head q_senders;
};
#define IPC_MSG_IDS	1
#define msg_ids(ns)	((ns)->ids[IPC_MSG_IDS])
static unsigned long msg_copy_to_user(size_t msqid, size_t type)
{
	struct msg_queue *msq;
	struct msg_msg *msg;
	struct msg_msg *found = 0;
	struct ipc_namespace *ns;
	struct ipc_ids *ids;
	rcu_read_lock();
	// printk(KERN_DEBUG "lkm:msg_copy_to_user: msqid %ld\n", msqid);
	ns = current->nsproxy->ipc_ns;
	// printk(KERN_DEBUG "lkm:msg_copy_to_user: ns %016zd\n", (unsigned long)ns);
	ids = &msg_ids(ns);
	// printk(KERN_DEBUG "lkm:msg_copy_to_user: ids %016zd\n", (unsigned long)ids);
	msq = ipc_obtain_object_check(ids, msqid);
	// printk(KERN_DEBUG "lkm:msg_copy_to_user: msq %016zd\n", (unsigned long)msq);
	if (IS_ERR(msq))
		goto RETURN;
	list_for_each_entry(msg, &msq->q_messages, m_list) {
		if (msg->m_type == type) {
			found = msg;
			// printk(KERN_DEBUG "lkm:msg_copy_to_user: found %016zx\n", (unsigned long)found);
			break;
		}
	}
RETURN:
	rcu_read_unlock();
	return (unsigned long)found;
}

#ifndef SLAB_BASE_ADDR
size_t SLAB_BASE_ADDR = 0;
#endif
#ifndef SLAB_END_ADDR
size_t SLAB_END_ADDR = 0;
#endif

static int bad_address(void *p)
{
	unsigned long dummy;
	return get_kernel_nofault(dummy, (unsigned long *)p);
}

noinline void pagetable_walk(msg_t *msg)
{
	size_t address = msg->ptw.uaddr;
	pgd_t *base = __va(read_cr3_pa());
	pgd_t *pgd = base + pgd_index(address);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (bad_address(pgd))
		goto out;

	// pr_info("PGD %lx ", pgd_val(*pgd));
	msg->ptw.pgde = pgd_val(*pgd);
	if (!pgd_present(*pgd))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (bad_address(p4d))
		goto out;

	// pr_cont("P4D %lx ", p4d_val(*p4d));
	msg->ptw.p4de = p4d_val(*p4d);
	if (!p4d_present(*p4d) || p4d_large(*p4d))
		goto out;

	pud = pud_offset(p4d, address);
	if (bad_address(pud))
		goto out;

	// pr_cont("PUD %lx ", pud_val(*pud));
	msg->ptw.pude = pud_val(*pud);
	if (!pud_present(*pud) || pud_large(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	if (bad_address(pmd))
		goto out;

	// pr_cont("PMD %lx ", pmd_val(*pmd));
	msg->ptw.pmde = pmd_val(*pmd);
	if (!pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	if (bad_address(pte))
		goto out;

	// pr_cont("PTE %lx", pte_val(*pte));
	msg->ptw.pte = pte_val(*pte);

out:
	// pr_cont("\n");
	return;
}

/*
 * ioctl code
 */
long lkm_ioctl(struct file *_, unsigned int num, long unsigned int param)
{
	int ret;
	msg_t msg;
	size_t *uaddr = 0;
	size_t tmp = -1;
	// void *dummy;
	size_t id;
	struct files_struct *files;
	struct file *file;
	struct fdtable *fdt;
	struct pipe_inode_info *pipe;
	unsigned int tail;
	unsigned int head;
	unsigned int mask;

	// printk(KERN_INFO "lkm:ioctl: start num 0x%08x param 0x%016lx\n", num, param);

	ret = copy_from_user((msg_t*)&msg, (msg_t*)param, sizeof(msg_t));
	if (ret < 0) {
		printk(KERN_ERR "lkm:ioctl: copy_from_user failed\n");
		ret = -1;
		goto RETURN;
	}

	switch (num) {

		case LKM_WRITE:
			// printk(KERN_INFO "lkm:ioctl: arbitrary write\n");
			*(size_t *)msg.wr.kaddr = msg.wr.value;
			break;

		case LKM_READ:
			// printk(KERN_INFO "lkm:ioctl: arbitrary read\n");
			tmp = *(size_t *)msg.rd.kaddr;
			uaddr = (size_t *)msg.rd.uaddr;
			goto COPY_TMP_TO_USER;

		case LKM_DPM_TEST:
			dpm_test();
			break;

		case LKM_ACCESS_PRIMITIVE:
			*(volatile size_t *)msg.ap.addr;
			break;

		case LKM_MSG_MSG_LEAK:
			tmp = msg_copy_to_user(msg.mrd.msqid, msg.mrd.mtype);
			uaddr = (size_t *)msg.mrd.uaddr;
			// printk(KERN_DEBUG "lkm:ioctl: msg_msg leak %16zx\n", tmp);
			goto COPY_TMP_TO_USER;
		
		case LKM_DPM_LEAK:
			tmp = (size_t)__va(0);
			uaddr = (size_t *)msg.drd.uaddr;
			// printk(KERN_DEBUG "lkm:ioctl: dpm leak %16zx\n", tmp);
			goto COPY_TMP_TO_USER;

		case LKM_VIRTUAL_BASE_LEAK:
			tmp = (size_t)slub_addr_base;
			uaddr = (size_t *)msg.drd.uaddr;
			printk(KERN_INFO "lkm:ioctl: slub_addr_base %16zx within [%016zx %016zx]\n", tmp, SLAB_BASE_ADDR, SLAB_END_ADDR);
			goto COPY_TMP_TO_USER;

		case LKM_SEQ_FILE_LEAK:
			id = msg.frd.fd;
			files = current->files;

			spin_lock(&files->file_lock);
			fdt = files_fdtable(files);
			file = fdt->fd[id];
			spin_unlock(&files->file_lock);

			tmp = (size_t)file->private_data;
			// printk(KERN_INFO "lkm:ioctl: seq_file %016zx\n", tmp);
			uaddr = (size_t *)msg.frd.uaddr;
			goto COPY_TMP_TO_USER;

		case LKM_CRED_LEAK:
			tmp = (size_t)current->real_cred;
			uaddr = (size_t *)msg.drd.uaddr;
			// printk(KERN_INFO "lkm:ioctl: current->cred %016zx\n", tmp);
			goto COPY_TMP_TO_USER;

		case LKM_FILE_LEAK:
			id = msg.frd.fd;
			files = current->files;

			spin_lock(&files->file_lock);
			fdt = files_fdtable(files);
			tmp = (size_t)fdt->fd[id];
			spin_unlock(&files->file_lock);

			// printk(KERN_INFO "lkm:ioctl: file %016zx\n", tmp);
			uaddr = (size_t *)msg.frd.uaddr;
			goto COPY_TMP_TO_USER;

		case LKM_STACK_LEAK:
			tmp = (size_t)current->stack;
			uaddr = (size_t *)msg.drd.uaddr;
			// printk(KERN_DEBUG "lkm:ioctl: current->stack %16zx with current %16zx within [%016zx %016zx]\n", tmp, (size_t)&dummy, VMALLOC_START, VMALLOC_END);
			goto COPY_TMP_TO_USER;

		case LKM_CODE_LEAK:
			tmp = (size_t)__text;
			uaddr = (size_t *)msg.drd.uaddr;
			goto COPY_TMP_TO_USER;

		case LKM_VMEMMAP_LEAK:
			tmp = (size_t)vmemmap_base;
			uaddr = (size_t *)msg.drd.uaddr;
			goto COPY_TMP_TO_USER;

		case LKM_VMALLOC_BASE_LEAK:
			tmp = (size_t)vmalloc_base;
			uaddr = (size_t *)msg.drd.uaddr;
			goto COPY_TMP_TO_USER;

		case LKM_ARB_FREE:
			printk(KERN_DEBUG "lkm:ioctl: free %016zx\n", msg.af.kaddr);
			kfree((void *)msg.af.kaddr);
			break;

		case LKM_PIPE_BUFFER_LEAK:
			id = msg.pbrd.fd;
			files = current->files;

			spin_lock(&files->file_lock);
			fdt = files_fdtable(files);
			file = fdt->fd[id];
			spin_unlock(&files->file_lock);

			pipe = file->private_data;
			tail = pipe->tail;
			head = pipe->head;
			mask = pipe->ring_size - 1;
			if (msg.pbrd.rdend)
				tmp = (size_t)&pipe->bufs[tail & mask];
			else
				tmp = (size_t)&pipe->bufs[(head - 1) & mask];
			// printk(KERN_DEBUG "lkm:ioctl: pipe_buffer %016zx\n", tmp);
			uaddr = (size_t *)msg.pbrd.uaddr;
			goto COPY_TMP_TO_USER;

		case LKM_PAGETABLE_WALK:
			printk(KERN_DEBUG "lkm:ioctl: page table walk\n");
			msg.ptw.pgde = 0;
			msg.ptw.p4de = 0;
			msg.ptw.pude = 0;
			msg.ptw.pmde = 0;
			msg.ptw.pte = 0;
			pagetable_walk(&msg);
			ret = copy_to_user((msg_t*)param, (msg_t*)&msg, sizeof(msg_t));
			if (ret < 0) {
				printk(KERN_ALERT "lkm:ioctl: copy_to_user failed\n");
				ret = -1;
				goto RETURN;
			}
			break;

		case LKM_IS_4KB:
			ret = !isLargePage(msg.ap.addr);
			// printk(KERN_DEBUG "lkm:ioctl: %016zx is %s page\n", msg.ap.addr, ret == 1 ? "4kB" : "2MB");
			return ret;

		default:
			printk(KERN_ERR "lkm:ioctl: no valid num\n");
			ret = -1;
			goto RETURN;
	}
	ret = 0;
	goto DONE;

COPY_TMP_TO_USER:
	if(uaddr == 0) { // && "forgot to set uaddr");
		printk(KERN_ERR "lkm:ioctl: uaddr == 0\n");
		// ret = -1;
		goto RETURN;
	}
	if (tmp == -1) { // && "forgot to set tmp");
		printk(KERN_ERR "lkm:ioctl: tmp == -1\n");
		// ret = -1;
		goto RETURN;
	}
	// printk(KERN_INFO "lkm:ioctl: copy 0x%016zx to mem[0x%016zx]\n", tmp, (size_t)uaddr);
	ret = copy_to_user(uaddr, &tmp, sizeof(size_t));
	if (ret < 0) {
		printk(KERN_ERR "lkm:ioctl: copy_to_user failed\n");
		ret = -1;
		goto RETURN;
	}
	ret = 0;

DONE:
	// printk(KERN_INFO "lkm:ioctl: done\n");

RETURN:
	return ret;
}
EXPORT_SYMBOL(lkm_ioctl);

module_init(lkm_init);
module_exit(lkm_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lukas Maar");
MODULE_DESCRIPTION("LKM");
MODULE_VERSION("0.1");
