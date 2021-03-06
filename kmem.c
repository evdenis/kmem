// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Denis Efremov <efremov@linux.com>. All Rights Reserved.
 */

#include "version.h"
#include <asm/stacktrace.h>
#include <linux/device.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "kmem_ioctl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Denis Efremov");
MODULE_DESCRIPTION("An example module for reading and writing kernel memory");
MODULE_VERSION(KMEM_VERSION);

static char *device_name = "kmemory";
module_param(device_name, charp, 0444);
MODULE_PARM_DESC(device_name,
		 "The device name for reading and writing kernel memory.");

static int	      major_number;
static struct class  *mclass;
static struct device *mdevice;

typedef long (*vmem_t)(char *buf, char *addr, unsigned long count);
static vmem_t kmread;
static vmem_t kmwrite;

typedef int (*check_addr_t)(const void *x);
static check_addr_t check_vmalloc_or_module_addr;

void dump_creds(const struct cred *c)
{
	pr_info("Dumping cred %p\n", c);
	if (c) {
		unsigned int i = 0;
		pr_info("usage: %d\n", atomic_read(&c->usage));
		pr_info("uid %u gid %u\n", c->uid.val, c->gid.val);
		pr_info("suid %u sgid %u\n", c->suid.val, c->sgid.val);
		pr_info("euid %u egid %u\n", c->euid.val, c->egid.val);
		pr_info("fsuid %u fsgid %u\n", c->fsuid.val, c->fsgid.val);
		pr_info("securebits %u\n", c->securebits);
		pr_info("cap_permitted ");
		CAP_FOR_EACH_U32(i) {
			pr_cont("%x ", c->cap_permitted.cap[i]);
		}
		pr_cont("\n");
		pr_info("cap_effective ");
		CAP_FOR_EACH_U32(i) {
			pr_cont("%x ", c->cap_effective.cap[i]);
		}
		pr_cont("\n");
	}
}

static inline unsigned long size_inside_page(unsigned long start,
					     unsigned long size)
{
	unsigned long sz;

	sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));

	return min(sz, size);
}

// The code is based on /dev/kmem driver
/*
 * This function reads the *virtual* memory as seen by the kernel.
 */
static ssize_t read_kmem(struct file *file, char __user *buf, size_t count,
			 loff_t *ppos)
{
	unsigned long p = *ppos;
	ssize_t       low_count, read, sz;
	char *kbuf; /* k-addr because kmread() takes vmlist_lock rwlock */
	int   err = 0;

	read = 0;
	if (p < (unsigned long)high_memory) {
		low_count = count;
		if (count > (unsigned long)high_memory - p)
			low_count = (unsigned long)high_memory - p;

		while (low_count > 0) {
			sz = size_inside_page(p, low_count);

			/*
			 * On ia64 if a page has been mapped somewhere as
			 * uncached, then it must also be accessed uncached
			 * by the kernel or data corruption may occur
			 */
			kbuf = xlate_dev_kmem_ptr((void *)p);
			if (!virt_addr_valid(kbuf))
				return -ENXIO;

			if (copy_to_user(buf, kbuf, sz))
				return -EFAULT;
			buf += sz;
			p += sz;
			read += sz;
			low_count -= sz;
			count -= sz;
		}
	}

	if (count > 0) {
		kbuf = (char *)__get_free_page(GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;
		while (count > 0) {
			sz = size_inside_page(p, count);
			if (!check_vmalloc_or_module_addr((void *)p)) {
				err = -ENXIO;
				break;
			}
			sz = kmread(kbuf, (char *)p, sz);
			if (!sz)
				break;
			if (copy_to_user(buf, kbuf, sz)) {
				err = -EFAULT;
				break;
			}
			count -= sz;
			buf += sz;
			read += sz;
			p += sz;
		}
		free_page((unsigned long)kbuf);
	}
	*ppos = p;
	return read ? read : err;
}

static ssize_t do_write_kmem(unsigned long p, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	ssize_t       written, sz;
	unsigned long copied;

	written = 0;

	while (count > 0) {
		void *ptr;

		sz = size_inside_page(p, count);

		/*
		 * On ia64 if a page has been mapped somewhere as uncached, then
		 * it must also be accessed uncached by the kernel or data
		 * corruption may occur.
		 */
		ptr = xlate_dev_kmem_ptr((void *)p);
		if (!virt_addr_valid(ptr))
			return -ENXIO;

		copied = copy_from_user(ptr, buf, sz);
		if (copied) {
			written += sz - copied;
			if (written)
				break;
			return -EFAULT;
		}
		buf += sz;
		p += sz;
		count -= sz;
		written += sz;
	}

	*ppos += written;
	return written;
}

// The code is based on /dev/kmem driver
/*
 * This function writes to the *virtual* memory as seen by the kernel.
 */
static ssize_t write_kmem(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	unsigned long p     = *ppos;
	ssize_t       wrote = 0;
	ssize_t       virtr = 0;
	char *kbuf; /* k-addr because vwrite() takes vmlist_lock rwlock */
	int   err = 0;

	if (p < (unsigned long)high_memory) {
		unsigned long to_write = min_t(unsigned long, count,
					       (unsigned long)high_memory - p);
		wrote		       = do_write_kmem(p, buf, to_write, ppos);
		if (wrote != to_write)
			return wrote;
		p += wrote;
		buf += wrote;
		count -= wrote;
	}

	if (count > 0) {
		kbuf = (char *)__get_free_page(GFP_KERNEL);
		if (!kbuf)
			return wrote ? wrote : -ENOMEM;
		while (count > 0) {
			unsigned long sz = size_inside_page(p, count);
			unsigned long n;

			if (!check_vmalloc_or_module_addr((void *)p)) {
				err = -ENXIO;
				break;
			}
			n = copy_from_user(kbuf, buf, sz);
			if (n) {
				err = -EFAULT;
				break;
			}
			kmwrite(kbuf, (char *)p, sz);
			count -= sz;
			buf += sz;
			virtr += sz;
			p += sz;
		}
		free_page((unsigned long)kbuf);
	}

	*ppos = p;
	return virtr + wrote ?: err;
}

static long ioctl_kmem(struct file *filp, unsigned int cmd, unsigned long argp)
{
	void __user       *arg_user;
	struct kmem_ioctl arg_kernel;
	ssize_t		  n = 0;

	arg_user = (void __user *)argp;

	if (copy_from_user(&arg_kernel, arg_user, sizeof(arg_kernel)))
		return -EFAULT;

	switch (cmd) {
	case KMEM_IOCTL_READ:
		pr_info("read ppos %llx count %zu\n", arg_kernel.rw.ppos,
			arg_kernel.rw.count);
		n = read_kmem(filp, arg_kernel.rw.buf, arg_kernel.rw.count,
			      &arg_kernel.rw.ppos);
		pr_info("read %zd bytes\n", n);
		break;
	case KMEM_IOCTL_WRITE:
		pr_info("write ppos %llx count %zu\n", arg_kernel.rw.ppos,
			arg_kernel.rw.count);
		n = write_kmem(filp, arg_kernel.rw.buf, arg_kernel.rw.count,
			       &arg_kernel.rw.ppos);
		pr_info("write %zd bytes\n", n);
		break;
	case KMEM_IOCTL_READ_ULONG:
		pr_info("read ppos %llx count %zu\n", arg_kernel.rw_ulong.ppos,
			sizeof(unsigned long));
		n = read_kmem(filp, arg_kernel.rw_ulong.buf,
			      sizeof(unsigned long), &arg_kernel.rw_ulong.ppos);
		pr_info("read %zd bytes\n", n);
		break;
	case KMEM_IOCTL_WRITE_ULONG:
		pr_info("write ppos %llx count %zu\n", arg_kernel.rw_ulong.ppos,
			sizeof(unsigned long));
		n = write_kmem(filp, arg_kernel.rw_ulong.buf,
			       sizeof(unsigned long),
			       &arg_kernel.rw_ulong.ppos);
		pr_info("write %zd bytes\n", n);
		break;
	case KMEM_IOCTL_STACK_PTR:
		arg_kernel.stack_ptr = (void *) current_stack_pointer;

		pr_info("THREAD_SIZE %lx\n", THREAD_SIZE);
		pr_info("stack ptr %p\n", arg_kernel.stack_ptr);
		pr_info("current %p\n", current);
		pr_info("current_thread_info %p\n", current_thread_info());
		pr_info("ti task_struct %p\n", current_thread_info()->task);
		pr_info("current->cred field addr %p\n", &current->cred);
		pr_info("current->cred addr %p\n", current->cred);
		pr_info("current->cred offset %zu\n", offsetof(struct task_struct, cred));
		pr_info("struct task_struct size %zu\n", sizeof(struct task_struct));
		pr_info("struct cred size %zu\n", sizeof(struct cred));

		if (copy_to_user(arg_user, &arg_kernel, sizeof(arg_kernel)))
			return -EFAULT;
		break;
	case KMEM_IOCTL_WRITE_NULL:
		pr_info("write null to %p\n",
			(unsigned long *)arg_kernel.wnull.ppos);
		*((unsigned long *)arg_kernel.wnull.ppos) = 0;
		break;
#if 0
	case KMEM_IOCTL_GET_ROOT:
		dump_creds(current->cred);
		commit_creds(prepare_kernel_cred(NULL));
		dump_creds(current->cred);
		break;
#endif
	default:
		pr_warn("unknown ioctl cmd %x\n", cmd);
		return -EINVAL;
	}

	return n;
}

static int open_kmem(struct inode *inode, struct file *filp)
{
	/* It's better to check for CAP_SYS_RAWIO in this case, */
	/* but the task assumes the process could be unpriviledged. */
	/* Thus we explicitly disable this check. */
	// return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;

	return 0;
}

static const struct file_operations kmem_fops = {
	.owner		= THIS_MODULE,
	.read		= read_kmem,
	.write		= write_kmem,
	.open		= open_kmem,
	.unlocked_ioctl = ioctl_kmem,
};

static int check_addr(const void *addr)
{
	return 0;
}

long dummy_vread(char *buf, char *addr, unsigned long count)
{
	/* Don't allow overflow */
	if ((unsigned long) buf + count < count)
		count = -(unsigned long) buf;

	memcpy(buf, addr, count);
	return count;
}

long dummy_vwrite(char *buf, char *addr, unsigned long count)
{
	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	memcpy(addr, buf, count);
	return count;
}

static void __init find_functions(void)
{
	kmread = (vmem_t)kallsyms_lookup_name("vread");
	if (!kmread) {
		pr_warn("can't find vread, will use memcpy\n");
		kmread = (vmem_t)&dummy_vread;
	}
	pr_devel("vread found\n");

	kmwrite = (vmem_t)kallsyms_lookup_name("vwrite");
	if (!kmwrite) {
		pr_warn("can't find vwrite, will use memcpy\n");
		kmwrite = (vmem_t)&dummy_vwrite;
	}
	pr_devel("vwrite found\n");

	check_vmalloc_or_module_addr =
		(check_addr_t)kallsyms_lookup_name("is_vmalloc_or_module_addr");
	if (!check_vmalloc_or_module_addr) {
		pr_warn("can't find is_vmalloc_or_module_addr, will skip the check\n");
		check_vmalloc_or_module_addr = check_addr;
	}
	pr_devel("is_vmalloc_or_module_addr found\n");
}

static char *mem_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0666;
	return NULL;
}

static int __init kmem_init(void)
{
	pr_info("loaded ( " KMEM_VERSION " )\n");

	/* allocate major number */
	major_number = register_chrdev(0, device_name, &kmem_fops);
	if (major_number < 0) {
		pr_err("Failed to register a major number\n");
		return major_number;
	}
	pr_devel("major number %d\n", major_number);

	mclass = class_create(THIS_MODULE, "kmemory");
	if (IS_ERR(mclass)) {
		pr_err("failed to create the device class\n");
		unregister_chrdev(major_number, device_name);
		return PTR_ERR(mclass);
	}
	pr_devel("device class registered\n");

	mclass->devnode = mem_devnode;

	mdevice = device_create(mclass, NULL, MKDEV(major_number, 0), NULL,
				device_name);
	if (IS_ERR(mdevice)) {
		pr_err("failed to create the device\n");
		class_destroy(mclass);
		unregister_chrdev(major_number, device_name);
		return PTR_ERR(mdevice);
	}
	pr_devel("device '%s' created\n", device_name);

	find_functions();

	return 0;
}

static void __exit kmem_exit(void)
{
	device_destroy(mclass, MKDEV(major_number, 0));
	class_destroy(mclass);
	unregister_chrdev(major_number, device_name);
	pr_info("unloaded ( " KMEM_VERSION " )\n");
}

module_init(kmem_init);
module_exit(kmem_exit);
