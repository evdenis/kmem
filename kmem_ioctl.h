/* SPDX-License-Identifier: GPL-2.0 */
#ifndef KMEM_IOCTL_H
#define KMEM_IOCTL_H

#include <linux/ioctl.h>

struct kmem_ioctl {
	struct {
		char *buf;
		size_t	count;
		long long ppos; // loff_t
	} rw;
	struct {
		char *buf;
		long long ppos;
	} rw_ulong;
	void *stack_ptr;
	struct {
		long long ppos;
	} wnull;
};

#define KMEM_IOCTL_MAGIC 0x33
#define KMEM_IOCTL_READ _IOR(KMEM_IOCTL_MAGIC, 0, struct kmem_ioctl)
#define KMEM_IOCTL_WRITE _IOW(KMEM_IOCTL_MAGIC, 1, struct kmem_ioctl)
#define KMEM_IOCTL_READ_ULONG _IOR(KMEM_IOCTL_MAGIC, 2, struct kmem_ioctl)
#define KMEM_IOCTL_WRITE_ULONG _IOW(KMEM_IOCTL_MAGIC, 3, struct kmem_ioctl)
#define KMEM_IOCTL_STACK_PTR _IOR(KMEM_IOCTL_MAGIC, 4, struct kmem_ioctl)
#define KMEM_IOCTL_WRITE_NULL _IOW(KMEM_IOCTL_MAGIC, 5, struct kmem_ioctl)
#define KMEM_IOCTL_GET_ROOT _IOW(KMEM_IOCTL_MAGIC, 6, struct kmem_ioctl)

#endif /* KMEM_IOCTL_H */
