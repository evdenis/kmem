#ifndef KMEM_IOCTL_H
#define KMEM_IOCTL_H

#include <linux/ioctl.h>

struct kmem_ioctl {
	struct {
		char *	buf;
		size_t	count;
		long long int ppos;
	} rw;
	struct {
		char *	buf;
		long long int ppos;
	} rw_ulong;
	unsigned long *stack_ptr;
	struct {
		long long int ppos;
	} wnull;
};

#define KMEM_IOCTL_MAGIC 0x33
#define KMEM_IOCTL_READ _IOR(KMEM_IOCTL_MAGIC, 0, struct kmem_ioctl)
#define KMEM_IOCTL_WRITE _IOW(KMEM_IOCTL_MAGIC, 1, struct kmem_ioctl)
#define KMEM_IOCTL_READ_ULONG _IOR(KMEM_IOCTL_MAGIC, 2, struct kmem_ioctl)
#define KMEM_IOCTL_WRITE_ULONG _IOW(KMEM_IOCTL_MAGIC, 3, struct kmem_ioctl)
#define KMEM_IOCTL_STACK_PTR _IOR(KMEM_IOCTL_MAGIC, 4, struct kmem_ioctl)
#define KMEM_IOCTL_WRITE_NULL _IOW(KMEM_IOCTL_MAGIC, 5, struct kmem_ioctl)

#endif /* KMEM_IOCTL_H */
