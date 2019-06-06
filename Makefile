# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2019 Denis Efremov <efremov@linux.com>. All Rights Reserved.

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: build

ifneq ($(V),1)
MAKEFLAGS += --no-print-directory
endif

version.h:
	@ver="/* SPDX-License-Identifier: GPL-2.0 */\n\
	#define KMEM_VERSION \"$$(git describe --dirty 2>/dev/null)\"" && \
	[ "$$(cat version.h 2>/dev/null)" != "$$ver" ]                     && \
	echo "$$ver" > version.h                                           && \
	git update-index --assume-unchanged version.h || true

build: version.h
	@$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	@$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	@-rm -f get_root

style:
	$(KERNELDIR)/scripts/checkpatch.pl -f --max-line-length=4000 --codespell --color=always kmem.c kmem_ioctl.h

check:
	@scan-build --html-title=Kmem -maxloop 100 --keep-going $(MAKE) -C $(KERNELDIR) C=2 CF="-D__CHECK_ENDIAN__" M=$(PWD)

coccicheck:
	@$(MAKE) -C $(KERNELDIR) coccicheck DEBUG_FILE="cocci.debug" MODE=report M=$(PWD)

format:
	@clang-format -style=file -i $(filter-out kmem.mod.c,$(wildcard *.c)) $(wildcard *.h)

cloc:
	@cloc --skip-uniqueness --by-file $(filter-out kmem.mod.c,$(wildcard *.c)) $(wildcard *.h)

unload:
	@-sudo rmmod kmem

load: build
	@sudo insmod ./kmem.ko

run: unload load
	@sudo dmesg | tail -n 30

get_root: get_root.c kmem_ioctl.h
	@gcc -std=gnu99 -o $@ $<

test: get_root
	@./$<

.PHONY: all version.h build style check coccicheck format cloc run load unload test
