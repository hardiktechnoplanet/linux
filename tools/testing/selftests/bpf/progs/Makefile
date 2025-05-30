# SPDX-License-Identifier: GPL-2.0

CLANG := clang
BPFTOOL := bpftool
CFLAGS := -g -O2 -Wall
BPFCFLAGS := $(CFLAGS) -target bpf -D__TARGET_ARCH_x86

# Add kernel headers path
INCLUDES := -I$(shell pwd) \
           -I$(shell pwd)/../../include \
           -I$(shell pwd)/../../../include \
           -I$(shell pwd)/../../../include/uapi \
           -I$(shell pwd)/../../include/tools \
           -I/usr/include/x86_64-linux-gnu

all: my_bpf_prog.bpf.o my_bpf_loader

my_bpf_prog.bpf.o: my_bpf_prog.c vmlinux.h
	$(CLANG) $(BPFCFLAGS) $(INCLUDES) -c $< -o $@

my_bpf_loader: my_bpf_loader.c
	gcc $(CFLAGS) -o $@ $< -lbpf -lelf

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f *.o my_bpf_loader vmlinux.h
