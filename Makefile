BPF_CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null)

CFLAGS += -O2 -g -Wall -Wextra
BPF_CFLAGS += -O2 -g -target bpf -D__TARGET_ARCH_x86

.PHONY: all clean run

all: proc_create

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

src/proc_create.bpf.o: src/proc_create.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

src/proc_create.skel.h: src/proc_create.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

proc_create: src/proc_create.c src/proc_create.skel.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -I./src $< -o $@ $(LIBBPF_LIBS) -lelf -lz

run: proc_create
	sudo ./proc_create

clean:
	rm -f proc_create vmlinux.h src/*.o src/*.skel.h
