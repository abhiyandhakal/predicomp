BPF_CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
LIBBPF_CFLAGS ?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS ?= $(shell pkg-config --libs libbpf 2>/dev/null)

CFLAGS += -O2 -g -Wall -Wextra
BPF_CFLAGS += -O2 -g -target bpf -D__TARGET_ARCH_x86

.PHONY: all clean run run-page-fault run-swap-probe run-proc-lifecycle workloads workloads-smoke ram-pool-status mem-arena mem-arena-demo mem-arena-bench controller process-pager process-pager-client

all: proc_create page_fault swap_probe proc_lifecycle workload_controller workloads mem-arena

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

src/proc_create.bpf.o: src/proc_create.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

src/proc_create.skel.h: src/proc_create.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

proc_create: src/proc_create.c src/proc_create.skel.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -I./src $< -o $@ $(LIBBPF_LIBS) -lelf -lz

src/page_fault.bpf.o: src/page_fault.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

src/page_fault.skel.h: src/page_fault.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

page_fault: src/page_fault.c src/page_fault.skel.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -I./src $< -o $@ $(LIBBPF_LIBS) -lelf -lz

src/swap_probe.bpf.o: src/swap_probe.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

src/swap_probe.skel.h: src/swap_probe.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

swap_probe: src/swap_probe.c src/swap_probe.skel.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -I./src $< -o $@ $(LIBBPF_LIBS) -lelf -lz

src/proc_lifecycle.bpf.o: src/proc_lifecycle.bpf.c vmlinux.h src/proc_lifecycle_event.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

src/proc_lifecycle.skel.h: src/proc_lifecycle.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

proc_lifecycle: src/proc_lifecycle.skel.h
	@echo "generated src/proc_lifecycle.skel.h"

workload_controller: controller/workload_controller.c src/proc_lifecycle.skel.h controller/workload_control_protocol.h src/proc_lifecycle_event.h
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -I./src -I./controller $< -o $@ $(LIBBPF_LIBS) -lelf -lz

controller: workload_controller

run: proc_create
	sudo ./proc_create

run-page-fault: page_fault
	sudo ./page_fault

run-swap-probe: swap_probe
	sudo ./swap_probe

run-proc-lifecycle: workload_controller
	sudo ./workload_controller

workloads: process-pager-client
	$(MAKE) -C workloads

process-pager:
	$(MAKE) -C process-pager

process-pager-client:
	$(MAKE) -C process-pager libpredicomp_client.a

workloads-smoke: workloads
	$(MAKE) -C workloads smoke

mem-arena:
	$(MAKE) -C mem-arena

mem-arena-demo: mem-arena
	$(MAKE) -C mem-arena demo

mem-arena-bench: mem-arena
	$(MAKE) -C mem-arena bench

ram-pool-status:
	./ram-pool/scripts/status_zram_pool.sh

clean:
	rm -f proc_create page_fault swap_probe proc_lifecycle workload_controller vmlinux.h src/*.o src/*.skel.h
	$(MAKE) -C workloads clean
	$(MAKE) -C process-pager clean
