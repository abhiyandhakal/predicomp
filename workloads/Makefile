CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=

SRC_DIR := src
BIN_DIR := bin
MEM_ARENA_DIR := ../mem-arena
PROCESS_PAGER_DIR := ../process-pager
MEM_ARENA_SRCS := \
	$(MEM_ARENA_DIR)/src/mem_arena.c \
	$(MEM_ARENA_DIR)/src/mem_arena_damon.c \
	$(MEM_ARENA_DIR)/src/mem_arena_codec.c \
	$(MEM_ARENA_DIR)/src/mem_arena_lru.c
PROCESS_PAGER_CLIENT_LIB := $(PROCESS_PAGER_DIR)/libpredicomp_client.a

TARGETS := \
	fork_exit_storm \
	fork_touch_exit \
	fork_exec_storm \
	interactive_burst \
	mmap_churn \
	anon_streamer \
	random_touch_heap

BINS := $(addprefix $(BIN_DIR)/,$(TARGETS))

.PHONY: all clean smoke

all: $(BINS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(PROCESS_PAGER_CLIENT_LIB):
	$(MAKE) -C $(PROCESS_PAGER_DIR) $(notdir $@)

$(BIN_DIR)/interactive_burst: $(PROCESS_PAGER_CLIENT_LIB)

$(BIN_DIR)/%: $(SRC_DIR)/%.c $(SRC_DIR)/common.c $(SRC_DIR)/common.h $(SRC_DIR)/controller_client.c $(SRC_DIR)/controller_client.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(MEM_ARENA_DIR)/include -I$(MEM_ARENA_DIR)/src -I../controller \
		-I$(PROCESS_PAGER_DIR)/include -I$(PROCESS_PAGER_DIR)/src \
		$< $(SRC_DIR)/common.c $(SRC_DIR)/controller_client.c $(MEM_ARENA_SRCS) \
		$(if $(filter interactive_burst,$*),$(PROCESS_PAGER_CLIENT_LIB),) \
		-o $@ $(LDFLAGS) -llz4 -pthread

smoke: all
	./$(BIN_DIR)/fork_exit_storm --duration-sec 1 --workers 1 --fork-rate 5
	./$(BIN_DIR)/fork_touch_exit --duration-sec 1 --workers 1 --fork-rate 3 --touch-pages 8
	./$(BIN_DIR)/fork_exec_storm --duration-sec 1 --workers 1 --fork-rate 2
	./$(BIN_DIR)/interactive_burst --duration-sec 1 --region-mb 8 --active-ms 10 --idle-ms 10
	./$(BIN_DIR)/mmap_churn --duration-sec 1 --map-kb 64 --ops-per-sec 10
	./$(BIN_DIR)/anon_streamer --duration-sec 1 --region-mb 8 --idle-ms 10
	./$(BIN_DIR)/random_touch_heap --duration-sec 1 --region-mb 8 --ops-per-sec 100

clean:
	rm -f $(BINS)
