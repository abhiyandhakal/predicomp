CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -D_GNU_SOURCE
AR ?= ar
ARFLAGS ?= rcs

INCLUDE_DIR := include
SRC_DIR := src
EXAMPLE_DIR := examples
TOOL_DIR := tools

LIB := libmemarena.a
LIB_SRCS := \
	$(SRC_DIR)/mem_arena.c \
	$(SRC_DIR)/mem_arena_damon.c \
	$(SRC_DIR)/mem_arena_codec.c \
	$(SRC_DIR)/mem_arena_lru.c
LIB_OBJS := $(LIB_SRCS:.c=.o)

DEMO := arena_demo
PROCESS_BENCH := process_mem_bench

.PHONY: all clean demo bench

all: $(LIB) $(DEMO) $(PROCESS_BENCH)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) -c $< -o $@

$(LIB): $(LIB_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(DEMO): $(EXAMPLE_DIR)/arena_demo.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< -L. -lmemarena -llz4 -pthread -o $@

$(PROCESS_BENCH): $(TOOL_DIR)/process_mem_bench.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< -L. -lmemarena -llz4 -pthread -o $@

demo: $(DEMO)
	./$(DEMO)

bench: $(PROCESS_BENCH)
	./$(PROCESS_BENCH)

clean:
	rm -f $(LIB) $(LIB_OBJS) $(DEMO) $(PROCESS_BENCH)
