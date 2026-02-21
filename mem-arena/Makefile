CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra
AR ?= ar
ARFLAGS ?= rcs

INCLUDE_DIR := include
SRC_DIR := src
EXAMPLE_DIR := examples

LIB := libmemarena.a
LIB_SRCS := \
	$(SRC_DIR)/mem_arena.c \
	$(SRC_DIR)/mem_arena_codec.c \
	$(SRC_DIR)/mem_arena_lru.c
LIB_OBJS := $(LIB_SRCS:.c=.o)

DEMO := arena_demo

.PHONY: all clean demo

all: $(LIB) $(DEMO)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -I$(SRC_DIR) -c $< -o $@

$(LIB): $(LIB_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(DEMO): $(EXAMPLE_DIR)/arena_demo.c $(LIB)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) $< -L. -lmemarena -llz4 -o $@

demo: $(DEMO)
	./$(DEMO)

clean:
	rm -f $(LIB) $(LIB_OBJS) $(DEMO)
