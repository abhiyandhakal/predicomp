CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -D_GNU_SOURCE
LDFLAGS ?=

SRC_DIR := src
INC_DIR := include
MEM_ARENA_SRC := ../mem-arena/src/mem_arena_codec.c
DAEMON_SRCS := $(SRC_DIR)/predicomp_pager.c $(SRC_DIR)/pager_damon.c $(MEM_ARENA_SRC)

DAEMON := predicomp_pager
CLIENT_LIB := libpredicomp_client.a

.PHONY: all clean

all: $(DAEMON) $(CLIENT_LIB)

$(DAEMON): $(DAEMON_SRCS) $(SRC_DIR)/protocol.h $(SRC_DIR)/pager_damon.h
	$(CC) $(CFLAGS) -I$(INC_DIR) -I$(SRC_DIR) -I../mem-arena/src \
		$(DAEMON_SRCS) -o $@ $(LDFLAGS) -llz4 -pthread

$(CLIENT_LIB): $(SRC_DIR)/predicomp_client.c $(INC_DIR)/predicomp_client.h $(SRC_DIR)/protocol.h
	$(CC) $(CFLAGS) -I$(INC_DIR) -I$(SRC_DIR) -c $(SRC_DIR)/predicomp_client.c -o $(SRC_DIR)/predicomp_client.o
	ar rcs $@ $(SRC_DIR)/predicomp_client.o

clean:
	rm -f $(DAEMON) $(CLIENT_LIB) $(SRC_DIR)/predicomp_client.o
