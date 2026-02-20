CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra

.PHONY: all clean run

all: compressor_monitor

compressor_monitor: main.c
	$(CC) $(CFLAGS) $< -o $@

run: compressor_monitor
	./compressor_monitor

clean:
	rm -f compressor_monitor test.txt.lz4 test.txt.out
