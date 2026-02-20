CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra
LZ4_CFLAGS ?= $(shell pkg-config --cflags liblz4 2>/dev/null)
LZ4_LIBS ?= $(shell pkg-config --libs liblz4 2>/dev/null || echo -llz4)

.PHONY: all clean clean-samples run

all: compressor_monitor

compressor_monitor: main.c
	$(CC) $(CFLAGS) $(LZ4_CFLAGS) $< -o $@ $(LZ4_LIBS)

run: compressor_monitor
	./compressor_monitor

clean:
	rm -f compressor_monitor results.csv

clean-samples:
	rm -rf samples
