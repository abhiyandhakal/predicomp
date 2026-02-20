CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra

.PHONY: all clean clean-samples run

all: compressor_monitor

compressor_monitor: main.c
	$(CC) $(CFLAGS) $< -o $@

run: compressor_monitor
	./compressor_monitor

clean:
	rm -f compressor_monitor results.csv test.txt.lz4 test.txt.out
	rm -f samples/*.lz4.tmp samples/*.out.tmp

clean-samples:
	rm -rf samples
