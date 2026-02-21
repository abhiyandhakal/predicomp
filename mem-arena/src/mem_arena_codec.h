#ifndef MEM_ARENA_CODEC_H
#define MEM_ARENA_CODEC_H

#include <stddef.h>

int mem_arena_lz4_compress(
    const unsigned char *input,
    size_t input_size,
    unsigned char *output,
    int output_capacity,
    int acceleration
);

int mem_arena_lz4_decompress(
    const unsigned char *input,
    int input_size,
    unsigned char *output,
    int output_size
);

#endif
