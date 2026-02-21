#include "mem_arena_codec.h"

#include <lz4.h>

int mem_arena_lz4_compress(
    const unsigned char *input,
    size_t input_size,
    unsigned char *output,
    int output_capacity,
    int acceleration
)
{
    return LZ4_compress_fast(
        (const char *)input,
        (char *)output,
        (int)input_size,
        output_capacity,
        acceleration
    );
}

int mem_arena_lz4_decompress(
    const unsigned char *input,
    int input_size,
    unsigned char *output,
    int output_size
)
{
    return LZ4_decompress_safe(
        (const char *)input,
        (char *)output,
        input_size,
        output_size
    );
}
