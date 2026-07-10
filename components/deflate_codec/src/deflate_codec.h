#ifndef DEFLATE_CODEC_H
#define DEFLATE_CODEC_H

#include <stddef.h>
#include <stdint.h>

/** Compress to raw deflate using maximum compression effort. */
uint8_t *deflate_compress_raw_alloc(const uint8_t *source, size_t source_len,
                                    size_t *dest_len, int window_bits);

/** Decompress raw deflate while enforcing an output-size limit. */
uint8_t *deflate_decompress_raw_alloc(const uint8_t *source, size_t source_len,
                                      size_t *dest_len, int window_bits,
                                      size_t max_output);

/** Decompress a zlib-wrapped stream while enforcing an output-size limit. */
uint8_t *deflate_decompress_zlib_alloc(const uint8_t *source, size_t source_len,
                                       size_t *dest_len, size_t max_output);

#endif /* DEFLATE_CODEC_H */
