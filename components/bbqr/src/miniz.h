/*
 * miniz.h - Minimal zlib-compatible compression/decompression
 * This is a minimal subset for BBQr compression support.
 *
 * Features:
 * - LZ77 compression with static Huffman codes
 * - Configurable window size (wbits parameter, default 10 = 1024 bytes)
 * - Full decompression support (stored, fixed, dynamic Huffman)
 * - Zlib header/trailer with Adler32 checksum
 *
 * Based on:
 * - miniz by Rich Geldreich (public domain)
 * - uzlib by Paul Sokolovsky (MIT license)
 * - MicroPython deflate module
 */

#ifndef MINIZ_H
#define MINIZ_H

#include <stddef.h>
#include <stdint.h>

/* Compression/decompression return codes */
#define MZ_OK 0
#define MZ_STREAM_END 1
#define MZ_NEED_DICT 2
#define MZ_ERRNO (-1)
#define MZ_STREAM_ERROR (-2)
#define MZ_DATA_ERROR (-3)
#define MZ_MEM_ERROR (-4)
#define MZ_BUF_ERROR (-5)
#define MZ_VERSION_ERROR (-6)
#define MZ_PARAM_ERROR (-10000)

/* Compression levels (currently ignored, using static Huffman) */
#define MZ_NO_COMPRESSION 0
#define MZ_BEST_SPEED 1
#define MZ_BEST_COMPRESSION 9
#define MZ_DEFAULT_COMPRESSION 6

/* Window bits (wbits) - determines LZ77 window size: 2^wbits bytes */
#define MZ_MIN_WBITS 8  /* 256 bytes */
#define MZ_MAX_WBITS 15 /* 32KB */
#define MZ_DEFAULT_WBITS 10 /* 1024 bytes - optimal for BBQr */

/* Flush types */
#define MZ_NO_FLUSH 0
#define MZ_PARTIAL_FLUSH 1
#define MZ_SYNC_FLUSH 2
#define MZ_FULL_FLUSH 3
#define MZ_FINISH 4

/**
 * @brief Compress data using zlib deflate
 *
 * @param dest Destination buffer for compressed data
 * @param dest_len Pointer to dest buffer size, updated with actual size
 * @param source Source data to compress
 * @param source_len Length of source data
 * @param level Compression level (0-9, or MZ_DEFAULT_COMPRESSION)
 * @return MZ_OK on success, error code on failure
 */
int mz_compress2(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                 size_t source_len, int level);

/**
 * @brief Compress data using default compression level
 */
int mz_compress(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                size_t source_len);

/**
 * @brief Get upper bound on compressed size
 */
size_t mz_compressBound(size_t source_len);

/**
 * @brief Decompress zlib-compressed data
 *
 * @param dest Destination buffer for decompressed data
 * @param dest_len Pointer to dest buffer size, updated with actual size
 * @param source Compressed source data
 * @param source_len Length of compressed data
 * @return MZ_OK on success, error code on failure
 */
int mz_uncompress(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                  size_t source_len);

/**
 * @brief Decompress with dynamic allocation
 *
 * @param source Compressed source data
 * @param source_len Length of compressed data
 * @param dest_len Pointer to store decompressed length
 * @return Allocated buffer with decompressed data, or NULL on failure
 *         Caller must free the returned buffer.
 */
uint8_t *mz_uncompress_alloc(const uint8_t *source, size_t source_len,
                             size_t *dest_len);

/**
 * @brief Compress with dynamic allocation
 *
 * @param source Source data to compress
 * @param source_len Length of source data
 * @param dest_len Pointer to store compressed length
 * @param level Compression level
 * @return Allocated buffer with compressed data, or NULL on failure
 *         Caller must free the returned buffer.
 */
uint8_t *mz_compress_alloc(const uint8_t *source, size_t source_len,
                           size_t *dest_len, int level);

/**
 * @brief Decompress raw deflate data (no zlib header/trailer)
 *
 * @param dest Destination buffer for decompressed data
 * @param dest_len Pointer to dest buffer size, updated with actual size
 * @param source Compressed source data (raw deflate)
 * @param source_len Length of compressed data
 * @return MZ_OK on success, error code on failure
 */
int mz_inflate_raw(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                   size_t source_len);

/**
 * @brief Decompress raw deflate with dynamic allocation
 */
uint8_t *mz_inflate_raw_alloc(const uint8_t *source, size_t source_len,
                              size_t *dest_len);

/**
 * @brief Compress to raw deflate (no zlib header/trailer)
 * Uses default window bits (MZ_DEFAULT_WBITS = 10, 1024 bytes)
 */
int mz_deflate_raw(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                   size_t source_len);

/**
 * @brief Compress to raw deflate with configurable window size
 *
 * @param wbits Window bits (8-15), determines window size as 2^wbits bytes
 *              Use 10 for BBQr (1024 byte window)
 */
int mz_deflate_raw_wbits(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                         size_t source_len, int wbits);

/**
 * @brief Compress to raw deflate with dynamic allocation
 */
uint8_t *mz_deflate_raw_alloc(const uint8_t *source, size_t source_len,
                              size_t *dest_len);

/**
 * @brief Compress to raw deflate with dynamic allocation and wbits
 */
uint8_t *mz_deflate_raw_alloc_wbits(const uint8_t *source, size_t source_len,
                                    size_t *dest_len, int wbits);

/**
 * @brief Compress with zlib wrapper and configurable window size
 *
 * @param wbits Window bits (8-15), determines window size as 2^wbits bytes
 */
int mz_compress_wbits(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                      size_t source_len, int level, int wbits);

/**
 * @brief Compress with zlib wrapper, dynamic allocation, and wbits
 */
uint8_t *mz_compress_alloc_wbits(const uint8_t *source, size_t source_len,
                                 size_t *dest_len, int level, int wbits);

#endif /* MINIZ_H */
