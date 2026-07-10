#include "deflate_codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define TEST_WBITS 10
#define TEST_MAX_OUTPUT (512U * 1024U)

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                          \
    tests_passed++;                                                            \
  } while (0)
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

static void test_raw_roundtrip(void) {
  TEST("raw deflate round-trip");

  uint8_t original[4096];
  for (size_t i = 0; i < sizeof(original); i++) {
    original[i] = (uint8_t)((i * 17 + i / 128) & 0xff);
  }

  size_t compressed_len = 0;
  uint8_t *compressed = deflate_compress_raw_alloc(original, sizeof(original),
                                                   &compressed_len, TEST_WBITS);
  if (!compressed) {
    FAIL("compression failed");
    return;
  }

  size_t decoded_len = 0;
  uint8_t *decoded = deflate_decompress_raw_alloc(
      compressed, compressed_len, &decoded_len, TEST_WBITS, TEST_MAX_OUTPUT);
  free(compressed);

  if (!decoded || decoded_len != sizeof(original) ||
      memcmp(decoded, original, sizeof(original)) != 0) {
    free(decoded);
    FAIL("round-trip mismatch");
    return;
  }

  printf("(%zu -> %zu bytes) ", sizeof(original), compressed_len);
  free(decoded);
  PASS();
}

static void test_wrapped_zlib_decode(void) {
  TEST("zlib-wrapped decode");

  static const uint8_t original[] =
      "Wrapped zlib compatibility data. Wrapped zlib compatibility data.";
  uLongf compressed_len = compressBound(sizeof(original));
  uint8_t *compressed = (uint8_t *)malloc((size_t)compressed_len);
  if (!compressed || compress2(compressed, &compressed_len, original,
                               sizeof(original), Z_BEST_COMPRESSION) != Z_OK) {
    free(compressed);
    FAIL("wrapped compression failed");
    return;
  }

  size_t decoded_len = 0;
  uint8_t *decoded = deflate_decompress_zlib_alloc(
      compressed, (size_t)compressed_len, &decoded_len, TEST_MAX_OUTPUT);
  free(compressed);

  if (!decoded || decoded_len != sizeof(original) ||
      memcmp(decoded, original, sizeof(original)) != 0) {
    free(decoded);
    FAIL("wrapped decode mismatch");
    return;
  }

  free(decoded);
  PASS();
}

static void test_output_limit(void) {
  TEST("decompression output limit");

  uint8_t original[4096] = {0};
  size_t compressed_len = 0;
  uint8_t *compressed = deflate_compress_raw_alloc(original, sizeof(original),
                                                   &compressed_len, TEST_WBITS);
  if (!compressed) {
    FAIL("compression failed");
    return;
  }

  size_t decoded_len = 0;
  uint8_t *decoded = deflate_decompress_raw_alloc(
      compressed, compressed_len, &decoded_len, TEST_WBITS, 1024);
  free(compressed);

  if (decoded) {
    free(decoded);
    FAIL("oversized output was accepted");
    return;
  }

  PASS();
}

static void test_empty_roundtrip(void) {
  TEST("empty raw-deflate round-trip");

  static const uint8_t empty[] = {0};
  size_t compressed_len = 0;
  uint8_t *compressed =
      deflate_compress_raw_alloc(empty, 0, &compressed_len, TEST_WBITS);
  if (!compressed) {
    FAIL("empty compression failed");
    return;
  }

  size_t decoded_len = 1;
  uint8_t *decoded = deflate_decompress_raw_alloc(
      compressed, compressed_len, &decoded_len, TEST_WBITS, TEST_MAX_OUTPUT);
  free(compressed);

  if (!decoded || decoded_len != 0) {
    free(decoded);
    FAIL("empty round-trip mismatch");
    return;
  }

  free(decoded);
  PASS();
}

static void test_invalid_stream(void) {
  TEST("invalid stream rejection");

  static const uint8_t invalid[] = {0xff, 0xff, 0xff, 0xff};
  size_t decoded_len = 0;
  uint8_t *decoded = deflate_decompress_raw_alloc(
      invalid, sizeof(invalid), &decoded_len, TEST_WBITS, TEST_MAX_OUTPUT);
  if (decoded) {
    free(decoded);
    FAIL("invalid stream was accepted");
    return;
  }

  PASS();
}

int main(void) {
  printf("Deflate Codec Test Suite\n");
  printf("========================\n\n");

  test_raw_roundtrip();
  test_wrapped_zlib_decode();
  test_output_limit();
  test_empty_roundtrip();
  test_invalid_stream();

  printf("\n========================\n");
  printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
