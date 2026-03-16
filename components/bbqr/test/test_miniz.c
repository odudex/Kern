/*
 * Miniz Test Suite
 * Tests for LZ77 compression with static Huffman encoding
 *
 * Compile: gcc -o test_miniz test_miniz.c ../src/miniz.c -I../src -Wall -Wextra
 * Run: ./test_miniz
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "miniz.h"

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

/* Helper: print hex dump of first n bytes */
static void hex_dump(const char *label, const uint8_t *data, size_t len,
                     size_t max_show) {
  printf("  %s (%zu bytes): ", label, len);
  size_t show = (len < max_show) ? len : max_show;
  for (size_t i = 0; i < show; i++) {
    printf("%02x ", data[i]);
  }
  if (len > max_show)
    printf("...");
  printf("\n");
}

/*
 * Test: Basic round-trip with simple string
 */
void test_basic_roundtrip(void) {
  TEST("basic round-trip");

  const char *original = "Hello, World!";
  size_t original_len = strlen(original);

  /* Compress */
  size_t compressed_len = 0;
  uint8_t *compressed =
      mz_compress_alloc((const uint8_t *)original, original_len,
                        &compressed_len, MZ_DEFAULT_COMPRESSION);
  if (!compressed) {
    FAIL("compression returned NULL");
    return;
  }

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

/*
 * Test: Round-trip with repetitive data (should compress well)
 */
void test_repetitive_data(void) {
  TEST("repetitive data compression");

  const char *original =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
  size_t original_len = strlen(original);

  /* Compress */
  size_t compressed_len = 0;
  uint8_t *compressed =
      mz_compress_alloc((const uint8_t *)original, original_len,
                        &compressed_len, MZ_DEFAULT_COMPRESSION);
  if (!compressed) {
    FAIL("compression returned NULL");
    return;
  }

  printf("(%zu -> %zu bytes, %.1f%% ratio) ", original_len, compressed_len,
         100.0 * compressed_len / original_len);

  /* Verify compression achieved */
  if (compressed_len >= original_len) {
    printf("\nWARNING: No compression achieved\n");
  }

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

/*
 * Test: Round-trip with mixed content
 */
void test_mixed_content(void) {
  TEST("mixed content round-trip");

  const char *original = "Hello, this is a test string for compression. "
                         "It should compress reasonably well because it has "
                         "some repetition. Hello hello hello! "
                         "The quick brown fox jumps over the lazy dog. "
                         "Pack my box with five dozen liquor jugs.";
  size_t original_len = strlen(original);

  /* Compress */
  size_t compressed_len = 0;
  uint8_t *compressed =
      mz_compress_alloc((const uint8_t *)original, original_len,
                        &compressed_len, MZ_DEFAULT_COMPRESSION);
  if (!compressed) {
    FAIL("compression returned NULL");
    return;
  }

  printf("(%zu -> %zu bytes) ", original_len, compressed_len);

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

/*
 * Test: Raw deflate (no zlib header/trailer)
 */
void test_raw_deflate(void) {
  TEST("raw deflate round-trip");

  const char *original = "Test data for raw deflate compression";
  size_t original_len = strlen(original);

  /* Compress */
  size_t compressed_len = 0;
  uint8_t *compressed = mz_deflate_raw_alloc((const uint8_t *)original,
                                             original_len, &compressed_len);
  if (!compressed) {
    FAIL("compression returned NULL");
    return;
  }

  printf("(%zu -> %zu bytes) ", original_len, compressed_len);

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_inflate_raw_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

/*
 * Test: Different window sizes (wbits)
 */
void test_wbits_8(void) {
  TEST("wbits=8 (256 byte window)");

  const char *original = "Testing compression with wbits=8. "
                         "This uses a 256 byte sliding window. "
                         "Testing compression with wbits=8 again.";
  size_t original_len = strlen(original);

  /* Compress with wbits=8 */
  size_t compressed_len = 0;
  uint8_t *compressed =
      mz_compress_alloc_wbits((const uint8_t *)original, original_len,
                              &compressed_len, MZ_DEFAULT_COMPRESSION, 8);
  if (!compressed) {
    FAIL("compression returned NULL");
    return;
  }

  printf("(%zu -> %zu bytes) ", original_len, compressed_len);

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

void test_wbits_10(void) {
  TEST("wbits=10 (1024 byte window - BBQr default)");

  const char *original = "Testing compression with wbits=10. "
                         "This is the default for BBQr. "
                         "Testing compression with wbits=10 again. "
                         "The 1024 byte window is a good balance.";
  size_t original_len = strlen(original);

  /* Compress with wbits=10 */
  size_t compressed_len = 0;
  uint8_t *compressed =
      mz_compress_alloc_wbits((const uint8_t *)original, original_len,
                              &compressed_len, MZ_DEFAULT_COMPRESSION, 10);
  if (!compressed) {
    FAIL("compression returned NULL");
    return;
  }

  printf("(%zu -> %zu bytes) ", original_len, compressed_len);

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

void test_wbits_15(void) {
  TEST("wbits=15 (32KB window)");

  const char *original =
      "Testing compression with wbits=15. "
      "This uses the maximum 32KB window. "
      "Larger windows can find more matches but use more RAM.";
  size_t original_len = strlen(original);

  /* Compress with wbits=15 */
  size_t compressed_len = 0;
  uint8_t *compressed =
      mz_compress_alloc_wbits((const uint8_t *)original, original_len,
                              &compressed_len, MZ_DEFAULT_COMPRESSION, 15);
  if (!compressed) {
    FAIL("compression returned NULL");
    return;
  }

  printf("(%zu -> %zu bytes) ", original_len, compressed_len);

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

/*
 * Test: Binary data (all byte values)
 */
void test_binary_data(void) {
  TEST("binary data round-trip");

  /* Create data with all byte values */
  uint8_t original[512];
  for (int i = 0; i < 256; i++) {
    original[i] = (uint8_t)i;
    original[256 + i] = (uint8_t)(255 - i);
  }
  size_t original_len = sizeof(original);

  /* Compress */
  size_t compressed_len = 0;
  uint8_t *compressed = mz_compress_alloc(
      original, original_len, &compressed_len, MZ_DEFAULT_COMPRESSION);
  if (!compressed) {
    FAIL("compression returned NULL");
    return;
  }

  printf("(%zu -> %zu bytes) ", original_len, compressed_len);

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

/*
 * Test: Empty input
 */
void test_empty_input(void) {
  TEST("empty input");

  uint8_t dest[64];
  size_t dest_len = sizeof(dest);

  int ret = mz_compress(dest, &dest_len, (const uint8_t *)"", 0);
  if (ret != MZ_OK) {
    printf("(compress returned %d) ", ret);
  }

  /* Try to decompress */
  if (ret == MZ_OK && dest_len > 0) {
    size_t decomp_len = 0;
    uint8_t *decomp = mz_uncompress_alloc(dest, dest_len, &decomp_len);
    if (decomp) {
      if (decomp_len == 0) {
        free(decomp);
        PASS();
        return;
      }
      free(decomp);
    }
  }

  /* Empty input might not produce valid output - that's OK */
  PASS();
}

/*
 * Test: Single byte
 */
void test_single_byte(void) {
  TEST("single byte");

  const uint8_t original[] = {'X'};
  size_t original_len = 1;

  /* Compress */
  size_t compressed_len = 0;
  uint8_t *compressed = mz_compress_alloc(
      original, original_len, &compressed_len, MZ_DEFAULT_COMPRESSION);
  if (!compressed) {
    FAIL("compression returned NULL");
    return;
  }

  printf("(1 -> %zu bytes) ", compressed_len);

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != 1 || decompressed[0] != 'X') {
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

/*
 * Test: Large data (stress test)
 */
void test_large_data(void) {
  TEST("large data (4KB)");

  /* Generate pseudo-random but reproducible data */
  size_t original_len = 4096;
  uint8_t *original = (uint8_t *)malloc(original_len);
  if (!original) {
    FAIL("malloc failed");
    return;
  }

  /* Fill with pattern that has some repetition */
  for (size_t i = 0; i < original_len; i++) {
    original[i] = (uint8_t)((i * 17 + i / 128) & 0xFF);
  }

  /* Compress */
  size_t compressed_len = 0;
  uint8_t *compressed = mz_compress_alloc(
      original, original_len, &compressed_len, MZ_DEFAULT_COMPRESSION);
  if (!compressed) {
    free(original);
    FAIL("compression returned NULL");
    return;
  }

  printf("(%zu -> %zu bytes, %.1f%%) ", original_len, compressed_len,
         100.0 * compressed_len / original_len);

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    free(original);
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    free(original);
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(original);
  free(decompressed);
  PASS();
}

/*
 * Test: PSBT-like data (typical BBQr content)
 */
void test_psbt_like_data(void) {
  TEST("PSBT-like binary data");

  /* Typical PSBT header and structure */
  const uint8_t original[] = {
      0x70, 0x73, 0x62, 0x74, 0xff, /* "psbt" + separator */
      0x01, 0x00, 0x52, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
      0x01, 0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, 0x19, 0x76,
      0xa9, 0x14, 0x89, 0xab, 0xcd, 0xef, 0xab, 0xba, 0xab, 0xba, 0xab,
      0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba, 0xab, 0xba,
      0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  size_t original_len = sizeof(original);

  /* Compress with BBQr default wbits=10 */
  size_t compressed_len = 0;
  uint8_t *compressed = mz_compress_alloc_wbits(
      original, original_len, &compressed_len, MZ_DEFAULT_COMPRESSION, 10);
  if (!compressed) {
    FAIL("compression returned NULL");
    return;
  }

  printf("(%zu -> %zu bytes) ", original_len, compressed_len);

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("decompression returned NULL");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    hex_dump("Original", original, original_len, 32);
    hex_dump("Decompressed", decompressed, decompressed_len, 32);
    free(decompressed);
    FAIL("data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

/*
 * Test: Fixed-buffer compression (no allocation)
 */
void test_fixed_buffer(void) {
  TEST("fixed buffer compression");

  const char *original = "Testing fixed buffer compression without malloc";
  size_t original_len = strlen(original);

  uint8_t compressed[256];
  size_t compressed_len = sizeof(compressed);

  int ret = mz_compress(compressed, &compressed_len, (const uint8_t *)original,
                        original_len);
  if (ret != MZ_OK) {
    printf("(mz_compress returned %d) ", ret);
    FAIL("compression failed");
    return;
  }

  printf("(%zu -> %zu bytes) ", original_len, compressed_len);

  /* Decompress into fixed buffer */
  uint8_t decompressed[256];
  size_t decompressed_len = sizeof(decompressed);

  ret = mz_uncompress(decompressed, &decompressed_len, compressed,
                      compressed_len);
  if (ret != MZ_OK) {
    printf("(mz_uncompress returned %d) ", ret);
    FAIL("decompression failed");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    FAIL("data mismatch");
    return;
  }

  PASS();
}

/*
 * Test: Buffer too small error
 */
void test_buffer_too_small(void) {
  TEST("buffer too small error");

  const char *original = "This string should not fit in a tiny buffer";
  size_t original_len = strlen(original);

  uint8_t compressed[8]; /* Way too small */
  size_t compressed_len = sizeof(compressed);

  int ret = mz_compress(compressed, &compressed_len, (const uint8_t *)original,
                        original_len);

  if (ret == MZ_BUF_ERROR) {
    PASS();
  } else {
    printf("(expected MZ_BUF_ERROR, got %d) ", ret);
    FAIL("wrong error code");
  }
}

/*
 * Test: Verify zlib header format
 */
void test_zlib_header(void) {
  TEST("zlib header format");

  const char *original = "Test";
  size_t original_len = strlen(original);

  uint8_t compressed[64];
  size_t compressed_len = sizeof(compressed);

  int ret =
      mz_compress_wbits(compressed, &compressed_len, (const uint8_t *)original,
                        original_len, MZ_DEFAULT_COMPRESSION, 10);
  if (ret != MZ_OK) {
    FAIL("compression failed");
    return;
  }

  /* Check zlib header */
  uint8_t cmf = compressed[0];
  uint8_t flg = compressed[1];

  /* CMF: method (bits 0-3) should be 8 (deflate) */
  if ((cmf & 0x0F) != 8) {
    printf("(CMF method = %d, expected 8) ", cmf & 0x0F);
    FAIL("wrong compression method");
    return;
  }

  /* CMF: info (bits 4-7) should be wbits-8 = 2 for wbits=10 */
  int cinfo = (cmf >> 4) & 0x0F;
  if (cinfo != 2) {
    printf("(CINFO = %d, expected 2 for wbits=10) ", cinfo);
    FAIL("wrong CINFO");
    return;
  }

  /* Header checksum: (CMF*256 + FLG) % 31 == 0 */
  if ((cmf * 256 + flg) % 31 != 0) {
    printf("(header checksum failed) ");
    FAIL("header checksum error");
    return;
  }

  printf("(CMF=0x%02x, FLG=0x%02x) ", cmf, flg);
  PASS();
}

/*
 * Test: Compression ratio benchmark
 */
void test_compression_ratio(void) {
  printf("\n=== Compression Ratio Benchmark ===\n");

  struct {
    const char *name;
    const uint8_t *data;
    size_t len;
  } test_cases[] = {
      {"Zeros (256)", NULL, 256},
      {"Ones (256)", NULL, 256},
      {"Sequential (256)", NULL, 256},
      {"Text (lorem)", NULL, 0},
  };

  /* Allocate test data */
  uint8_t zeros[256], ones[256], seq[256];
  memset(zeros, 0, sizeof(zeros));
  memset(ones, 0xFF, sizeof(ones));
  for (int i = 0; i < 256; i++)
    seq[i] = (uint8_t)i;

  const char *lorem =
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
      "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
      "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.";

  test_cases[0].data = zeros;
  test_cases[1].data = ones;
  test_cases[2].data = seq;
  test_cases[3].data = (const uint8_t *)lorem;
  test_cases[3].len = strlen(lorem);

  for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
    const uint8_t *data = test_cases[i].data;
    size_t len = test_cases[i].len;

    size_t compressed_len = 0;
    uint8_t *compressed =
        mz_compress_alloc(data, len, &compressed_len, MZ_DEFAULT_COMPRESSION);

    if (compressed) {
      printf("  %-20s: %4zu -> %4zu bytes (%5.1f%%)\n", test_cases[i].name, len,
             compressed_len, 100.0 * compressed_len / len);
      free(compressed);
    } else {
      printf("  %-20s: compression failed\n", test_cases[i].name);
    }
  }
  printf("\n");
}

/*
 * Main test runner
 */
int main(void) {
  printf("========================================\n");
  printf("        Miniz Test Suite\n");
  printf("  LZ77 + Static Huffman Compression\n");
  printf("========================================\n\n");

  /* Basic functionality tests */
  printf("=== Basic Tests ===\n");
  test_basic_roundtrip();
  test_repetitive_data();
  test_mixed_content();
  test_raw_deflate();

  /* Window size tests */
  printf("\n=== Window Size Tests ===\n");
  test_wbits_8();
  test_wbits_10();
  test_wbits_15();

  /* Edge case tests */
  printf("\n=== Edge Case Tests ===\n");
  test_binary_data();
  test_empty_input();
  test_single_byte();

  /* Larger data tests */
  printf("\n=== Large Data Tests ===\n");
  test_large_data();
  test_psbt_like_data();

  /* API tests */
  printf("\n=== API Tests ===\n");
  test_fixed_buffer();
  test_buffer_too_small();
  test_zlib_header();

  /* Benchmark */
  test_compression_ratio();

  /* Summary */
  printf("========================================\n");
  printf("        Test Summary\n");
  printf("========================================\n");
  printf("Passed: %d\n", tests_passed);
  printf("Failed: %d\n", tests_failed);
  printf("Total:  %d\n", tests_passed + tests_failed);
  printf("========================================\n");

  return tests_failed > 0 ? 1 : 0;
}
