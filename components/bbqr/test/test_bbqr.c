/*
 * BBQr Test Suite
 * Compile with: gcc -o test_bbqr test_bbqr.c ../src/base32.c ../src/miniz.c
 * ../src/bbqr.c -I../src -lz Or without system zlib: gcc -o test_bbqr
 * test_bbqr.c ../src/base32.c ../src/miniz.c ../src/bbqr.c -I../src
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base32.h"
#include "bbqr.h"
#include "bbqr_samples.h"
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

/* Test base32 encoding */
void test_base32_encode(void) {
  TEST("base32_encode basic");

  const uint8_t input[] = "Hello";
  char output[32];
  size_t len = base32_encode(input, 5, output, sizeof(output));

  if (len > 0 && strcmp(output, "JBSWY3DP") == 0) {
    PASS();
  } else {
    FAIL(output);
  }
}

/* Test base32 decoding */
void test_base32_decode(void) {
  TEST("base32_decode basic");

  const char *input = "JBSWY3DP";
  uint8_t output[32];
  size_t out_len;

  if (base32_decode(input, strlen(input), output, sizeof(output), &out_len)) {
    output[out_len] = '\0';
    if (out_len == 5 && strcmp((char *)output, "Hello") == 0) {
      PASS();
    } else {
      FAIL("Wrong decoded value");
    }
  } else {
    FAIL("Decode failed");
  }
}

/* Test base32 round-trip */
void test_base32_roundtrip(void) {
  TEST("base32 round-trip");

  const uint8_t original[] = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x80, 0x7F};
  char encoded[64];
  uint8_t decoded[64];
  size_t decoded_len;

  size_t enc_len =
      base32_encode(original, sizeof(original), encoded, sizeof(encoded));
  if (enc_len == 0) {
    FAIL("Encode failed");
    return;
  }

  if (!base32_decode(encoded, enc_len, decoded, sizeof(decoded),
                     &decoded_len)) {
    FAIL("Decode failed");
    return;
  }

  if (decoded_len == sizeof(original) &&
      memcmp(original, decoded, decoded_len) == 0) {
    PASS();
  } else {
    FAIL("Data mismatch");
  }
}

/* Test base36 encoding/decoding */
void test_base36(void) {
  TEST("base36 encode/decode");

  char c1, c2;

  /* Test 0 */
  bbqr_base36_encode(0, &c1, &c2);
  if (c1 != '0' || c2 != '0') {
    FAIL("0 encode failed");
    return;
  }
  if (bbqr_base36_decode('0', '0') != 0) {
    FAIL("0 decode failed");
    return;
  }

  /* Test 1 */
  bbqr_base36_encode(1, &c1, &c2);
  if (c1 != '0' || c2 != '1') {
    FAIL("1 encode failed");
    return;
  }
  if (bbqr_base36_decode('0', '1') != 1) {
    FAIL("1 decode failed");
    return;
  }

  /* Test 36 */
  bbqr_base36_encode(36, &c1, &c2);
  if (c1 != '1' || c2 != '0') {
    FAIL("36 encode failed");
    return;
  }
  if (bbqr_base36_decode('1', '0') != 36) {
    FAIL("36 decode failed");
    return;
  }

  /* Test 1295 (max) */
  bbqr_base36_encode(1295, &c1, &c2);
  if (c1 != 'Z' || c2 != 'Z') {
    FAIL("1295 encode failed");
    return;
  }
  if (bbqr_base36_decode('Z', 'Z') != 1295) {
    FAIL("1295 decode failed");
    return;
  }

  PASS();
}

/* Test BBQr header parsing */
void test_bbqr_parse_header(void) {
  TEST("bbqr_parse_part header");

  const char *qr = "B$ZP0100TESTPAYLOAD";
  BBQrPart part;

  if (!bbqr_parse_part(qr, strlen(qr), &part)) {
    FAIL("Parse failed");
    return;
  }

  if (part.encoding != 'Z') {
    FAIL("Wrong encoding");
    return;
  }
  if (part.file_type != 'P') {
    FAIL("Wrong file type");
    return;
  }
  if (part.total != 1) {
    FAIL("Wrong total");
    return;
  }
  if (part.index != 0) {
    FAIL("Wrong index");
    return;
  }
  if (part.payload_len != 11 || strncmp(part.payload, "TESTPAYLOAD", 11) != 0) {
    FAIL("Wrong payload");
    return;
  }

  PASS();
}

/* Test miniz compression/decompression round-trip */
void test_miniz_roundtrip(void) {
  TEST("miniz compress/decompress round-trip");

  const char *original = "Hello, this is a test string for compression. "
                         "It should compress reasonably well because it has "
                         "some repetition. Hello hello hello!";
  size_t original_len = strlen(original);

  /* Compress */
  size_t compressed_len = 0;
  uint8_t *compressed =
      mz_compress_alloc((const uint8_t *)original, original_len,
                        &compressed_len, MZ_DEFAULT_COMPRESSION);
  if (!compressed) {
    FAIL("Compression failed");
    return;
  }

  printf("(compressed %zu -> %zu bytes) ", original_len, compressed_len);

  /* Decompress */
  size_t decompressed_len = 0;
  uint8_t *decompressed =
      mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
  free(compressed);

  if (!decompressed) {
    FAIL("Decompression failed");
    return;
  }

  if (decompressed_len != original_len ||
      memcmp(original, decompressed, original_len) != 0) {
    free(decompressed);
    FAIL("Data mismatch");
    return;
  }

  free(decompressed);
  PASS();
}

/* Test BBQr encode/decode round-trip */
void test_bbqr_roundtrip(void) {
  TEST("bbqr encode/decode round-trip");

  /* Sample PSBT-like data */
  const uint8_t original[] = {0x70, 0x73, 0x62, 0x74, 0xff, /* "psbt" + 0xff */
                              0x01, 0x00, 0x52, 0x02, 0x00, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  size_t original_len = sizeof(original);

  BBQrParts *parts = bbqr_encode(original, original_len, BBQR_TYPE_PSBT, 400);
  if (!parts) {
    FAIL("Encode failed");
    return;
  }

  BBQrPart parsed;
  if (!bbqr_parse_part(parts->parts[0], strlen(parts->parts[0]), &parsed)) {
    bbqr_parts_free(parts);
    FAIL("Parse failed");
    return;
  }

  size_t decoded_len = 0;
  uint8_t *decoded = bbqr_decode_payload(parsed.encoding, parsed.payload,
                                         parsed.payload_len, &decoded_len);
  bbqr_parts_free(parts);

  if (!decoded) {
    FAIL("Decode failed");
    return;
  }

  if (decoded_len != original_len ||
      memcmp(original, decoded, original_len) != 0) {
    free(decoded);
    FAIL("Data mismatch");
    return;
  }

  free(decoded);
  PASS();
}

/* Expected PSBT data (base64 decoded) for test_real_bbqr_decode */
static const uint8_t EXPECTED_PSBT[] = {
    0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00, 0xf6, 0x02, 0x00, 0x00, 0x00,
    0x05, 0x53, 0xa2, 0x60, 0x3a, 0x61, 0x5c, 0x98, 0x8d, 0xcb, 0xb6, 0x3a,
    0x9e, 0xd1, 0x92, 0x87, 0xf0, 0xa6, 0x41, 0xec, 0x91, 0xff, 0xd3, 0x37,
    0xdb, 0xcb, 0x2a, 0x44, 0x52, 0x4f, 0x45, 0xe5, 0xfb, 0x07, 0x00, 0x00,
    0x00, 0x00, 0xfd, 0xff, 0xff, 0xff, 0x53, 0xa2, 0x60, 0x3a, 0x61, 0x5c,
    0x98, 0x8d, 0xcb, 0xb6, 0x3a, 0x9e, 0xd1, 0x92, 0x87, 0xf0, 0xa6, 0x41,
    0xec, 0x91, 0xff, 0xd3, 0x37, 0xdb, 0xcb, 0x2a, 0x44, 0x52, 0x4f, 0x45,
    0xe5, 0xfb, 0x0a, 0x00, 0x00, 0x00, 0x00, 0xfd, 0xff, 0xff, 0xff, 0x53,
    0xa2, 0x60, 0x3a, 0x61, 0x5c, 0x98, 0x8d, 0xcb, 0xb6, 0x3a, 0x9e, 0xd1,
    0x92, 0x87, 0xf0, 0xa6, 0x41, 0xec, 0x91, 0xff, 0xd3, 0x37, 0xdb, 0xcb,
    0x2a, 0x44, 0x52, 0x4f, 0x45, 0xe5, 0xfb, 0x08, 0x00, 0x00, 0x00, 0x00,
    0xfd, 0xff, 0xff, 0xff, 0x53, 0xa2, 0x60, 0x3a, 0x61, 0x5c, 0x98, 0x8d,
    0xcb, 0xb6, 0x3a, 0x9e, 0xd1, 0x92, 0x87, 0xf0, 0xa6, 0x41, 0xec, 0x91,
    0xff, 0xd3, 0x37, 0xdb, 0xcb, 0x2a, 0x44, 0x52, 0x4f, 0x45, 0xe5, 0xfb,
    0x09, 0x00, 0x00, 0x00, 0x00, 0xfd, 0xff, 0xff, 0xff, 0x53, 0xa2, 0x60,
    0x3a, 0x61, 0x5c, 0x98, 0x8d, 0xcb, 0xb6, 0x3a, 0x9e, 0xd1, 0x92, 0x87,
    0xf0, 0xa6, 0x41, 0xec, 0x91, 0xff, 0xd3, 0x37, 0xdb, 0xcb, 0x2a, 0x44,
    0x52, 0x4f, 0x45, 0xe5, 0xfb, 0x06, 0x00, 0x00, 0x00, 0x00, 0xfd, 0xff,
    0xff, 0xff, 0x01, 0x2b, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16,
    0x00, 0x14, 0xb1, 0x50, 0x25, 0xed, 0xdb, 0x38, 0x87, 0x5e, 0xc7, 0x68,
    0x8d, 0x5d, 0x36, 0x73, 0x72, 0x43, 0x81, 0x29, 0x67, 0x71, 0xfc, 0x74,
    0x49, 0x00, 0x4f, 0x01, 0x04, 0x35, 0x87, 0xcf, 0x03, 0x62, 0xed, 0x72,
    0xaa, 0x80, 0x00, 0x00, 0x00, 0x59, 0x91, 0x97, 0x77, 0xe3, 0x99, 0xc6,
    0x2f, 0xdc, 0x4b, 0x30, 0x0f, 0x44, 0x66, 0x64, 0x6f, 0x1a, 0xe8, 0x6f,
    0x99, 0x95, 0x85, 0x72, 0x9e, 0x4c, 0xcc, 0x91, 0x65, 0x5e, 0x17, 0x8d,
    0x36, 0x03, 0xbc, 0x14, 0xe6, 0xbd, 0x60, 0xb7, 0x6a, 0xd5, 0x45, 0x09,
    0xde, 0xa7, 0x4c, 0xbd, 0xa6, 0x0d, 0x1f, 0xc2, 0x5a, 0x65, 0x7d, 0x25,
    0x8e, 0xaa, 0x8c, 0x40, 0xd6, 0x5c, 0x98, 0x7b, 0x79, 0x53, 0x10, 0xd6,
    0x3d, 0xc4, 0xa7, 0x54, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x80, 0x00,
    0x00, 0x00, 0x80, 0x00, 0x01, 0x01, 0x1f, 0x88, 0x13, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0xd0, 0x92, 0x28, 0x51, 0x7d, 0x5e,
    0x9c, 0xe3, 0xba, 0x2a, 0x05, 0xfb, 0x29, 0x11, 0xa6, 0xa2, 0x16, 0xb7,
    0x0a, 0x47, 0x01, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00, 0x22, 0x06, 0x03,
    0xa5, 0x28, 0x5c, 0x64, 0x5f, 0xe6, 0x59, 0xcc, 0xa1, 0xd1, 0xc2, 0x3a,
    0x58, 0x1b, 0xc4, 0x0e, 0x38, 0xe6, 0x42, 0x71, 0xcd, 0x65, 0x58, 0x08,
    0xf6, 0x68, 0x41, 0xbe, 0xc1, 0xad, 0x1e, 0x2f, 0x18, 0xd6, 0x3d, 0xc4,
    0xa7, 0x54, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
    0x1f, 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14,
    0xca, 0x0e, 0x73, 0xa1, 0x27, 0x89, 0xa0, 0x59, 0xfe, 0x9a, 0x51, 0x57,
    0xf7, 0x3f, 0xd0, 0x41, 0xa6, 0xdc, 0xe4, 0x2d, 0x01, 0x03, 0x04, 0x01,
    0x00, 0x00, 0x00, 0x22, 0x06, 0x03, 0x64, 0xe0, 0x94, 0xf7, 0xda, 0x39,
    0xbb, 0xed, 0x46, 0x21, 0xf3, 0xf6, 0x8d, 0x62, 0xee, 0x70, 0x7e, 0x78,
    0xdb, 0xf4, 0x6c, 0xd5, 0xe0, 0xe4, 0xe1, 0x63, 0x91, 0xbc, 0x36, 0x55,
    0x2d, 0x28, 0x18, 0xd6, 0x3d, 0xc4, 0xa7, 0x54, 0x00, 0x00, 0x80, 0x01,
    0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x3e,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x1f, 0x88, 0x13, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x8e, 0xc6, 0xa2, 0xb8, 0xac, 0xd1,
    0xc8, 0x72, 0xeb, 0x1b, 0x53, 0xff, 0x26, 0x6b, 0x93, 0xb9, 0x6c, 0x9d,
    0xe4, 0x4b, 0x01, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00, 0x22, 0x06, 0x02,
    0xe7, 0x85, 0x7e, 0x8f, 0x67, 0x3d, 0xd3, 0x3b, 0x77, 0x59, 0x32, 0x23,
    0xd4, 0x17, 0x1a, 0xbf, 0x3f, 0x7d, 0x4e, 0xf5, 0x73, 0x44, 0xaa, 0xa3,
    0x3c, 0xbe, 0x98, 0xbc, 0x90, 0x09, 0x20, 0xd7, 0x18, 0xd6, 0x3d, 0xc4,
    0xa7, 0x54, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
    0x1f, 0x88, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14,
    0x43, 0xc7, 0xb5, 0x80, 0xb1, 0x1c, 0x8c, 0xcd, 0x59, 0x80, 0x62, 0x3b,
    0x20, 0xeb, 0x6c, 0x4e, 0xa3, 0xf3, 0xdc, 0xbe, 0x01, 0x03, 0x04, 0x01,
    0x00, 0x00, 0x00, 0x22, 0x06, 0x03, 0x59, 0x79, 0x72, 0x2f, 0xf1, 0x32,
    0x10, 0x76, 0xbd, 0x2c, 0x47, 0x3e, 0xd4, 0x39, 0x5c, 0xcc, 0xe1, 0x3f,
    0x5d, 0xd0, 0x4a, 0x5b, 0x8a, 0xfb, 0x02, 0x8b, 0x03, 0xc7, 0x85, 0x4b,
    0xa9, 0x46, 0x18, 0xd6, 0x3d, 0xc4, 0xa7, 0x54, 0x00, 0x00, 0x80, 0x01,
    0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x3d,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x1f, 0x88, 0x13, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0xee, 0x5c, 0x29, 0x61, 0x5e, 0xca,
    0xef, 0x34, 0x11, 0x34, 0xa5, 0xc0, 0x55, 0x3d, 0x45, 0x1c, 0x2a, 0x38,
    0x46, 0x85, 0x01, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00, 0x22, 0x06, 0x02,
    0xd0, 0x28, 0x6b, 0x66, 0x5b, 0x7e, 0x14, 0x39, 0xf2, 0xd0, 0x93, 0x89,
    0x37, 0x3f, 0x5e, 0x45, 0x55, 0x96, 0x5f, 0x5f, 0x86, 0x87, 0x95, 0x8b,
    0x6e, 0x6d, 0x3e, 0x34, 0xe8, 0x52, 0xb3, 0xd8, 0x18, 0xd6, 0x3d, 0xc4,
    0xa7, 0x54, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 0x22, 0x02,
    0x02, 0xa1, 0xe7, 0xa6, 0xfc, 0xee, 0x1e, 0x1b, 0x3a, 0x01, 0x40, 0x8a,
    0x3b, 0x06, 0x70, 0x2f, 0xb6, 0xe1, 0xaa, 0x39, 0xec, 0x90, 0x6a, 0xb3,
    0xef, 0x1b, 0xc5, 0xc1, 0x36, 0xd7, 0x9a, 0x96, 0x7e, 0x18, 0xd6, 0x3d,
    0xc4, 0xa7, 0x54, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x80, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0xcb, 0x00, 0x00, 0x00, 0x00};

/* Test decoding a real BBQr PSBT QR code */
void test_real_bbqr_decode(void) {
  TEST("decode real BBQr QR code");

  const char *qr =
      "B$"
      "ZP0100FMUE4KXZZ7EPBDMJQGAYCNLYKGBFKYWMRTPNHW5M4ZOZZVH6MGM6HG4J74XZXXZ6VX"
      "SRFZHP7L2DOO2QCHB5777774JVFSCFVRBA4YQVOIJKXEANU2IFCO4BAEGMIGCEGYDKRPV5NX"
      "IR45Z4UM35NLFYZC4VCM556BHYSJ4DH4RYW2P3PHTKJN2FVMNIAKRDE5HC67Z46OMP4HLPAN"
      "7JPNEUPSURP6JTU63BNTPTHEZTCNKOXTLYY6MPZCZ32CO3WOXLU4W6LPXLG5YZV76KDKGULL"
      "K34VJ5B3LWEZSUK4DAWXFTHWZDZBEBUGARDCAZICMJCUN6IMMO5DQLSM2AE27D4Y6N5JOF7J"
      "NVG4GZEKY62XHORTGCYQGVBRFGZTCLGVRFFYU7IWPFS6HRSBKYJ5ARH2FWOTUFM5JSGOF6MU"
      "4O4O5YKZHF6AWDOQQLABQRVC3JZYRLL2UN5OJA6LP2ZQHQ573BOHEX3V42FC5QEXS4DFHPW4"
      "WHPP3VKP6PZLJX5FOUCXOF5UXTSVY7HR4ZQPDRR5M2RLQGKZN6YMDN5E53M2GHTKFSPCS6JM"
      "D76V6LT26DGZ7OCNX3QLKMZ5N6X6WTNUXVXF2HDIUV6EMX3JXV727XWXMGLVLCTN6TH5SM4B"
      "KLRDWVCYNUYW44R5XW3WBI2NZTNMRBZFNOC5MO37RM657WEH6BEWKZUT75CSFANSXY5O65CX"
      "FZQMYP5VRS66CFO76WN2TGH3POVPOSBWVS3NUYW26IXUKMRQ57LXSE2BSOTAKQLNLRSLILW5"
      "LIIXZONBSKOROXRFMH5ORQXHJ5YPWOGV2FU7D4LP55J3V4LQ5ZGF2BTNXWBNOFBJCCQMJRFV"
      "6L53GPHM4WSK2GQ4XGXNQC7VWQ6V2ZX2MZBNPZXX2NDA3G25TU3K6DVL4TJCAAAA";

  BBQrPart part;
  if (!bbqr_parse_part(qr, strlen(qr), &part)) {
    FAIL("Header parse failed");
    return;
  }

  size_t decoded_len = 0;
  uint8_t *decoded = bbqr_decode_payload(part.encoding, part.payload,
                                         part.payload_len, &decoded_len);
  if (!decoded) {
    FAIL("Decode failed");
    return;
  }

  /* Verify PSBT magic and data */
  if (decoded_len < 5 || memcmp(decoded, "psbt\xff", 5) != 0) {
    free(decoded);
    FAIL("Invalid PSBT magic");
    return;
  }

  if (decoded_len != sizeof(EXPECTED_PSBT) ||
      memcmp(decoded, EXPECTED_PSBT, sizeof(EXPECTED_PSBT)) != 0) {
    free(decoded);
    FAIL("Data mismatch");
    return;
  }

  free(decoded);
  PASS();
}

/**
 * @brief Helper to verify BBQr decoding against test vectors
 */
void verify_bbqr_decode(const char *test_name, const char **parts, int count,
                        const uint8_t *expected, size_t expected_len) {
  printf("Testing vector: %s... ", test_name);

  char *assembled_payload = NULL;
  size_t assembled_len = 0;
  char encoding = 0;
  char file_type = 0;

  // Verify and assemble parts
  for (int i = 0; i < count; i++) {
    BBQrPart part;
    if (!bbqr_parse_part(parts[i], strlen(parts[i]), &part)) {
      free(assembled_payload);
      FAIL("Parse failed for part");
      return;
    }

    if (i == 0) {
      encoding = part.encoding;
      file_type = part.file_type;
      if (part.total != count) {
        free(assembled_payload);
        FAIL("Wrong total count in header");
        return;
      }
    } else {
      if (part.encoding != encoding || part.file_type != file_type) {
        free(assembled_payload);
        FAIL("Inconsistent header info");
        return;
      }
    }

    // Ensure parts are provided in order for this simple test harness
    if (part.index != i) {
      free(assembled_payload);
      FAIL("Parts out of order");
      return;
    }

    // Append payload
    char *new_payload =
        realloc(assembled_payload, assembled_len + part.payload_len);
    if (!new_payload) {
      free(assembled_payload);
      FAIL("Memory allocation");
      return;
    }
    assembled_payload = new_payload;
    memcpy(assembled_payload + assembled_len, part.payload, part.payload_len);
    assembled_len += part.payload_len;
  }

  size_t decoded_len = 0;
  uint8_t *decoded = bbqr_decode_payload(encoding, assembled_payload,
                                         assembled_len, &decoded_len);
  free(assembled_payload);

  if (!decoded) {
    FAIL("Decode failed");
    return;
  }

  if (decoded_len != expected_len) {
    printf("Expected len %zu, got %zu. ", expected_len, decoded_len);
    if (decoded_len > expected_len) {
      printf("Extra bytes at end: ");
      for (size_t i = expected_len; i < decoded_len; i++)
        printf("%02x ", decoded[i]);
      printf("\n");
    }
    free(decoded);
    FAIL("Length mismatch");
    return;
  }

  if (memcmp(decoded, expected, expected_len) != 0) {
    free(decoded);
    FAIL("Data mismatch");
    return;
  }

  free(decoded);
  PASS();
}

void test_vectors(void) {
  printf("Running Test Vectors...\n");

  // Descriptors
  verify_bbqr_decode("Nunchuk Single", bbqr_desc_nunchuk_single_parts,
                     BBQR_ARRAY_LEN(bbqr_desc_nunchuk_single_parts),
                     (const uint8_t *)bbqr_desc_nunchuk_single_expected,
                     strlen(bbqr_desc_nunchuk_single_expected));

  verify_bbqr_decode("Nunchuk Multi", bbqr_desc_nunchuk_multi_parts,
                     BBQR_ARRAY_LEN(bbqr_desc_nunchuk_multi_parts),
                     (const uint8_t *)bbqr_desc_nunchuk_multi_expected,
                     strlen(bbqr_desc_nunchuk_multi_expected));

  verify_bbqr_decode("Sparrow Single", bbqr_desc_sparrow_single_parts,
                     BBQR_ARRAY_LEN(bbqr_desc_sparrow_single_parts),
                     (const uint8_t *)bbqr_desc_sparrow_single_expected,
                     strlen(bbqr_desc_sparrow_single_expected));

  verify_bbqr_decode("Sparrow Multi", bbqr_desc_sparrow_multi_parts,
                     BBQR_ARRAY_LEN(bbqr_desc_sparrow_multi_parts),
                     (const uint8_t *)bbqr_desc_sparrow_multi_expected,
                     strlen(bbqr_desc_sparrow_multi_expected));

  // JSON
  verify_bbqr_decode("Coldcard JSON", bbqr_json_coldcard_parts,
                     BBQR_ARRAY_LEN(bbqr_json_coldcard_parts),
                     bbqr_json_coldcard_expected,
                     bbqr_json_coldcard_expected_len);

  // PSBTs (Zlib)
  verify_bbqr_decode("Nunchuk PSBT", bbqr_nunchuk_psbt_parts,
                     BBQR_ARRAY_LEN(bbqr_nunchuk_psbt_parts),
                     bbqr_nunchuk_psbt_bytes, bbqr_nunchuk_psbt_bytes_len);

  verify_bbqr_decode("Sparrow PSBT", bbqr_sparrow_psbt_parts,
                     BBQR_ARRAY_LEN(bbqr_sparrow_psbt_parts),
                     bbqr_sparrow_psbt_bytes, bbqr_sparrow_psbt_bytes_len);

  // PSBTs (Base32 - No Compression)
  verify_bbqr_decode("Nunchuk PSBT (NC)", bbqr_nunchuk_psbt_nc_parts,
                     BBQR_ARRAY_LEN(bbqr_nunchuk_psbt_nc_parts),
                     bbqr_nunchuk_psbt_bytes, bbqr_nunchuk_psbt_bytes_len);

  verify_bbqr_decode("Sparrow PSBT (NC)", bbqr_sparrow_psbt_nc_parts,
                     BBQR_ARRAY_LEN(bbqr_sparrow_psbt_nc_parts),
                     bbqr_sparrow_psbt_bytes, bbqr_sparrow_psbt_bytes_len);

  // Signed PSBT Hex
  verify_bbqr_decode("Signed PSBT (Hex)", bbqr_signed_psbt_hex_parts,
                     BBQR_ARRAY_LEN(bbqr_signed_psbt_hex_parts),
                     bbqr_signed_psbt_bytes, bbqr_signed_psbt_bytes_len);
}

int main(void) {
  printf("BBQr Test Suite\n");
  printf("================\n\n");

  test_base32_encode();
  test_base32_decode();
  test_base32_roundtrip();
  test_base36();
  test_bbqr_parse_header();
  test_miniz_roundtrip();
  test_bbqr_roundtrip();
  test_real_bbqr_decode();
  test_vectors();

  printf("\n================\n");
  printf("Results: %d passed, %d failed\n", tests_passed, tests_failed);

  return tests_failed > 0 ? 1 : 0;
}
