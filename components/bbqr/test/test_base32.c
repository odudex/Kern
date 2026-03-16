/*
 * Base32 Test Suite
 * Compile with: gcc -o test_base32 test_base32.c ../src/base32.c -I../src
 * Run: ./test_base32
 */

#include "base32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Test vectors */
typedef struct {
  const uint8_t *bytes;
  size_t bytes_len;
  const char *encoded;        /* without padding */
  const char *encoded_padded; /* with padding */
} base32_test_vector_t;

/* PSBT test vector (long binary data) - 349 bytes */
static const uint8_t TEST_BYTES_0[] = {
    0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00, 0x7b, 0x02, 0x00, 0x00, 0x00,
    0x02, 0xd2, 0x68, 0x80, 0x76, 0xf6, 0x3c, 0x08, 0xa0, 0x6b, 0x16, 0xce,
    0x9f, 0xd9, 0x0a, 0x31, 0xbf, 0x46, 0x06, 0x81, 0x01, 0x0c, 0xae, 0x5d,
    0x0b, 0x11, 0x8a, 0xb5, 0xdf, 0x5a, 0xa6, 0xd3, 0xcf, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xfd, 0xff, 0xff, 0xff, 0x58, 0xb8, 0x91, 0x7f, 0xcb, 0x16,
    0x36, 0xae, 0xcf, 0x9b, 0xa4, 0xec, 0x8f, 0x1d, 0x20, 0xc9, 0xcf, 0x62,
    0x82, 0x7d, 0x16, 0x1d, 0xc0, 0xd7, 0x73, 0x62, 0xaf, 0x02, 0x7f, 0xcf,
    0xa7, 0x7d, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0xff, 0xff, 0xff, 0x01,
    0xe8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0xae,
    0xcd, 0x1e, 0xdc, 0x3e, 0xff, 0x65, 0xaa, 0x20, 0x9d, 0x02, 0x15, 0xe7,
    0x3d, 0x70, 0x90, 0x5d, 0xc1, 0x68, 0x6c, 0xb0, 0xfe, 0x2a, 0x00, 0x00,
    0x22, 0x02, 0x02, 0xd7, 0xb1, 0x50, 0x49, 0x10, 0xbb, 0x71, 0x27, 0x14,
    0x4a, 0x73, 0x09, 0xde, 0xee, 0xde, 0x32, 0xe8, 0x8a, 0x06, 0x57, 0x0d,
    0x96, 0xdb, 0x68, 0x31, 0x9e, 0xb7, 0x56, 0x05, 0xd5, 0x44, 0x12, 0x47,
    0x30, 0x44, 0x02, 0x20, 0x07, 0x8b, 0x9f, 0xe8, 0x79, 0xec, 0x5f, 0x35,
    0x12, 0x7c, 0xbf, 0x3b, 0xb5, 0x26, 0x32, 0x64, 0x07, 0x3d, 0x78, 0x9f,
    0xa2, 0xc8, 0x9b, 0x08, 0x9f, 0x12, 0xf1, 0xfe, 0x50, 0xea, 0xef, 0x56,
    0x02, 0x20, 0x1a, 0xf3, 0xcc, 0x2a, 0x97, 0x0e, 0x00, 0x9c, 0xcf, 0xa9,
    0x83, 0xd1, 0xe4, 0x70, 0x68, 0x98, 0x9e, 0x8c, 0x4d, 0x4c, 0x3e, 0x03,
    0xc4, 0x04, 0xb0, 0x36, 0xa1, 0x2b, 0xab, 0x1c, 0x73, 0x9c, 0x01, 0x00,
    0x22, 0x02, 0x03, 0xc4, 0xc8, 0x06, 0xd0, 0xc1, 0x19, 0xb3, 0x35, 0xe3,
    0x9b, 0x14, 0x4b, 0xc4, 0xba, 0xb1, 0xa5, 0x10, 0x06, 0xcf, 0x3d, 0x97,
    0x5d, 0xbe, 0x74, 0x07, 0xe3, 0x1e, 0xe7, 0x59, 0x39, 0xe9, 0xe0, 0x47,
    0x30, 0x44, 0x02, 0x20, 0x12, 0xeb, 0x0a, 0xf4, 0x95, 0x3e, 0x33, 0xbd,
    0x47, 0x07, 0xd5, 0x23, 0xf0, 0x7a, 0x1d, 0xda, 0x4e, 0xcf, 0x30, 0xea,
    0x15, 0x37, 0x8c, 0xf5, 0x6c, 0xb1, 0x3a, 0x85, 0x23, 0x14, 0xd3, 0x31,
    0x02, 0x20, 0x78, 0x8a, 0x56, 0x3b, 0xf1, 0x7a, 0x17, 0x85, 0x80, 0xab,
    0xc5, 0xae, 0x3b, 0x96, 0x5f, 0x5c, 0xfc, 0x02, 0xc3, 0xff, 0xd7, 0x4e,
    0xf8, 0x56, 0x26, 0x43, 0xe0, 0xcc, 0x3c, 0x9e, 0xdb, 0xe0, 0x01, 0x00,
    0x00};

/* "Hello World" */
static const uint8_t TEST_BYTES_1[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
                                       0x57, 0x6f, 0x72, 0x6c, 0x64};

/* "Hello World." */
static const uint8_t TEST_BYTES_2[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
                                       0x57, 0x6f, 0x72, 0x6c, 0x64, 0x2e};

/* "1234567890" */
static const uint8_t TEST_BYTES_3[] = {0x31, 0x32, 0x33, 0x34, 0x35,
                                       0x36, 0x37, 0x38, 0x39, 0x30};

/* Single byte: 0x00 */
static const uint8_t TEST_BYTES_4[] = {0x00};

/* Single byte: 'f' */
static const uint8_t TEST_BYTES_5[] = {0x66};

/* Sequence of bytes: 0x01, 0x02, 0x03, 0x04 */
static const uint8_t TEST_BYTES_6[] = {0x01, 0x02, 0x03, 0x04};

/* Mixed bytes: 0x00, 0xff, 0xfe, 0xfd, 0xfc, 0xfb */
static const uint8_t TEST_BYTES_7[] = {0x00, 0xff, 0xfe, 0xfd, 0xfc, 0xfb};

/* All zeros: 10 bytes */
static const uint8_t TEST_BYTES_8[] = {0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00};

/* All ones: 10 bytes of 0xff */
static const uint8_t TEST_BYTES_9[] = {0xff, 0xff, 0xff, 0xff, 0xff,
                                       0xff, 0xff, 0xff, 0xff, 0xff};

/* "Hello, World!" */
static const uint8_t TEST_BYTES_10[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f,
                                        0x2c, 0x20, 0x57, 0x6f, 0x72,
                                        0x6c, 0x64, 0x21};

/* Full range of first 16 bytes */
static const uint8_t TEST_BYTES_11[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                        0x0c, 0x0d, 0x0e, 0x0f};

/* "The quick brown fox jumps over the lazy dog" */
static const uint8_t TEST_BYTES_12[] = {
    0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62,
    0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75,
    0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68,
    0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67};

/* Random hex sequence: 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 */
static const uint8_t TEST_BYTES_13[] = {0x12, 0x34, 0x56, 0x78,
                                        0x9a, 0xbc, 0xde, 0xf0};

/* Random binary */
static const uint8_t TEST_BYTES_14[] = {0x93, 0x83, 0xc1, 0x28, 0xd9, 0x8a,
                                        0xea, 0xf4, 0xfa, 0xb1, 0xc8, 0xe0,
                                        0x1c, 0xf7, 0xbf, 0x29};

/* All test vectors */
static const base32_test_vector_t test_vectors[] = {
    {TEST_BYTES_0, sizeof(TEST_BYTES_0),
     "OBZWE5H7AEAHWAQAAAAAFUTIQB3PMPAIUBVRNTU73EFDDP2GA2AQCDFOLUFRDCVV35NKNU6"
     "PAAAAAAAA7X77772YXCIX7SYWG2XM7G5E5SHR2IGJZ5RIE7IWDXANO43CV4BH7T5HPUAAA"
     "AAAAD677777AHUAGAAAAAAAAAAWAAKK5TI63Q7P6ZNKECOQEFPHHVYJAXOBNBWLB7RKAAA"
     "CEAQC26YVASIQXNYSOFCKOME553W6GLUIUBSXBWLNW2BRT23VMBOVIQJEOMCEAIQAPC475"
     "B46YXZVCJ6L6O5VEYZGIBZ5PCP2FSE3BCPRF4P6KDVO6VQCEANPHTBKS4HABHGPVGB5DZD"
     "QNCMJ5DCNJQ7AHRAEWA3KCK5LDRZZYAIAEIBAHRGIA3IMCGNTGXRZWFCLYS5LDJIQA3HT3"
     "F25XZ2APYY645MTT2PAI4YEIARACLVQV5EVHYZ32RYH2UR7A6Q53JHM6MHKCU3YZ5LMWE5"
     "IKIYU2MYQEIDYRJLDX4L2C6CYBK6FVY5ZMX247QBMH76XJ34FMJSD4DGDZHW34AAQAAA",
     "OBZWE5H7AEAHWAQAAAAAFUTIQB3PMPAIUBVRNTU73EFDDP2GA2AQCDFOLUFRDCVV35NKNU"
     "6PAAAAAAAA7X77772YXCIX7SYWG2XM7G5E5SHR2IGJZ5RIE7IWDXANO43CV4BH7T5HPUAA"
     "AAAAAD677777AHUAGAAAAAAAAAAWAAKK5TI63Q7P6ZNKECOQEFPHHVYJAXOBNBWLB7RKAA"
     "ACEAQC26YVASIQXNYSOFCKOME553W6GLUIUBSXBWLNW2BRT23VMBOVIQJEOMCEAIQAPC47"
     "5B46YXZVCJ6L6O5VEYZGIBZ5PCP2FSE3BCPRF4P6KDVO6VQCEANPHTBKS4HABHGPVGB5DZ"
     "DQNCMJ5DCNJQ7AHRAEWA3KCK5LDRZZYAIAEIBAHRGIA3IMCGNTGXRZWFCLYS5LDJIQA3HT"
     "3F25XZ2APYY645MTT2PAI4YEIARACLVQV5EVHYZ32RYH2UR7A6Q53JHM6MHKCU3YZ5LMWE"
     "5IKIYU2MYQEIDYRJLDX4L2C6CYBK6FVY5ZMX247QBMH76XJ34FMJSD4DGDZHW34AAQAAA="},
    {TEST_BYTES_1, sizeof(TEST_BYTES_1), "JBSWY3DPEBLW64TMMQ",
     "JBSWY3DPEBLW64TMMQ======"},
    {TEST_BYTES_2, sizeof(TEST_BYTES_2), "JBSWY3DPEBLW64TMMQXA",
     "JBSWY3DPEBLW64TMMQXA===="},
    {TEST_BYTES_3, sizeof(TEST_BYTES_3), "GEZDGNBVGY3TQOJQ",
     "GEZDGNBVGY3TQOJQ"},
    {TEST_BYTES_4, sizeof(TEST_BYTES_4), "AA", "AA======"},
    {TEST_BYTES_5, sizeof(TEST_BYTES_5), "MY", "MY======"},
    {TEST_BYTES_6, sizeof(TEST_BYTES_6), "AEBAGBA", "AEBAGBA="},
    {TEST_BYTES_7, sizeof(TEST_BYTES_7), "AD7757P47M", "AD7757P47M======"},
    {TEST_BYTES_8, sizeof(TEST_BYTES_8), "AAAAAAAAAAAAAAAA",
     "AAAAAAAAAAAAAAAA"},
    {TEST_BYTES_9, sizeof(TEST_BYTES_9), "7777777777777777",
     "7777777777777777"},
    {TEST_BYTES_10, sizeof(TEST_BYTES_10), "JBSWY3DPFQQFO33SNRSCC",
     "JBSWY3DPFQQFO33SNRSCC==="},
    {TEST_BYTES_11, sizeof(TEST_BYTES_11), "AAAQEAYEAUDAOCAJBIFQYDIOB4",
     "AAAQEAYEAUDAOCAJBIFQYDIOB4======"},
    {TEST_BYTES_12, sizeof(TEST_BYTES_12),
     "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWO",
     "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWO=="
     "="},
    {TEST_BYTES_13, sizeof(TEST_BYTES_13), "CI2FM6E2XTPPA", "CI2FM6E2XTPPA==="},
    {TEST_BYTES_14, sizeof(TEST_BYTES_14), "SOB4CKGZRLVPJ6VRZDQBZ557FE",
     "SOB4CKGZRLVPJ6VRZDQBZ557FE======"},
};

#define NUM_TEST_VECTORS (sizeof(test_vectors) / sizeof(test_vectors[0]))

/* Helper to strip padding from encoded string */
static void strip_padding(const char *input, char *output, size_t output_size) {
  size_t len = strlen(input);
  while (len > 0 && input[len - 1] == '=') {
    len--;
  }
  if (len >= output_size) {
    len = output_size - 1;
  }
  memcpy(output, input, len);
  output[len] = '\0';
}

/* Test encoding with all test vectors */
void test_base32_encode_vectors(void) {
  char output[1024];
  char stripped[1024];

  printf("\n=== Base32 Encoding Tests ===\n");

  for (size_t i = 0; i < NUM_TEST_VECTORS; i++) {
    const base32_test_vector_t *tv = &test_vectors[i];
    char test_name[64];
    snprintf(test_name, sizeof(test_name), "base32_encode vector %zu", i);
    TEST(test_name);

    size_t len =
        base32_encode(tv->bytes, tv->bytes_len, output, sizeof(output));

    if (len == 0) {
      FAIL("encode returned 0");
      continue;
    }

    /* Strip padding from output to compare with expected (without padding) */
    strip_padding(output, stripped, sizeof(stripped));

    if (strcmp(stripped, tv->encoded) == 0) {
      PASS();
    } else {
      printf("\n  Expected: %s\n", tv->encoded);
      printf("  Got:      %s\n", stripped);
      FAIL("encoding mismatch");
    }
  }
}

/* Test encoding produces correct padded output */
void test_base32_encode_padded(void) {
  char output[1024];

  printf("\n=== Base32 Padded Encoding Tests ===\n");

  for (size_t i = 0; i < NUM_TEST_VECTORS; i++) {
    const base32_test_vector_t *tv = &test_vectors[i];
    char test_name[64];
    snprintf(test_name, sizeof(test_name), "base32_encode_padded vector %zu",
             i);
    TEST(test_name);

    size_t len =
        base32_encode(tv->bytes, tv->bytes_len, output, sizeof(output));

    if (len == 0) {
      FAIL("encode returned 0");
      continue;
    }

    if (strcmp(output, tv->encoded_padded) == 0) {
      PASS();
    } else {
      printf("\n  Expected: %s\n", tv->encoded_padded);
      printf("  Got:      %s\n", output);
      FAIL("padded encoding mismatch");
    }
  }
}

/* Test decoding with all test vectors (unpadded input) */
void test_base32_decode_unpadded(void) {
  uint8_t output[1024];
  size_t out_len;

  printf("\n=== Base32 Decoding Tests (Unpadded) ===\n");

  for (size_t i = 0; i < NUM_TEST_VECTORS; i++) {
    const base32_test_vector_t *tv = &test_vectors[i];
    char test_name[64];
    snprintf(test_name, sizeof(test_name), "base32_decode_unpadded vector %zu",
             i);
    TEST(test_name);

    if (!base32_decode(tv->encoded, strlen(tv->encoded), output, sizeof(output),
                       &out_len)) {
      FAIL("decode failed");
      continue;
    }

    if (out_len != tv->bytes_len) {
      printf("\n  Expected length: %zu, Got: %zu\n", tv->bytes_len, out_len);
      FAIL("length mismatch");
      continue;
    }

    if (memcmp(output, tv->bytes, tv->bytes_len) == 0) {
      PASS();
    } else {
      printf("\n  Expected bytes: ");
      for (size_t j = 0; j < tv->bytes_len && j < 32; j++) {
        printf("%02x ", tv->bytes[j]);
      }
      if (tv->bytes_len > 32)
        printf("...");
      printf("\n  Got bytes:      ");
      for (size_t j = 0; j < out_len && j < 32; j++) {
        printf("%02x ", output[j]);
      }
      if (out_len > 32)
        printf("...");
      printf("\n");
      FAIL("data mismatch");
    }
  }
}

/* Test decoding with all test vectors (padded input) */
void test_base32_decode_padded(void) {
  uint8_t output[1024];
  size_t out_len;

  printf("\n=== Base32 Decoding Tests (Padded) ===\n");

  for (size_t i = 0; i < NUM_TEST_VECTORS; i++) {
    const base32_test_vector_t *tv = &test_vectors[i];
    char test_name[64];
    snprintf(test_name, sizeof(test_name), "base32_decode_padded vector %zu",
             i);
    TEST(test_name);

    if (!base32_decode(tv->encoded_padded, strlen(tv->encoded_padded), output,
                       sizeof(output), &out_len)) {
      FAIL("decode failed");
      continue;
    }

    if (out_len != tv->bytes_len) {
      printf("\n  Expected length: %zu, Got: %zu\n", tv->bytes_len, out_len);
      FAIL("length mismatch");
      continue;
    }

    if (memcmp(output, tv->bytes, tv->bytes_len) == 0) {
      PASS();
    } else {
      printf("\n  Expected bytes: ");
      for (size_t j = 0; j < tv->bytes_len && j < 32; j++) {
        printf("%02x ", tv->bytes[j]);
      }
      if (tv->bytes_len > 32)
        printf("...");
      printf("\n  Got bytes:      ");
      for (size_t j = 0; j < out_len && j < 32; j++) {
        printf("%02x ", output[j]);
      }
      if (out_len > 32)
        printf("...");
      printf("\n");
      FAIL("data mismatch");
    }
  }
}

/* Test round-trip: encode then decode */
void test_base32_roundtrip(void) {
  char encoded[1024];
  uint8_t decoded[1024];
  size_t decoded_len;

  printf("\n=== Base32 Round-Trip Tests ===\n");

  for (size_t i = 0; i < NUM_TEST_VECTORS; i++) {
    const base32_test_vector_t *tv = &test_vectors[i];
    char test_name[64];
    snprintf(test_name, sizeof(test_name), "base32_roundtrip vector %zu", i);
    TEST(test_name);

    /* Encode */
    size_t enc_len =
        base32_encode(tv->bytes, tv->bytes_len, encoded, sizeof(encoded));
    if (enc_len == 0) {
      FAIL("encode failed");
      continue;
    }

    /* Decode */
    if (!base32_decode(encoded, enc_len, decoded, sizeof(decoded),
                       &decoded_len)) {
      FAIL("decode failed");
      continue;
    }

    /* Compare */
    if (decoded_len != tv->bytes_len) {
      printf("\n  Original length: %zu, Decoded length: %zu\n", tv->bytes_len,
             decoded_len);
      FAIL("length mismatch");
      continue;
    }

    if (memcmp(decoded, tv->bytes, tv->bytes_len) == 0) {
      PASS();
    } else {
      FAIL("data mismatch after round-trip");
    }
  }
}

/* Test case-insensitive decoding */
void test_base32_case_insensitive(void) {
  uint8_t output[64];
  size_t out_len;

  printf("\n=== Base32 Case Insensitivity Tests ===\n");

  TEST("base32_decode lowercase");
  if (base32_decode("jbswy3dpeblw64tmmq", 18, output, sizeof(output),
                    &out_len)) {
    if (out_len == 11 && memcmp(output, "Hello World", 11) == 0) {
      PASS();
    } else {
      FAIL("wrong decoded value");
    }
  } else {
    FAIL("decode failed");
  }

  TEST("base32_decode mixed case");
  if (base32_decode("JbSwY3DpEbLw64TmMq", 18, output, sizeof(output),
                    &out_len)) {
    if (out_len == 11 && memcmp(output, "Hello World", 11) == 0) {
      PASS();
    } else {
      FAIL("wrong decoded value");
    }
  } else {
    FAIL("decode failed");
  }
}

/* Test invalid input handling */
void test_base32_invalid_input(void) {
  char output[64];
  uint8_t decoded[64];
  size_t out_len;

  printf("\n=== Base32 Invalid Input Tests ===\n");

  /* Test encode with NULL input */
  TEST("base32_encode NULL input");
  size_t len = base32_encode(NULL, 5, output, sizeof(output));
  if (len == 0) {
    PASS();
  } else {
    FAIL("should return 0 for NULL input");
  }

  /* Test encode with NULL output */
  TEST("base32_encode NULL output");
  const uint8_t dummy[] = "test";
  len = base32_encode(dummy, 4, NULL, 64);
  if (len == 0) {
    PASS();
  } else {
    FAIL("should return 0 for NULL output");
  }

  /* Test encode with zero length */
  TEST("base32_encode zero length");
  len = base32_encode(dummy, 0, output, sizeof(output));
  if (len == 0) {
    PASS();
  } else {
    FAIL("should return 0 for zero length");
  }

  /* Test encode with insufficient output buffer */
  TEST("base32_encode small buffer");
  len = base32_encode(dummy, 4, output, 2); /* needs 8 chars + null */
  if (len == 0) {
    PASS();
  } else {
    FAIL("should return 0 for small buffer");
  }

  /* Test decode with NULL input */
  TEST("base32_decode NULL input");
  bool result = base32_decode(NULL, 8, decoded, sizeof(decoded), &out_len);
  if (!result) {
    PASS();
  } else {
    FAIL("should return false for NULL input");
  }

  /* Test decode with NULL output */
  TEST("base32_decode NULL output");
  result = base32_decode("JBSWY3DP", 8, NULL, 64, &out_len);
  if (!result) {
    PASS();
  } else {
    FAIL("should return false for NULL output");
  }

  /* Test decode with NULL out_len */
  TEST("base32_decode NULL out_len");
  result = base32_decode("JBSWY3DP", 8, decoded, sizeof(decoded), NULL);
  if (!result) {
    PASS();
  } else {
    FAIL("should return false for NULL out_len");
  }

  /* Test decode with invalid characters */
  TEST("base32_decode invalid chars (!)");
  result = base32_decode("JBSWY!DP", 8, decoded, sizeof(decoded), &out_len);
  if (!result) {
    PASS();
  } else {
    FAIL("should return false for invalid chars");
  }

  /* Test decode with invalid characters (1) */
  TEST("base32_decode invalid chars (1)");
  result = base32_decode("JBSWY1DP", 8, decoded, sizeof(decoded), &out_len);
  if (!result) {
    PASS();
  } else {
    FAIL("should return false for digit 1");
  }

  /* Test decode with invalid characters (0) */
  TEST("base32_decode invalid chars (0)");
  result = base32_decode("JBSWY0DP", 8, decoded, sizeof(decoded), &out_len);
  if (!result) {
    PASS();
  } else {
    FAIL("should return false for digit 0");
  }

  /* Test decode with insufficient output buffer */
  TEST("base32_decode small buffer");
  result = base32_decode("JBSWY3DPEBLW64TMMQ", 18, decoded, 2, &out_len);
  if (!result) {
    PASS();
  } else {
    FAIL("should return false for small buffer");
  }
}

/* Test length calculation functions */
void test_base32_length_functions(void) {
  printf("\n=== Base32 Length Function Tests ===\n");

  /* Test encoded length calculation */
  TEST("base32_encoded_len 0 bytes");
  if (base32_encoded_len(0) == 0) {
    PASS();
  } else {
    FAIL("expected 0");
  }

  TEST("base32_encoded_len 1 byte");
  if (base32_encoded_len(1) == 8) {
    PASS();
  } else {
    printf("got %zu, expected 8\n", base32_encoded_len(1));
    FAIL("wrong length");
  }

  TEST("base32_encoded_len 5 bytes");
  if (base32_encoded_len(5) == 8) {
    PASS();
  } else {
    printf("got %zu, expected 8\n", base32_encoded_len(5));
    FAIL("wrong length");
  }

  TEST("base32_encoded_len 6 bytes");
  if (base32_encoded_len(6) == 16) {
    PASS();
  } else {
    printf("got %zu, expected 16\n", base32_encoded_len(6));
    FAIL("wrong length");
  }

  TEST("base32_encoded_len 10 bytes");
  if (base32_encoded_len(10) == 16) {
    PASS();
  } else {
    printf("got %zu, expected 16\n", base32_encoded_len(10));
    FAIL("wrong length");
  }

  /* Test decoded length calculation */
  TEST("base32_decoded_len 8 chars");
  if (base32_decoded_len(8) == 5) {
    PASS();
  } else {
    printf("got %zu, expected 5\n", base32_decoded_len(8));
    FAIL("wrong length");
  }

  TEST("base32_decoded_len 16 chars");
  if (base32_decoded_len(16) == 10) {
    PASS();
  } else {
    printf("got %zu, expected 10\n", base32_decoded_len(16));
    FAIL("wrong length");
  }
}

/* Test empty and padding-only strings */
void test_base32_edge_cases(void) {
  uint8_t output[64];
  size_t out_len;

  printf("\n=== Base32 Edge Case Tests ===\n");

  /* Test decode empty string after stripping padding */
  TEST("base32_decode all padding");
  if (base32_decode("========", 8, output, sizeof(output), &out_len)) {
    if (out_len == 0) {
      PASS();
    } else {
      printf("expected 0 bytes, got %zu\n", out_len);
      FAIL("should decode to empty");
    }
  } else {
    FAIL("decode failed");
  }

  /* Test decode with whitespace (if supported) */
  TEST("base32_decode with spaces");
  if (base32_decode("JBSW Y3DP", 9, output, sizeof(output), &out_len)) {
    if (out_len == 5 && memcmp(output, "Hello", 5) == 0) {
      PASS();
    } else {
      FAIL("wrong decoded value");
    }
  } else {
    FAIL("decode failed");
  }
}

int main(void) {
  printf("========================================\n");
  printf("        Base32 Test Suite\n");
  printf("========================================\n");

  /* Run all tests */
  test_base32_encode_vectors();
  test_base32_encode_padded();
  test_base32_decode_unpadded();
  test_base32_decode_padded();
  test_base32_roundtrip();
  test_base32_case_insensitive();
  test_base32_invalid_input();
  test_base32_length_functions();
  test_base32_edge_cases();

  /* Print summary */
  printf("\n========================================\n");
  printf("        Test Summary\n");
  printf("========================================\n");
  printf("Passed: %d\n", tests_passed);
  printf("Failed: %d\n", tests_failed);
  printf("Total:  %d\n", tests_passed + tests_failed);
  printf("========================================\n");

  return tests_failed > 0 ? 1 : 0;
}
