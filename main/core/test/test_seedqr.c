#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_core.h>

#include "qr/seedqr.h"

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

/* "abandon" is word 0, "about" word 3 and "art" word 102 of the BIP39 list,
 * and all-zero entropy encodes "abandon ... about" (12) or "... art" (24). */
#define ABOUT_12                                                               \
  "abandon abandon abandon abandon abandon abandon "                           \
  "abandon abandon abandon abandon abandon about"
#define ART_24                                                                 \
  "abandon abandon abandon abandon abandon abandon abandon abandon "           \
  "abandon abandon abandon abandon abandon abandon abandon abandon "           \
  "abandon abandon abandon abandon abandon abandon abandon art"
#define DIGITS_12 "000000000000000000000000000000000000000000000003"
#define DIGITS_24                                                              \
  "000000000000000000000000000000000000000000000000"                           \
  "000000000000000000000000000000000000000000000102"

static void expect_mnemonic(const char *name, const char *data, size_t len,
                            mnemonic_qr_format_t format, const char *want) {
  TEST(name);
  mnemonic_qr_format_t got_format = MNEMONIC_QR_UNKNOWN;
  char *m = mnemonic_qr_to_mnemonic(data, len, &got_format);
  if (got_format != format)
    FAIL("wrong format");
  else if (want ? (!m || strcmp(m, want) != 0) : m != NULL)
    FAIL(want ? "wrong mnemonic" : "should be refused");
  else
    PASS();
  free(m);
}

int main(void) {
  if (wally_init(0) != WALLY_OK) {
    printf("ABORT: wally_init failed\n");
    return 1;
  }
  printf("=== SeedQR codec tests ===\n\n");
  unsigned char zeros[32] = {0};

  expect_mnemonic("SeedQR 12 words", DIGITS_12, strlen(DIGITS_12),
                  MNEMONIC_QR_SEEDQR, ABOUT_12);
  expect_mnemonic("SeedQR 24 words", DIGITS_24, strlen(DIGITS_24),
                  MNEMONIC_QR_SEEDQR, ART_24);
  expect_mnemonic("Compact SeedQR 12 words", (const char *)zeros, 16,
                  MNEMONIC_QR_COMPACT, ABOUT_12);
  expect_mnemonic("Compact SeedQR 24 words", (const char *)zeros, 32,
                  MNEMONIC_QR_COMPACT, ART_24);
  expect_mnemonic("plaintext words", ABOUT_12, strlen(ABOUT_12),
                  MNEMONIC_QR_PLAINTEXT, ABOUT_12);
  expect_mnemonic("SeedQR with a bad checksum refused",
                  "000000000000000000000000000000000000000000000000", 48,
                  MNEMONIC_QR_SEEDQR, NULL);
  expect_mnemonic("SeedQR with an index past 2047 refused",
                  "204800000000000000000000000000000000000000000003", 48,
                  MNEMONIC_QR_SEEDQR, NULL);

  TEST("mnemonic to SeedQR digits");
  char *digits = mnemonic_to_seedqr(ART_24);
  if (digits && strcmp(digits, DIGITS_24) == 0)
    PASS();
  else
    FAIL("wrong digits");
  free(digits);

  TEST("mnemonic to Compact SeedQR entropy");
  size_t len = 0;
  unsigned char *compact = mnemonic_to_compact_seedqr(ABOUT_12, &len);
  if (compact && len == 16 && memcmp(compact, zeros, 16) == 0)
    PASS();
  else
    FAIL("wrong entropy");
  free(compact);

  TEST("an invalid mnemonic has no SeedQR");
  digits =
      mnemonic_to_seedqr("abandon abandon abandon abandon abandon abandon "
                         "abandon abandon abandon abandon abandon abandon");
  compact = mnemonic_to_compact_seedqr(
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon",
      &len);
  if (!digits && !compact)
    PASS();
  else
    FAIL("should be refused");
  free(digits);
  free(compact);

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
