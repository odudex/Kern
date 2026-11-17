#include "../bip_flow.h"

#include <stdio.h>

static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS() printf("PASS\n")
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

static void expect_error(descriptor_validation_result_t result,
                         uint8_t expected, const char *name) {
  TEST(name);
  if (bip_flow_register_error(result) == expected) {
    PASS();
  } else {
    FAIL("unexpected error code");
  }
}

int main(void) {
  printf("BIP flow register error tests\n");
  printf("=============================\n\n");

  expect_error(VALIDATION_USER_DECLINED, 0x01,
               "declined registration answers user declined");
  expect_error(VALIDATION_PARSE_ERROR, 0x05,
               "parse error answers registration failed");
  expect_error(VALIDATION_FINGERPRINT_NOT_FOUND, 0x05,
               "fingerprint error answers registration failed");
  expect_error(VALIDATION_DUPLICATE, 0x05,
               "duplicate descriptor answers registration failed");
  expect_error(VALIDATION_XPUB_MISMATCH, 0x05,
               "xpub mismatch answers registration failed");
  expect_error(VALIDATION_NETWORK_MISMATCH, 0x10,
               "network mismatch answers network mismatch");
  expect_error(VALIDATION_INTERNAL_ERROR, 0x0B,
               "internal error answers internal device error");

  printf("\nResults: %d failed\n", tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
