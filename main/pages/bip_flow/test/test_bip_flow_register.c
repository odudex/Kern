#include "../bip_flow.h"

#include <stdio.h>

static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS() printf("PASS\n")
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                \
    tests_failed++;                                                            \
  } while (0)

static void expect_response_allowed(descriptor_validation_result_t result,
                                    bool expected, const char *name) {
  TEST(name);
  if (bip_flow_register_validation_result_allows_response(result) == expected) {
    PASS();
  } else {
    FAIL("unexpected response policy");
  }
}

int main(void) {
  printf("BIP flow register response policy tests\n");
  printf("=======================================\n\n");

  expect_response_allowed(VALIDATION_SUCCESS, true,
                          "approved registration may show response");
  expect_response_allowed(VALIDATION_USER_DECLINED, true,
                          "declined registration may show response");
  expect_response_allowed(VALIDATION_PARSE_ERROR, false,
                          "parse error must stay local");
  expect_response_allowed(VALIDATION_FINGERPRINT_NOT_FOUND, false,
                          "fingerprint error must stay local");
  expect_response_allowed(VALIDATION_DUPLICATE, false,
                          "duplicate shortcut must stay local");
  expect_response_allowed(VALIDATION_XPUB_MISMATCH, false,
                          "xpub mismatch must stay local");

  printf("\nResults: %d failed\n", tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
