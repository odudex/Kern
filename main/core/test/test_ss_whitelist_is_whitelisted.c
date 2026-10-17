#include <stdint.h>
#include <stdio.h>
#include <wally_core.h>

#include "core/ss_whitelist.h"

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

int main(void) {
  /* The host libwally hashes through PSA, as the device does, which needs
   * wally_init. */
  if (wally_init(0) != WALLY_OK) {
    printf("ABORT: wally_init failed\n");
    return 1;
  }
  printf("=== ss_keypath_is_whitelisted tests ===\n\n");

  /* Group 1: account boundary */
  printf("--- Group 1: account boundary ---\n");
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 0, 0, 0};
    TEST("account=0 accepted");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("account 0 should be accepted");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 99, 0, 0};
    TEST("account=99 accepted");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("account 99 should be accepted");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 100, 0, 0};
    TEST("account=100 rejected");
    if (ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("account 100 should be rejected");
    } else {
      PASS();
    }
  }

  /* Group 2: index boundary */
  printf("\n--- Group 2: index boundary ---\n");
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 0, 0, 0};
    TEST("index=0 accepted");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("index 0 should be accepted");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH,         84, 0, 0, 0,
                       SS_MAX_OUT_ADDR_INDEX - 1};
    TEST("index=SS_MAX_OUT_ADDR_INDEX-1 accepted");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("index SS_MAX_OUT_ADDR_INDEX-1 should be accepted");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 0, 0, SS_MAX_OUT_ADDR_INDEX};
    TEST("index=SS_MAX_OUT_ADDR_INDEX rejected");
    if (ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("index SS_MAX_OUT_ADDR_INDEX should be rejected");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 0, 0, SS_MAX_OUT_ADDR_INDEX};
    TEST("index=SS_MAX_OUT_ADDR_INDEX accepted when uncapped");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_ADDR_INDEX_UNCAPPED)) {
      FAIL("index SS_MAX_OUT_ADDR_INDEX should be accepted when uncapped");
    } else {
      PASS();
    }
  }

  /* Group 3: coin / network */
  printf("\n--- Group 3: coin / network ---\n");
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 0, 0, 0};
    TEST("coin=0 accepted on mainnet");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("coin 0 should be accepted on mainnet");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 1, 0, 0, 0};
    TEST("coin=1 rejected on mainnet");
    if (ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("coin 1 should be rejected on mainnet");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 1, 0, 0, 0};
    TEST("coin=1 accepted on testnet");
    if (!ss_keypath_is_whitelisted(&kp, true, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("coin 1 should be accepted on testnet");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 0, 0, 0};
    TEST("coin=0 rejected on testnet");
    if (ss_keypath_is_whitelisted(&kp, true, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("coin 0 should be rejected on testnet");
    } else {
      PASS();
    }
  }

  /* Group 4: chain boundary */
  printf("\n--- Group 4: chain boundary ---\n");
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 0, 0, 0};
    TEST("chain=0 accepted");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("chain 0 should be accepted");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 0, 1, 0};
    TEST("chain=1 accepted");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("chain 1 should be accepted");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 0, 2, 0};
    TEST("chain=2 rejected");
    if (ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("chain 2 should be rejected");
    } else {
      PASS();
    }
  }

  /* Group 5: all four valid purposes accepted */
  printf("\n--- Group 5: all four purposes accepted ---\n");
  {
    ss_keypath_t kp = {SS_SCRIPT_P2PKH, 44, 0, 0, 0, 0};
    TEST("purpose=44 accepted");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("purpose 44 should be accepted");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2SH_P2WPKH, 49, 0, 0, 0, 0};
    TEST("purpose=49 accepted");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("purpose 49 should be accepted");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2WPKH, 84, 0, 0, 0, 0};
    TEST("purpose=84 accepted");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("purpose 84 should be accepted");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp = {SS_SCRIPT_P2TR, 86, 0, 0, 0, 0};
    TEST("purpose=86 accepted");
    if (!ss_keypath_is_whitelisted(&kp, false, SS_MAX_OUT_ADDR_INDEX)) {
      FAIL("purpose 86 should be accepted");
    } else {
      PASS();
    }
  }

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
