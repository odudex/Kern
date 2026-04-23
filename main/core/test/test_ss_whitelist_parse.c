#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Pull in implementation directly */
#include "../ss_whitelist.c"

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

/* m/44'/0'/0'/0/0 — purpose 44|0x80000000 = 0x8000002c */
static const unsigned char buf_44[] = {
    0x2c, 0x00, 0x00, 0x80, /* purpose 44' */
    0x00, 0x00, 0x00, 0x80, /* coin    0'  */
    0x00, 0x00, 0x00, 0x80, /* account 0'  */
    0x00, 0x00, 0x00, 0x00, /* chain   0   */
    0x00, 0x00, 0x00, 0x00, /* index   0   */
};

/* m/49'/0'/0'/0/0 */
static const unsigned char buf_49[] = {
    0x31, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* m/84'/0'/0'/0/0 */
static const unsigned char buf_84[] = {
    0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* m/86'/0'/0'/0/0 */
static const unsigned char buf_86[] = {
    0x56, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static void test_valid_purpose(const char *name, const unsigned char *buf,
                               ss_script_type_t expected_script,
                               uint32_t expected_purpose) {
  TEST(name);
  ss_keypath_t kp;
  if (!ss_keypath_parse(buf, 20, &kp)) {
    FAIL("parse returned false");
    return;
  }
  if (kp.script != expected_script) {
    FAIL("wrong script type");
    return;
  }
  if (kp.purpose != expected_purpose) {
    FAIL("wrong purpose");
    return;
  }
  if (kp.coin != 0 || kp.account != 0 || kp.chain != 0 || kp.index != 0) {
    FAIL("wrong coin/account/chain/index");
    return;
  }
  PASS();
}

static void test_format(const char *name, ss_keypath_t kp,
                        const char *expected) {
  TEST(name);
  char buf[SS_KEYPATH_FMT_MAX];
  if (!ss_keypath_format(&kp, buf, sizeof(buf))) {
    FAIL("format returned false");
    return;
  }
  if (strcmp(buf, expected) != 0) {
    FAIL("wrong format string");
    return;
  }
  PASS();
}

int main(void) {
  printf("=== ss_keypath_parse tests ===\n\n");

  /* Group 1: round-trip all four valid purposes */
  printf("--- Group 1: valid purposes ---\n");
  test_valid_purpose("m/44'/0'/0'/0/0", buf_44, SS_SCRIPT_P2PKH, 44);
  test_valid_purpose("m/49'/0'/0'/0/0", buf_49, SS_SCRIPT_P2SH_P2WPKH, 49);
  test_valid_purpose("m/84'/0'/0'/0/0", buf_84, SS_SCRIPT_P2WPKH, 84);
  test_valid_purpose("m/86'/0'/0'/0/0", buf_86, SS_SCRIPT_P2TR, 86);

  /* Group 2: length rejection */
  printf("\n--- Group 2: length rejection ---\n");
  {
    ss_keypath_t kp;
    TEST("len=0 rejected");
    if (ss_keypath_parse(buf_44, 0, &kp)) {
      FAIL("should reject len 0");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp;
    TEST("len=19 rejected");
    if (ss_keypath_parse(buf_44, 19, &kp)) {
      FAIL("should reject len 19");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp;
    TEST("len=21 rejected");
    if (ss_keypath_parse(buf_44, 21, &kp)) {
      FAIL("should reject len 21");
    } else {
      PASS();
    }
  }
  {
    ss_keypath_t kp;
    TEST("len=24 rejected (full keypath with fingerprint)");
    if (ss_keypath_parse(buf_44, 24, &kp)) {
      FAIL("should reject len 24");
    } else {
      PASS();
    }
  }

  /* Group 3: unhardened purpose rejected */
  printf("\n--- Group 3: unhardened purpose rejected ---\n");
  {
    unsigned char buf[20];
    memcpy(buf, buf_44, 20);
    buf[3] &= 0x7f; /* clear bit 31 of purpose */
    ss_keypath_t kp;
    TEST("unhardened purpose (44 without flag)");
    if (ss_keypath_parse(buf, 20, &kp)) {
      FAIL("should reject unhardened purpose");
    } else {
      PASS();
    }
  }

  /* Group 4: unhardened coin rejected */
  printf("\n--- Group 4: unhardened coin rejected ---\n");
  {
    unsigned char buf[20];
    memcpy(buf, buf_44, 20);
    buf[7] &= 0x7f; /* clear bit 31 of coin */
    ss_keypath_t kp;
    TEST("unhardened coin");
    if (ss_keypath_parse(buf, 20, &kp)) {
      FAIL("should reject unhardened coin");
    } else {
      PASS();
    }
  }

  /* Group 5: unhardened account rejected */
  printf("\n--- Group 5: unhardened account rejected ---\n");
  {
    unsigned char buf[20];
    memcpy(buf, buf_44, 20);
    buf[11] &= 0x7f; /* clear bit 31 of account */
    ss_keypath_t kp;
    TEST("unhardened account");
    if (ss_keypath_parse(buf, 20, &kp)) {
      FAIL("should reject unhardened account");
    } else {
      PASS();
    }
  }

  /* Group 6: hardened chain rejected */
  printf("\n--- Group 6: hardened chain rejected ---\n");
  {
    unsigned char buf[20];
    memcpy(buf, buf_44, 20);
    buf[15] |= 0x80; /* set bit 31 of chain */
    ss_keypath_t kp;
    TEST("hardened chain");
    if (ss_keypath_parse(buf, 20, &kp)) {
      FAIL("should reject hardened chain");
    } else {
      PASS();
    }
  }

  /* Group 7: hardened index rejected */
  printf("\n--- Group 7: hardened index rejected ---\n");
  {
    unsigned char buf[20];
    memcpy(buf, buf_44, 20);
    buf[19] |= 0x80; /* set bit 31 of index */
    ss_keypath_t kp;
    TEST("hardened index");
    if (ss_keypath_parse(buf, 20, &kp)) {
      FAIL("should reject hardened index");
    } else {
      PASS();
    }
  }

  /* Group 8: unknown purpose rejected */
  printf("\n--- Group 8: unknown purpose rejected ---\n");
  {
    /* purpose 45 hardened: 45 | 0x80000000 = 0x8000002d → LE: 0x2d 0x00 0x00
     * 0x80 */
    unsigned char buf[20];
    memcpy(buf, buf_44, 20);
    buf[0] = 0x2d; /* purpose 45' */
    ss_keypath_t kp;
    TEST("purpose 45' (unknown)");
    if (ss_keypath_parse(buf, 20, &kp)) {
      FAIL("should reject purpose 45");
    } else {
      PASS();
    }
  }
  {
    /* purpose 48 hardened: 48 | 0x80000000 = 0x80000030 → LE: 0x30 0x00 0x00
     * 0x80 */
    unsigned char buf[20];
    memcpy(buf, buf_44, 20);
    buf[0] = 0x30; /* purpose 48' */
    ss_keypath_t kp;
    TEST("purpose 48' (unknown)");
    if (ss_keypath_parse(buf, 20, &kp)) {
      FAIL("should reject purpose 48");
    } else {
      PASS();
    }
  }

  /* Group 9: ss_keypath_format — all four purposes */
  printf("\n--- Group 9: ss_keypath_format ---\n");
  test_format("format m/44'/0'/0'/0/0",
              (ss_keypath_t){SS_SCRIPT_P2PKH, 44, 0, 0, 0, 0},
              "m/44'/0'/0'/0/0");
  test_format("format m/49'/0'/0'/0/0",
              (ss_keypath_t){SS_SCRIPT_P2SH_P2WPKH, 49, 0, 0, 0, 0},
              "m/49'/0'/0'/0/0");
  test_format("format m/84'/0'/0'/0/0",
              (ss_keypath_t){SS_SCRIPT_P2WPKH, 84, 0, 0, 0, 0},
              "m/84'/0'/0'/0/0");
  test_format("format m/86'/0'/0'/0/0",
              (ss_keypath_t){SS_SCRIPT_P2TR, 86, 0, 0, 0, 0},
              "m/86'/0'/0'/0/0");

  /* Group 10: ss_keypath_format — non-zero fields + overflow */
  printf("\n--- Group 10: ss_keypath_format edge cases ---\n");
  test_format("format m/84'/1'/5'/1/42",
              (ss_keypath_t){SS_SCRIPT_P2WPKH, 84, 1, 5, 1, 42},
              "m/84'/1'/5'/1/42");
  {
    ss_keypath_t kp = {SS_SCRIPT_P2PKH, 44, 0, 0, 0, 0};
    char tiny[5]; /* too small for "m/44'..." */
    TEST("format overflow rejected");
    if (ss_keypath_format(&kp, tiny, sizeof(tiny))) {
      FAIL("should return false on overflow");
    } else {
      PASS();
    }
  }

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
