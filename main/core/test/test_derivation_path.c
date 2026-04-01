/*
 * Tests for parse_derivation_path() in key.c
 * Using BIP32 test vectors from the specification.
 *
 * Compile: see Makefile
 * Run: ./test_derivation_path
 */

#include <stdio.h>
#include <string.h>

/* Include key.c directly to access the static parse_derivation_path */
#include "../key.c"

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

static void test_parse_valid(const char *name, const char *path,
                             size_t expected_depth,
                             const uint32_t *expected_indices) {
  TEST(name);
  uint32_t indices[10];
  size_t depth = 0;
  memset(indices, 0, sizeof(indices));

  if (!parse_derivation_path(path, indices, &depth, 10)) {
    FAIL("parse returned false");
    return;
  }

  if (depth != expected_depth) {
    char msg[128];
    snprintf(msg, sizeof(msg), "depth %zu != expected %zu", depth,
             expected_depth);
    FAIL(msg);
    return;
  }

  for (size_t i = 0; i < expected_depth; i++) {
    if (indices[i] != expected_indices[i]) {
      char msg[128];
      snprintf(msg, sizeof(msg), "index[%zu] 0x%08x != expected 0x%08x", i,
               indices[i], expected_indices[i]);
      FAIL(msg);
      return;
    }
  }

  PASS();
}

static void test_parse_invalid(const char *name, const char *path) {
  TEST(name);
  uint32_t indices[10];
  size_t depth = 0;

  if (parse_derivation_path(path, indices, &depth, 10)) {
    FAIL("parse should have returned false");
    return;
  }

  PASS();
}

static uint32_t hardened(uint32_t index) {
  return index | BIP32_INITIAL_HARDENED_CHILD;
}

int main(void) {
  printf("=== parse_derivation_path tests ===\n\n");

  /* BIP32 Test Vector 1 paths (seed 000102030405060708090a0b0c0d0e0f) */
  printf("--- BIP32 Test Vector 1 ---\n");

  test_parse_valid("TV1: m", "m", 0, NULL);

  {
    uint32_t exp[] = {hardened(0)};
    test_parse_valid("TV1: m/0'", "m/0'", 1, exp);
  }

  {
    uint32_t exp[] = {hardened(0), 1};
    test_parse_valid("TV1: m/0'/1", "m/0'/1", 2, exp);
  }

  {
    uint32_t exp[] = {hardened(0), 1, hardened(2)};
    test_parse_valid("TV1: m/0'/1/2'", "m/0'/1/2'", 3, exp);
  }

  {
    uint32_t exp[] = {hardened(0), 1, hardened(2), 2};
    test_parse_valid("TV1: m/0'/1/2'/2", "m/0'/1/2'/2", 4, exp);
  }

  {
    uint32_t exp[] = {hardened(0), 1, hardened(2), 2, 1000000000};
    test_parse_valid("TV1: m/0'/1/2'/2/1000000000", "m/0'/1/2'/2/1000000000",
                     5, exp);
  }

  /* BIP32 Test Vector 2 paths */
  printf("\n--- BIP32 Test Vector 2 ---\n");

  {
    uint32_t exp[] = {0};
    test_parse_valid("TV2: m/0", "m/0", 1, exp);
  }

  {
    uint32_t exp[] = {0, hardened(2147483647)};
    test_parse_valid("TV2: m/0/2147483647'", "m/0/2147483647'", 2, exp);
  }

  {
    uint32_t exp[] = {0, hardened(2147483647), 1};
    test_parse_valid("TV2: m/0/2147483647'/1", "m/0/2147483647'/1", 3, exp);
  }

  {
    uint32_t exp[] = {0, hardened(2147483647), 1, hardened(2147483646)};
    test_parse_valid("TV2: m/0/2147483647'/1/2147483646'",
                     "m/0/2147483647'/1/2147483646'", 4, exp);
  }

  {
    uint32_t exp[] = {0, hardened(2147483647), 1, hardened(2147483646), 2};
    test_parse_valid("TV2: m/0/2147483647'/1/2147483646'/2",
                     "m/0/2147483647'/1/2147483646'/2", 5, exp);
  }

  /* Boundary values */
  printf("\n--- Boundary values ---\n");

  {
    uint32_t exp[] = {2147483647};
    test_parse_valid("max non-hardened: m/2147483647", "m/2147483647", 1, exp);
  }

  /* Without m/ prefix (BIP32 allows optional m) */
  printf("\n--- Without m/ prefix ---\n");

  {
    uint32_t exp[] = {0};
    test_parse_valid("no-prefix: 0", "0", 1, exp);
  }

  {
    uint32_t exp[] = {hardened(0)};
    test_parse_valid("no-prefix: 0' (single hardened)", "0'", 1, exp);
  }

  {
    uint32_t exp[] = {hardened(0), 1};
    test_parse_valid("no-prefix: 0'/1", "0'/1", 2, exp);
  }

  {
    uint32_t exp[] = {hardened(44), hardened(0), hardened(0)};
    test_parse_valid("no-prefix: 44'/0'/0'", "44'/0'/0'", 3, exp);
  }

  /* h and H hardened notation */
  printf("\n--- Hardened h/H notation ---\n");

  {
    uint32_t exp[] = {hardened(0)};
    test_parse_valid("h notation: m/0h", "m/0h", 1, exp);
  }

  {
    uint32_t exp[] = {hardened(0)};
    test_parse_valid("H notation: m/0H", "m/0H", 1, exp);
  }

  {
    uint32_t exp[] = {hardened(84), hardened(0), hardened(0)};
    test_parse_valid("h notation: m/84h/0h/0h", "m/84h/0h/0h", 3, exp);
  }

  {
    uint32_t exp[] = {hardened(44), 0, hardened(0)};
    test_parse_valid("mixed: m/44h/0/0'", "m/44h/0/0'", 3, exp);
  }

  /* Invalid paths */
  printf("\n--- Invalid paths ---\n");

  test_parse_invalid("invalid: empty string", "");
  test_parse_invalid("invalid: NULL path", NULL);

  {
    size_t depth = 0;
    TEST("invalid: NULL indices_out");
    if (parse_derivation_path("m/0", NULL, &depth, 10)) {
      FAIL("should reject NULL indices_out");
    } else {
      PASS();
    }
  }

  {
    uint32_t indices[10];
    TEST("invalid: NULL depth_out");
    if (parse_derivation_path("m/0", indices, NULL, 10)) {
      FAIL("should reject NULL depth_out");
    } else {
      PASS();
    }
  }

  test_parse_invalid("invalid: x/0", "x/0");
  test_parse_invalid("invalid: m0 (no separator)", "m0");
  test_parse_invalid("invalid: m0/1 (no separator)", "m0/1");
  test_parse_invalid("invalid: m/abc", "m/abc");
  test_parse_invalid("invalid: m/0//", "m/0//");
  test_parse_invalid("invalid: m//0", "m//0");
  test_parse_invalid("invalid: space m/0 /1", "m/0 /1");
  test_parse_invalid("invalid: dash m/0-1", "m/0-1");
  test_parse_invalid("invalid: trailing h m/h", "m/h");
  test_parse_invalid("invalid: semicolon m/0;1", "m/0;1");
  test_parse_invalid("invalid: M/0 (uppercase)", "M/0");
  test_parse_invalid("invalid: m/0'/1\\n", "m/0'/1\n");
  test_parse_invalid("invalid: starts with h", "h/0/1");
  test_parse_invalid("invalid: starts with h0", "h0/1");
  test_parse_invalid("invalid: trailing slash m/", "m/");
  test_parse_invalid("invalid: trailing slash m/0/", "m/0/");
  test_parse_invalid("invalid: m in path m/0/m", "m/0/m");
  test_parse_invalid("invalid: m/2147483648' (overflow hardened)", "m/2147483648'");
  test_parse_invalid("invalid: m/4294967295' (max u32 hardened)", "m/4294967295'");
  test_parse_invalid("invalid: m/2147483648 (non-hardened in hardened range)", "m/2147483648");
  test_parse_invalid("invalid: m/4294967295 (max u32 non-hardened)", "m/4294967295");
  test_parse_invalid("invalid: m/4294967296 (u32 overflow wrap)", "m/4294967296");
  test_parse_invalid("invalid: m/9999999999 (large overflow)", "m/9999999999");
  test_parse_invalid("invalid: m/99999999999999999999 (huge overflow)", "m/99999999999999999999");
  test_parse_invalid("invalid: m/0'' (double hardened)", "m/0''");
  test_parse_invalid("invalid: m/0'h (double hardened mixed)", "m/0'h");
  test_parse_invalid("invalid: m/0h' (double hardened mixed)", "m/0h'");
  test_parse_invalid("invalid: m/0'H (double hardened mixed)", "m/0'H");
  test_parse_invalid("invalid: m/' (hardened without digits)", "m/'");
  test_parse_invalid("invalid: m/00 (leading zero)", "m/00");
  test_parse_invalid("invalid: m/01 (leading zero)", "m/01");
  test_parse_invalid("invalid: m/00' (leading zero hardened)", "m/00'");
  test_parse_invalid("invalid: 0'//1 (double slash no prefix)", "0'//1");

  /* Edge cases */
  printf("\n--- Edge cases ---\n");
  {
    uint32_t indices[10];
    size_t depth = 0;
    TEST("max depth exceeded (11 levels, max=10)");
    if (parse_derivation_path("m/0/1/2/3/4/5/6/7/8/9/10", indices, &depth,
                              10)) {
      FAIL("should reject path exceeding max_depth");
    } else {
      PASS();
    }
  }

  {
    uint32_t indices[10];
    size_t depth = 0;
    uint32_t exp[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    TEST("exact max depth (10 levels, max=10)");
    if (!parse_derivation_path("m/0/1/2/3/4/5/6/7/8/9", indices, &depth, 10)) {
      FAIL("should accept path at exactly max_depth");
    } else if (depth != 10) {
      FAIL("depth should be 10");
    } else {
      bool ok = true;
      for (size_t i = 0; i < 10; i++) {
        if (indices[i] != exp[i]) { ok = false; break; }
      }
      if (ok) { PASS(); } else { FAIL("wrong indices"); }
    }
  }

  {
    uint32_t indices[10];
    size_t depth = 0;
    TEST("max_depth=0 accepts m");
    if (!parse_derivation_path("m", indices, &depth, 0)) {
      FAIL("should accept 'm' with max_depth=0");
    } else if (depth != 0) {
      FAIL("depth should be 0");
    } else {
      PASS();
    }
  }

  {
    uint32_t indices[10];
    size_t depth = 0;
    TEST("max_depth=0 rejects m/0");
    if (parse_derivation_path("m/0", indices, &depth, 0)) {
      FAIL("should reject 'm/0' with max_depth=0");
    } else {
      PASS();
    }
  }

  {
    uint32_t indices[10];
    size_t depth = 0;
    TEST("max_depth=1 accepts m/0");
    if (!parse_derivation_path("m/0", indices, &depth, 1)) {
      FAIL("should accept 'm/0' with max_depth=1");
    } else if (depth != 1 || indices[0] != 0) {
      FAIL("wrong depth or index");
    } else {
      PASS();
    }
  }

  {
    uint32_t indices[10];
    size_t depth = 0;
    TEST("max_depth=1 rejects m/0/1");
    if (parse_derivation_path("m/0/1", indices, &depth, 1)) {
      FAIL("should reject 'm/0/1' with max_depth=1");
    } else {
      PASS();
    }
  }

  /* Summary */
  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
