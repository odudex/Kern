#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "core/registry.h"

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

/* Account-level xpubs from the standard BIP39 test mnemonic "abandon...about".
 * key_get_fingerprint stub returns {0x00,0x00,0x00,0x00}, so all descriptors
 * use origin fingerprint 00000000. */
#define XPUB_84                                                                \
  "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvP"               \
  "EbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
#define XPUB_86                                                                \
  "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWc"                \
  "LteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"

#define H(n) (0x80000000u | (n))

/* A raw keypath: fingerprint deadbeef (the registry compares paths only),
 * then `n` little-endian components. Returns its length. */
static size_t keypath(uint8_t *out, size_t n, ...) {
  va_list ap;
  va_start(ap, n);
  memset(out, 0, 4);
  out[0] = 0xde;
  out[1] = 0xad;
  out[2] = 0xbe;
  out[3] = 0xef;
  for (size_t i = 0; i < n; i++) {
    uint32_t c = va_arg(ap, uint32_t);
    for (size_t b = 0; b < 4; b++)
      out[4 + i * 4 + b] = (uint8_t)(c >> (8 * b));
  }
  va_end(ap);
  return 4 + n * 4;
}

static void seed_registry(void) {
  registry_clear();
  bool ok =
      /* e[0]: 84'/0'/0', single-path */
      registry_add_from_string("e0",
                               "wpkh([00000000/84'/0'/0']" XPUB_84 "/0/*)",
                               STORAGE_FLASH, false) &&
      /* e[1]: 48'/0'/0'/2', multipath */
      registry_add_from_string(
          "e1", "wpkh([00000000/48'/0'/0'/2']" XPUB_84 "/<0;1>/*)",
          STORAGE_FLASH, false) &&
      /* e[2]: 86'/0'/0', single-path */
      registry_add_from_string("e2", "tr([00000000/86'/0'/0']" XPUB_86 "/0/*)",
                               STORAGE_FLASH, false);
  if (!ok) {
    TEST("seed registry");
    FAIL("registry_add_from_string");
  }
}

static bool add_one(const char *desc) {
  registry_clear();
  return registry_add_from_string("t", desc, STORAGE_FLASH, false);
}

static registry_entry_t *match(const uint8_t *kp, size_t len, uint32_t *mi,
                               uint32_t *cn) {
  registry_match_cursor_t cursor = {0};
  return registry_match_keypath(kp, len, &cursor, mi, cn);
}

static void expect_match(const char *name, const uint8_t *kp, size_t len,
                         const char *id, uint32_t mi, uint32_t cn) {
  TEST(name);
  uint32_t got_mi = 99, got_cn = 99;
  registry_entry_t *r = match(kp, len, &got_mi, &got_cn);
  if (!r)
    FAIL("returned NULL");
  else if (strcmp(r->id, id) != 0)
    FAIL("wrong entry");
  else if (got_mi != mi || got_cn != cn)
    FAIL("wrong multi_index or child_num");
  else
    PASS();
}

static void expect_none(const char *name, const uint8_t *kp, size_t len) {
  TEST(name);
  uint32_t mi = 0, cn = 0;
  if (match(kp, len, &mi, &cn) != NULL)
    FAIL("should return NULL");
  else
    PASS();
}

int main(void) {
  printf("=== registry_match_keypath tests ===\n\n");
  uint8_t kp[4 + MAX_KEYPATH_TOTAL_DEPTH * 4];
  size_t n;

  printf("--- basic match ---\n");
  seed_registry();
  n = keypath(kp, 5, H(86), H(0), H(0), 0u, 3u);
  expect_match("match entry #2", kp, n, "e2", 0, 3);
  n = keypath(kp, 5, H(99), H(0), H(0), 0u, 0u);
  expect_none("unknown origin", kp, n);

  printf("\n--- tail shape ---\n");
  n = keypath(kp, 4, H(86), H(0), H(0), 3u);
  expect_none("tail depth = 1", kp, n);
  n = keypath(kp, 6, H(86), H(0), H(0), 0u, 3u, 1u);
  expect_none("tail depth = 3", kp, n);
  n = keypath(kp, 5, H(86), H(0), H(0), H(0), 3u);
  expect_none("hardened chain", kp, n);
  n = keypath(kp, 5, H(86), H(0), H(0), 0u, H(3));
  expect_none("hardened index", kp, n);

  printf("\n--- multipath groups ---\n");
  n = keypath(kp, 5, H(86), H(0), H(0), 2u, 3u);
  expect_none("single-path /0/* does not match /2/3", kp, n);
  n = keypath(kp, 5, H(86), H(0), H(0), 1u, 3u);
  expect_none("single-path /0/* does not match /1/3", kp, n);
  n = keypath(kp, 6, H(48), H(0), H(0), H(2), 1u, 7u);
  expect_match("<0;1> change at group 1", kp, n, "e1", 1, 7);

  if (add_one("wsh(multi(1,[00000000/48'/0'/0'/2']" XPUB_84 "/<2;3>/*,"
              "[11111111/48'/0'/0'/2']" XPUB_86 "/<2;3>/*))")) {
    n = keypath(kp, 6, H(48), H(0), H(0), H(2), 2u, 4u);
    expect_match("<2;3> receive is group 0", kp, n, "t", 0, 4);
    n = keypath(kp, 6, H(48), H(0), H(0), H(2), 3u, 4u);
    expect_match("<2;3> change is group 1", kp, n, "t", 1, 4);
    n = keypath(kp, 6, H(48), H(0), H(0), H(2), 0u, 4u);
    expect_none("<2;3> does not match /0/4", kp, n);
  } else {
    FAIL("register <2;3>");
  }

  if (add_one("wpkh([00000000/84'/0'/0']" XPUB_84 "/<1;0>/*)")) {
    n = keypath(kp, 5, H(84), H(0), H(0), 1u, 9u);
    expect_match("<1;0>: /1/9 is group 0", kp, n, "t", 0, 9);
  } else {
    FAIL("register <1;0>");
  }

  if (add_one("wpkh([00000000/84'/0'/0']" XPUB_84 "/<0;1;2>/*)")) {
    n = keypath(kp, 5, H(84), H(0), H(0), 2u, 5u);
    expect_match("<0;1;2>: /2/5 is group 2", kp, n, "t", 2, 5);
  } else {
    FAIL("register <0;1;2>");
  }

  if (add_one("wpkh([00000000/84'/0'/0']" XPUB_84 "/0/<0;1>/*)")) {
    n = keypath(kp, 6, H(84), H(0), H(0), 0u, 1u, 6u);
    expect_match("/0/<0;1>/*: /0/1/6 is group 1", kp, n, "t", 1, 6);
  } else {
    FAIL("register /0/<0;1>/*");
  }

  if (add_one("wpkh([00000000/84'/0'/0']" XPUB_84 "/1/*)")) {
    n = keypath(kp, 5, H(84), H(0), H(0), 1u, 8u);
    expect_match("single-path /1/*", kp, n, "t", 0, 8);
  } else {
    FAIL("register /1/*");
  }

  /* Same seed in two groups: the recovery key at <2;3> matches too. */
  if (add_one("wsh(or_d(pk([00000000/48'/0'/0'/2']" XPUB_84 "/<0;1>/*),"
              "and_v(v:pkh([00000000/48'/0'/0'/2']" XPUB_84 "/<2;3>/*),"
              "older(144))))")) {
    const registry_entry_t *e = registry_get(0);
    TEST("two own keys recorded");
    if (e->num_own_keys == 2 &&
        strcmp(e->own_keys[0].child_path, "<0;1>/*") == 0 &&
        strcmp(e->own_keys[1].child_path, "<2;3>/*") == 0)
      PASS();
    else
      FAIL("expected both own keys with their child paths");
    n = keypath(kp, 6, H(48), H(0), H(0), H(2), 2u, 3u);
    expect_match("recovery key /2/3 is group 0", kp, n, "t", 0, 3);
  } else {
    FAIL("register two-group miniscript");
  }

  printf("\n--- cursor pagination ---\n");
  seed_registry();
  n = keypath(kp, 5, H(86), H(0), H(0), 0u, 3u);
  {
    registry_match_cursor_t cursor = {0};
    uint32_t mi = 0, cn = 0;
    TEST("first call returns e[2]");
    registry_entry_t *r = registry_match_keypath(kp, n, &cursor, &mi, &cn);
    if (!r || strcmp(r->id, "e2") != 0)
      FAIL("expected e2");
    else
      PASS();

    TEST("second call returns NULL");
    if (registry_match_keypath(kp, n, &cursor, &mi, &cn) != NULL)
      FAIL("expected NULL after last entry");
    else
      PASS();
  }

  registry_clear();
  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
