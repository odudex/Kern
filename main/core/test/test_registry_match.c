#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../registry.c"

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

static void seed_registry(void) {
  registry_clear();
  /* e[0]: 84'/0'/0', single-path */
  registry_add_from_string("e0", "wpkh([00000000/84'/0'/0']" XPUB_84 "/0/*)",
                           STORAGE_FLASH, false);
  /* e[1]: 48'/0'/0'/2', multipath */
  registry_add_from_string("e1",
                           "wpkh([00000000/48'/0'/0'/2']" XPUB_84 "/<0;1>/*)",
                           STORAGE_FLASH, false);
  /* e[2]: 86'/0'/0', single-path */
  registry_add_from_string("e2", "tr([00000000/86'/0'/0']" XPUB_86 "/0/*)",
                           STORAGE_FLASH, false);
}

int main(void) {
  printf("=== registry_match_keypath tests ===\n\n");

  /* --- Group 1: basic match --- */
  printf("--- Group 1: basic match e[2] ---\n");
  {
    seed_registry();
    static const uint8_t kp[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x56, 0x00, 0x00, 0x80, /* 86' */
        0x00, 0x00, 0x00, 0x80,                         /* 0' */
        0x00, 0x00, 0x00, 0x80,                         /* 0' */
        0x00, 0x00, 0x00, 0x00,                         /* mp=0 */
        0x03, 0x00, 0x00, 0x00,                         /* ix=3 */
    };
    size_t cursor = 0;
    TEST("match entry #2");
    registry_entry_t *r = registry_match_keypath(kp, sizeof kp, &cursor);
    if (!r) {
      FAIL("returned NULL");
    } else if (strncmp(r->id, "e2", 2) != 0) {
      FAIL("wrong entry");
    } else if (cursor != 3) {
      FAIL("cursor not advanced");
    } else {
      PASS();
    }
  }

  /* --- Group 2: unknown origin --- */
  printf("\n--- Group 2: unknown origin ---\n");
  {
    seed_registry();
    static const uint8_t kp[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x63, 0x00, 0x00, 0x80, /* 99' — not in registry
                                                         */
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    size_t cursor = 0;
    TEST("unknown origin");
    if (registry_match_keypath(kp, sizeof kp, &cursor) != NULL) {
      FAIL("should return NULL");
    } else {
      PASS();
    }
  }

  /* --- Group 3: wrong tail depth --- */
  printf("\n--- Group 3: wrong tail depth ---\n");
  {
    seed_registry();
    /* tail depth = 1: keypath 20 bytes, total_depth=4, tail=4-3=1 */
    static const uint8_t kp_tail1[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x56, 0x00, 0x00, 0x80, /* 86' */
        0x00, 0x00, 0x00, 0x80,                         /* 0' */
        0x00, 0x00, 0x00, 0x80,                         /* 0' */
        0x03, 0x00, 0x00, 0x00, /* ix=3 (only 1 trailing) */
    };
    size_t cursor = 0;
    TEST("tail depth = 1");
    if (registry_match_keypath(kp_tail1, sizeof kp_tail1, &cursor) != NULL) {
      FAIL("should return NULL");
    } else {
      PASS();
    }
  }
  {
    seed_registry();
    /* tail depth = 3: keypath 28 bytes, total_depth=6, tail=6-3=3 */
    static const uint8_t kp_tail3[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x56, 0x00, 0x00, 0x80, /* 86' */
        0x00, 0x00, 0x00, 0x80,                         /* 0' */
        0x00, 0x00, 0x00, 0x80,                         /* 0' */
        0x00, 0x00, 0x00, 0x00,                         /* mp=0 */
        0x03, 0x00, 0x00, 0x00,                         /* ix=3 */
        0x01, 0x00, 0x00, 0x00, /* extra (3rd trailing) */
    };
    size_t cursor = 0;
    TEST("tail depth = 3");
    if (registry_match_keypath(kp_tail3, sizeof kp_tail3, &cursor) != NULL) {
      FAIL("should return NULL");
    } else {
      PASS();
    }
  }

  /* --- Group 4: hardened trailing --- */
  printf("\n--- Group 4: hardened trailing ---\n");
  {
    seed_registry();
    /* hardened mp */
    static const uint8_t kp_hmp[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x56, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, /* mp = 0'
                                                                 (hardened!) */
        0x03, 0x00, 0x00, 0x00,
    };
    size_t cursor = 0;
    TEST("hardened mp");
    if (registry_match_keypath(kp_hmp, sizeof kp_hmp, &cursor) != NULL) {
      FAIL("should return NULL");
    } else {
      PASS();
    }
  }
  {
    seed_registry();
    /* hardened ix */
    static const uint8_t kp_hix[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x56, 0x00, 0x00, 0x80, 0x00, 0x00,
        0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, /* mp=0 */
        0x03, 0x00, 0x00, 0x80, /* ix = 3' (hardened!) */
    };
    size_t cursor = 0;
    TEST("hardened ix");
    if (registry_match_keypath(kp_hix, sizeof kp_hix, &cursor) != NULL) {
      FAIL("should return NULL");
    } else {
      PASS();
    }
  }

  /* --- Group 5: mp range --- */
  printf("\n--- Group 5: mp range ---\n");
  {
    seed_registry();
    /* mp > 1 */
    static const uint8_t kp_mp2[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x56, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00, /* mp=2 — out of
                                                                 range */
        0x03, 0x00, 0x00, 0x00,
    };
    size_t cursor = 0;
    TEST("mp > 1");
    if (registry_match_keypath(kp_mp2, sizeof kp_mp2, &cursor) != NULL) {
      FAIL("should return NULL");
    } else {
      PASS();
    }
  }
  {
    seed_registry();
    /* single-path entry (e[2], num_paths=1) with mp=1 → rejected */
    static const uint8_t kp_sp_mp1[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x56, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, /* mp=1 on
                                                                 single-path
                                                                 descriptor */
        0x03, 0x00, 0x00, 0x00,
    };
    size_t cursor = 0;
    TEST("single-path entry with mp=1");
    if (registry_match_keypath(kp_sp_mp1, sizeof kp_sp_mp1, &cursor) != NULL) {
      FAIL("should return NULL");
    } else {
      PASS();
    }
  }
  {
    seed_registry();
    /* multipath entry (e[1], num_paths=2) with mp=1 → accepted */
    static const uint8_t kp_mp_mp1[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x30, 0x00, 0x00, 0x80, /* 48' */
        0x00, 0x00, 0x00, 0x80,                         /* 0' */
        0x00, 0x00, 0x00, 0x80,                         /* 0' */
        0x02, 0x00, 0x00, 0x80,                         /* 2' */
        0x01, 0x00, 0x00, 0x00,                         /* mp=1 */
        0x07, 0x00, 0x00, 0x00,                         /* ix=7 */
    };
    size_t cursor = 0;
    TEST("multipath entry with mp=1");
    registry_entry_t *r =
        registry_match_keypath(kp_mp_mp1, sizeof kp_mp_mp1, &cursor);
    if (!r) {
      FAIL("returned NULL");
    } else if (strncmp(r->id, "e1", 2) != 0) {
      FAIL("wrong entry");
    } else {
      PASS();
    }
  }

  /* --- Group 6: cursor pagination --- */
  printf("\n--- Group 6: cursor pagination ---\n");
  {
    seed_registry();
    static const uint8_t kp[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0x56, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    };
    size_t cursor = 0;
    TEST("first call returns e[2]");
    registry_entry_t *r = registry_match_keypath(kp, sizeof kp, &cursor);
    if (!r || strncmp(r->id, "e2", 2) != 0) {
      FAIL("expected e2");
    } else {
      PASS();
    }

    TEST("second call (cursor=3) returns NULL");
    registry_entry_t *r2 = registry_match_keypath(kp, sizeof kp, &cursor);
    if (r2 != NULL) {
      FAIL("expected NULL after last entry");
    } else {
      PASS();
    }
  }

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
