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
 * key_get_fingerprint stub returns {0x00,0x00,0x00,0x00}, so descriptors
 * with origin fingerprint 00000000 match our wallet. */
#define XPUB_84                                                                \
  "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvP"               \
  "EbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
#define XPUB_86                                                                \
  "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWc"                \
  "LteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"

int main(void) {
  printf("=== registry_add_from_string parse tests ===\n\n");

  /* --- Group 1: wpkh multipath --- */
  printf("--- Group 1: wpkh multipath ---\n");
  {
    registry_clear();
    bool ok = registry_add_from_string(
        "wpkh_test", "wpkh([00000000/84'/0'/0']" XPUB_84 "/<0;1>/*)#d9qwe873",
        STORAGE_FLASH, false);

    TEST("wpkh: add returns true");
    if (ok) {
      PASS();
    } else {
      FAIL("returned false");
    }

    TEST("wpkh: count == 1");
    if (registry_count() == 1) {
      PASS();
    } else {
      FAIL("wrong count");
    }

    const registry_entry_t *e = registry_find_by_id("wpkh_test");
    TEST("wpkh: entry found");
    if (e) {
      PASS();
    } else {
      FAIL("entry not found");
      goto skip_wpkh;
    }

    TEST("wpkh: my_key_index == 0");
    if (e->my_key_index == 0) {
      PASS();
    } else {
      FAIL("wrong key index");
    }

    TEST("wpkh: num_paths == 2");
    if (e->num_paths == 2) {
      PASS();
    } else {
      FAIL("wrong num_paths");
    }

    TEST("wpkh: origin depth == 3");
    if (e->origin_path_len == 3) {
      PASS();
    } else {
      FAIL("wrong depth");
    }

    TEST("wpkh: origin path[0] == 84'");
    if (e->origin_path[0] == 0x80000054u) {
      PASS();
    } else {
      FAIL("wrong path[0]");
    }

    TEST("wpkh: origin path[1] == 0'");
    if (e->origin_path[1] == 0x80000000u) {
      PASS();
    } else {
      FAIL("wrong path[1]");
    }

    TEST("wpkh: origin path[2] == 0'");
    if (e->origin_path[2] == 0x80000000u) {
      PASS();
    } else {
      FAIL("wrong path[2]");
    }

  skip_wpkh:;
  }

  /* --- Group 2: wsh(sortedmulti) --- */
  printf("\n--- Group 2: wsh(sortedmulti) ---\n");
  {
    registry_clear();
    bool ok = registry_add_from_string("sm_test",
                                       "wsh(sortedmulti(2,"
                                       "[00000000/48'/0'/0'/2']" XPUB_84 "/0/*,"
                                       "[11111111/48'/0'/0'/2']" XPUB_86 "/0/*"
                                       "))#6nfc46dh",
                                       STORAGE_FLASH, false);

    TEST("sortedmulti: add returns true");
    if (ok) {
      PASS();
    } else {
      FAIL("returned false");
    }

    TEST("sortedmulti: count == 1");
    if (registry_count() == 1) {
      PASS();
    } else {
      FAIL("wrong count");
    }

    const registry_entry_t *e = registry_find_by_id("sm_test");
    TEST("sortedmulti: entry found");
    if (e) {
      PASS();
    } else {
      FAIL("entry not found");
      goto skip_sm;
    }

    TEST("sortedmulti: my_key_index == 0");
    if (e->my_key_index == 0) {
      PASS();
    } else {
      FAIL("wrong key index");
    }

    TEST("sortedmulti: num_paths == 1");
    if (e->num_paths == 1) {
      PASS();
    } else {
      FAIL("wrong num_paths");
    }

    TEST("sortedmulti: origin depth == 4");
    if (e->origin_path_len == 4) {
      PASS();
    } else {
      FAIL("wrong depth");
    }

    TEST("sortedmulti: origin path[0] == 48'");
    if (e->origin_path[0] == 0x80000030u) {
      PASS();
    } else {
      FAIL("wrong path[0]");
    }

    TEST("sortedmulti: origin path[1] == 0'");
    if (e->origin_path[1] == 0x80000000u) {
      PASS();
    } else {
      FAIL("wrong path[1]");
    }

    TEST("sortedmulti: origin path[2] == 0'");
    if (e->origin_path[2] == 0x80000000u) {
      PASS();
    } else {
      FAIL("wrong path[2]");
    }

    TEST("sortedmulti: origin path[3] == 2'");
    if (e->origin_path[3] == 0x80000002u) {
      PASS();
    } else {
      FAIL("wrong path[3]");
    }

  skip_sm:;
  }

  /* --- Group 3: tr (taproot, multipath) --- */
  printf("\n--- Group 3: tr (taproot, multipath) ---\n");
  {
    registry_clear();
    bool ok = registry_add_from_string(
        "tr_test", "tr([00000000/86'/0'/0']" XPUB_86 "/<0;1>/*)#wpff3yhl",
        STORAGE_FLASH, false);

    TEST("tr: add returns true");
    if (ok) {
      PASS();
    } else {
      FAIL("returned false");
    }

    TEST("tr: count == 1");
    if (registry_count() == 1) {
      PASS();
    } else {
      FAIL("wrong count");
    }

    const registry_entry_t *e = registry_find_by_id("tr_test");
    TEST("tr: entry found");
    if (e) {
      PASS();
    } else {
      FAIL("entry not found");
      goto skip_tr;
    }

    TEST("tr: my_key_index == 0");
    if (e->my_key_index == 0) {
      PASS();
    } else {
      FAIL("wrong key index");
    }

    TEST("tr: num_paths == 2");
    if (e->num_paths == 2) {
      PASS();
    } else {
      FAIL("wrong num_paths");
    }

    TEST("tr: origin depth == 3");
    if (e->origin_path_len == 3) {
      PASS();
    } else {
      FAIL("wrong depth");
    }

    TEST("tr: origin path[0] == 86'");
    if (e->origin_path[0] == 0x80000056u) {
      PASS();
    } else {
      FAIL("wrong path[0]");
    }

    TEST("tr: origin path[1] == 0'");
    if (e->origin_path[1] == 0x80000000u) {
      PASS();
    } else {
      FAIL("wrong path[1]");
    }

    TEST("tr: origin path[2] == 0'");
    if (e->origin_path[2] == 0x80000000u) {
      PASS();
    } else {
      FAIL("wrong path[2]");
    }

  skip_tr:;
  }

  /* --- Group 4: wsh(miniscript) --- */
  printf("\n--- Group 4: wsh(miniscript) ---\n");
  {
    registry_clear();
    bool ok = registry_add_from_string(
        "ms_test",
        "wsh(and_v(v:pk([00000000/84'/0'/0']" XPUB_84 "/0/*),"
        "pk([11111111/84'/0'/0']" XPUB_86 "/0/*)))#drgmlfhn",
        STORAGE_FLASH, false);

    TEST("miniscript: add returns true");
    if (ok) {
      PASS();
    } else {
      FAIL("returned false");
    }

    TEST("miniscript: count == 1");
    if (registry_count() == 1) {
      PASS();
    } else {
      FAIL("wrong count");
    }

    const registry_entry_t *e = registry_find_by_id("ms_test");
    TEST("miniscript: entry found");
    if (e) {
      PASS();
    } else {
      FAIL("entry not found");
      goto skip_ms;
    }

    TEST("miniscript: my_key_index == 0");
    if (e->my_key_index == 0) {
      PASS();
    } else {
      FAIL("wrong key index");
    }

    TEST("miniscript: num_paths == 1");
    if (e->num_paths == 1) {
      PASS();
    } else {
      FAIL("wrong num_paths");
    }

    TEST("miniscript: origin depth == 3");
    if (e->origin_path_len == 3) {
      PASS();
    } else {
      FAIL("wrong depth");
    }

    TEST("miniscript: origin path[0] == 84'");
    if (e->origin_path[0] == 0x80000054u) {
      PASS();
    } else {
      FAIL("wrong path[0]");
    }

    TEST("miniscript: origin path[1] == 0'");
    if (e->origin_path[1] == 0x80000000u) {
      PASS();
    } else {
      FAIL("wrong path[1]");
    }

    TEST("miniscript: origin path[2] == 0'");
    if (e->origin_path[2] == 0x80000000u) {
      PASS();
    } else {
      FAIL("wrong path[2]");
    }

  skip_ms:;
  }

  /* --- Group 5: negative: fingerprint not found --- */
  printf("\n--- Group 5: negative: fingerprint not found ---\n");
  {
    registry_clear();
    bool ok = registry_add_from_string(
        "no_match", "wpkh([11111111/84'/0'/0']" XPUB_84 "/0/*)#cmnyxe9f",
        STORAGE_FLASH, false);

    TEST("no match: returns false");
    if (!ok) {
      PASS();
    } else {
      FAIL("should have returned false");
    }

    TEST("no match: count == 0");
    if (registry_count() == 0) {
      PASS();
    } else {
      FAIL("count should be 0");
    }
  }

  /* --- Group 6: negative: malformed checksum --- */
  printf("\n--- Group 6: negative: malformed checksum ---\n");
  {
    registry_clear();
    /* d9qwe873 is the correct checksum for the wpkh descriptor; flipping
     * one character must cause libwally to reject the descriptor. */
    bool ok = registry_add_from_string(
        "bad_cksum", "wpkh([00000000/84'/0'/0']" XPUB_84 "/<0;1>/*)#d9qwe874",
        STORAGE_FLASH, false);

    TEST("bad checksum: returns false");
    if (!ok) {
      PASS();
    } else {
      FAIL("should have rejected bad checksum");
    }

    TEST("bad checksum: count == 0");
    if (registry_count() == 0) {
      PASS();
    } else {
      FAIL("count should be 0");
    }
  }

  /* --- Group 7: negative: truncated descriptor --- */
  printf("\n--- Group 7: negative: truncated descriptor ---\n");
  {
    registry_clear();
    /* Cut mid-key — libwally will reject. */
    bool ok = registry_add_from_string(
        "trunc", "wpkh([00000000/84'/0'/0']xpub6CatWdiZiodmU", STORAGE_FLASH,
        false);

    TEST("truncated: returns false");
    if (!ok) {
      PASS();
    } else {
      FAIL("should have rejected truncated descriptor");
    }

    TEST("truncated: count == 0");
    if (registry_count() == 0) {
      PASS();
    } else {
      FAIL("count should be 0");
    }
  }

  /* --- Group 8: negative: empty / NULL descriptor --- */
  printf("\n--- Group 8: negative: empty / NULL descriptor ---\n");
  {
    registry_clear();
    bool ok_empty = registry_add_from_string("empty", "", STORAGE_FLASH, false);

    TEST("empty desc: returns false");
    if (!ok_empty) {
      PASS();
    } else {
      FAIL("should have rejected empty descriptor");
    }

    bool ok_null = registry_add_from_string("null", NULL, STORAGE_FLASH, false);

    TEST("null desc: returns false");
    if (!ok_null) {
      PASS();
    } else {
      FAIL("should have rejected NULL descriptor");
    }

    TEST("empty/null: count == 0");
    if (registry_count() == 0) {
      PASS();
    } else {
      FAIL("count should be 0");
    }
  }

  /* --- Group 9: negative: oversize origin path --- */
  printf("\n--- Group 9: negative: oversize origin path ---\n");
  {
    registry_clear();
    /* Origin depth 7 (84'/0'/0'/0'/0'/0'/0') > MAX_KEYPATH_ORIGIN_DEPTH (6).
     * Even if libwally accepts the BIP32 string, registry parsing must
     * reject the oversize origin. */
    bool ok = registry_add_from_string(
        "oversize", "wpkh([00000000/84'/0'/0'/0'/0'/0'/0']" XPUB_84 "/0/*)",
        STORAGE_FLASH, false);

    TEST("oversize origin: returns false");
    if (!ok) {
      PASS();
    } else {
      FAIL("should have rejected oversize origin path");
    }

    TEST("oversize origin: count == 0");
    if (registry_count() == 0) {
      PASS();
    } else {
      FAIL("count should be 0");
    }
  }

  /* --- Group 10: long id is truncated (REGISTRY_ID_MAX_LEN-1) --- */
  printf("\n--- Group 10: long id truncation ---\n");
  {
    registry_clear();
    const char *desc = "wpkh([00000000/84'/0'/0']" XPUB_84 "/<0;1>/*)#d9qwe873";
    /* 32-char id + extra; should be truncated to REGISTRY_ID_MAX_LEN-1 and
     * still succeed without buffer overflow. */
    const char *long_id = "abcdefghij_abcdefghij_abcdefghij_overflow_tail";

    TEST("long id: add returns true");
    if (registry_add_from_string(long_id, desc, STORAGE_FLASH, false)) {
      PASS();
    } else {
      FAIL("long id add failed");
    }

    TEST("long id: count == 1");
    if (registry_count() == 1) {
      PASS();
    } else {
      FAIL("count != 1");
    }
  }

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
