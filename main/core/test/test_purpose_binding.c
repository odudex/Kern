#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wally_descriptor.h>

/* Pull in full implementation directly */
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

/* Account-level xpubs derived at m/84'/0'/0' and m/86'/0'/0' for the
 * standard BIP39 test mnemonic "abandon...about", empty passphrase.
 * These are depth-3 mainnet xpubs as required by wally_descriptor_parse. */
#define XPUB_84                                                                \
  "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvP"               \
  "EbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
#define XPUB_86                                                                \
  "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWc"                \
  "LteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"

/* ---- Group 1: purpose_script_binding_check_strict ---- */

static void test_strict(const char *name, uint32_t purpose,
                        ss_script_type_t script, bool expected) {
  TEST(name);
  bool got = purpose_script_binding_check_strict(purpose, script);
  if (got != expected)
    FAIL(expected ? "expected true, got false" : "expected false, got true");
  else
    PASS();
}

/* ---- Group 2: purpose_script_binding_check_soft ---- */

static void test_soft(const char *name, const char *descriptor_str,
                      psb_result_t expected) {
  TEST(name);
  struct wally_descriptor *desc = NULL;
  if (wally_descriptor_parse(descriptor_str, NULL, WALLY_NETWORK_NONE, 0,
                             &desc) != WALLY_OK) {
    FAIL("wally_descriptor_parse failed");
    return;
  }
  psb_result_t got = purpose_script_binding_check_soft(desc);
  wally_descriptor_free(desc);
  if (got != expected) {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected %d, got %d", (int)expected, (int)got);
    FAIL(msg);
  } else {
    PASS();
  }
}

int main(void) {
  printf("=== purpose_script_binding tests ===\n\n");

  printf("--- Group 1: purpose_script_binding_check_strict ---\n");
  /* Matching pairs → true */
  test_strict("44 + P2PKH        → true", 44, SS_SCRIPT_P2PKH, true);
  test_strict("49 + P2SH_P2WPKH  → true", 49, SS_SCRIPT_P2SH_P2WPKH, true);
  test_strict("84 + P2WPKH       → true", 84, SS_SCRIPT_P2WPKH, true);
  test_strict("86 + P2TR         → true", 86, SS_SCRIPT_P2TR, true);
  /* Cross pairs → false */
  test_strict("84 + P2TR  (mismatch) → false", 84, SS_SCRIPT_P2TR, false);
  test_strict("86 + P2WPKH mismatch → false", 86, SS_SCRIPT_P2WPKH, false);
  test_strict("44 + P2WPKH mismatch → false", 44, SS_SCRIPT_P2WPKH, false);
  /* Unknown purpose → false */
  test_strict("48 + P2WPKH (no whitelist entry) → false", 48, SS_SCRIPT_P2WPKH,
              false);
  test_strict("99 + P2PKH (unknown purpose)     → false", 99, SS_SCRIPT_P2PKH,
              false);

  printf("\n--- Group 2: purpose_script_binding_check_soft ---\n");

  /* WARN: wsh outer but purpose 86 (convention: tr) */
  test_soft("wsh/purpose-86 → WARN",
            "wsh(sortedmulti(2,[00000000/86'/0'/0']" XPUB_86 "," XPUB_84 "))",
            PSB_WARN);

  /* WARN: tr outer but purpose 84 (convention: wpkh) */
  test_soft("tr/purpose-84 → WARN", "tr([00000000/84'/0'/0']" XPUB_84 ")",
            PSB_WARN);

  /* OK: wpkh outer, purpose 84 (matches convention) */
  test_soft("wpkh/purpose-84 → OK", "wpkh([00000000/84'/0'/0']" XPUB_84 ")",
            PSB_OK);

  /* NA: wpkh outer, purpose 99 (not in {44,48,49,84,86}) */
  test_soft("wpkh/purpose-99 → NA", "wpkh([00000000/99'/0'/0']" XPUB_84 ")",
            PSB_NA);

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
