#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <wally_address.h>
#include <wally_core.h>
#include <wally_descriptor.h>

#include "core/address_match.h"
#include "core/key.h"

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

/* Counts script generations, to pin how much of a wallet a sweep walks. */
static size_t to_script_calls = 0;
int __real_wally_descriptor_to_script(const struct wally_descriptor *desc,
                                      uint32_t depth, uint32_t index,
                                      uint32_t variant, uint32_t multi_index,
                                      uint32_t child_num, uint32_t flags,
                                      unsigned char *bytes_out, size_t len,
                                      size_t *written);
int __wrap_wally_descriptor_to_script(const struct wally_descriptor *desc,
                                      uint32_t depth, uint32_t index,
                                      uint32_t variant, uint32_t multi_index,
                                      uint32_t child_num, uint32_t flags,
                                      unsigned char *bytes_out, size_t len,
                                      size_t *written) {
  to_script_calls++;
  return __real_wally_descriptor_to_script(desc, depth, index, variant,
                                           multi_index, child_num, flags,
                                           bytes_out, len, written);
}

static const char *TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

/* sh(wsh(sortedmulti)) with keys from other seeds; receive #46 below. */
static const char *SHWSH_DESC =
    "sh(wsh(sortedmulti(2,"
    "[5bf9f809/48h/0h/0h/1h]xpub6E6EsYCLtbWuL8pnpVKamSTLGw2DqZ7WkdgiFBuxZmuLNnn"
    "g6KVv1b3M6K4HWnMDED9TCNaM4VnjyKiCG1ziwtp2dZvWSwqhsPDYmZHQKeT/<0;1>/*,"
    "[301682c5/48h/0h/0h/1h]xpub6EPzE2wqkpe2ocFEB2NkXYhKJb2hniTmMWF9MDm1fYS3Sy"
    "SXJKmYEgjmKDJxN6Wt1aDJPgx9onFZFtCnbJZQnN2t5o6Eckir5fYB57nneWC/<0;1>/*,"
    "[94ceb1b6/48h/0h/0h/1h]xpub6F8mC76Kbo69gD379rdasDfkSqGrWd4ScK944mPTrYWMt3"
    "kUwcDooawGsZhymFSELtr2DcpHrD6aVcgoBw6UB8GmKG4UYqthsSytnp3QChB/<0;1>/*)))";

static bool find_singlesig(ss_script_type_t script, const char *address,
                           address_match_t *match, bool *decoded) {
  uint8_t spk[ADDRESS_MATCH_SPK_MAX];
  size_t spk_len = 0;
  *decoded = address_match_decode(address, false, spk, sizeof(spk), &spk_len);
  return *decoded &&
         address_match_singlesig(script, 0, false, spk, spk_len, 0, 100, match);
}

static void test_singlesig_base58_case_variant(void) {
  address_match_t m = {0};
  bool decoded = false;

  TEST("BIP44 receive #29 is found");
  if (find_singlesig(SS_SCRIPT_P2PKH, "17NPYLwFXdsJ2DHXHzEhifh6wMKyUQmxRk", &m,
                     &decoded) &&
      m.chain == 0 && m.index == 29)
    PASS();
  else
    FAIL("expected Receive #29");

  /* Same letters in another case, and the base58 checksum still holds: a
   * different hash160, so a different owner. */
  TEST("BIP44 receive #29 case variant is not ours");
  bool found = find_singlesig(
      SS_SCRIPT_P2PKH, "17NPyLwfXdsJ2dHXhZEhifH6WmKYUQMXRk", &m, &decoded);
  if (!decoded)
    FAIL("the variant should be a valid address");
  else if (found)
    FAIL("a case variant must not verify");
  else
    PASS();
}

static void test_singlesig_uppercase_bech32(void) {
  const char *lower = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
  char upper[64];
  size_t n = strlen(lower);
  for (size_t i = 0; i <= n; i++)
    upper[i] = (char)toupper((unsigned char)lower[i]);

  address_match_t m = {0};
  bool decoded = false;
  TEST("BIP84 receive #0 is found in uppercase bech32");
  if (find_singlesig(SS_SCRIPT_P2WPKH, upper, &m, &decoded) && m.chain == 0 &&
      m.index == 0)
    PASS();
  else
    FAIL("expected Receive #0");
}

static void test_wrong_network_rejected(void) {
  uint8_t spk[ADDRESS_MATCH_SPK_MAX];
  size_t spk_len = 0;
  const char *testnet = "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl";
  TEST("testnet address does not decode on mainnet");
  if (!address_match_decode(testnet, true, spk, sizeof(spk), &spk_len))
    FAIL("should decode on testnet");
  else if (address_match_decode(testnet, false, spk, sizeof(spk), &spk_len))
    FAIL("expected a network mismatch");
  else
    PASS();
}

static bool find_descriptor(const struct wally_descriptor *desc,
                            const char *address, address_match_t *match,
                            bool *decoded) {
  uint8_t spk[ADDRESS_MATCH_SPK_MAX];
  size_t spk_len = 0;
  *decoded = address_match_decode(address, false, spk, sizeof(spk), &spk_len);
  return *decoded &&
         address_match_descriptor(desc, 2, spk, spk_len, 0, 100, match);
}

static void test_descriptor_base58_case_variant(void) {
  struct wally_descriptor *desc = NULL;
  TEST("sh(wsh(sortedmulti)) parses");
  if (wally_descriptor_parse(SHWSH_DESC, NULL, WALLY_NETWORK_BITCOIN_MAINNET, 0,
                             &desc) != WALLY_OK) {
    FAIL("parse");
    return;
  }
  PASS();

  address_match_t m = {0};
  bool decoded = false;
  TEST("sh(wsh(sortedmulti)) receive #46 is found");
  if (find_descriptor(desc, "3KTeTNE5p6Sc3AYaDgFRfpBzrqkdvKuhg3", &m,
                      &decoded) &&
      m.chain == 0 && m.index == 46)
    PASS();
  else
    FAIL("expected Receive #46");

  TEST("sh(wsh(sortedmulti)) receive #46 case variant is not ours");
  bool found =
      find_descriptor(desc, "3KTetnE5p6sc3aYADGFrfpBzrqkDvkuhG3", &m, &decoded);
  if (!decoded)
    FAIL("the variant should be a valid address");
  else if (found)
    FAIL("a case variant must not verify");
  else
    PASS();

  wally_descriptor_free(desc);
}

/* A single-path descriptor has no change branch: sweeping "change" would
 * regenerate the receive addresses a second time. */
static void test_single_path_sweeps_receive_only(void) {
  const char *single =
      "wsh(sortedmulti(2,"
      "[5bf9f809/48h/0h/0h/1h]xpub6E6EsYCLtbWuL8pnpVKamSTLGw2DqZ7WkdgiFBuxZmuLN"
      "nng6KVv1b3M6K4HWnMDED9TCNaM4VnjyKiCG1ziwtp2dZvWSwqhsPDYmZHQKeT/0/*,"
      "[301682c5/48h/0h/0h/1h]xpub6EPzE2wqkpe2ocFEB2NkXYhKJb2hniTmMWF9MDm1fYS3"
      "SySXJKmYEgjmKDJxN6Wt1aDJPgx9onFZFtCnbJZQnN2t5o6Eckir5fYB57nneWC/0/*))";
  struct wally_descriptor *desc = NULL;
  TEST("single-path descriptor: a miss walks only receive addresses");
  if (wally_descriptor_parse(single, NULL, WALLY_NETWORK_BITCOIN_MAINNET, 0,
                             &desc) != WALLY_OK) {
    FAIL("parse");
    return;
  }
  const uint8_t spk[22] = {0x00, 0x14};
  address_match_t m;
  to_script_calls = 0;
  bool found = address_match_descriptor(desc, 1, spk, sizeof(spk), 0, 10, &m);
  size_t single_calls = to_script_calls;
  to_script_calls = 0;
  bool found2 = address_match_descriptor(desc, 2, spk, sizeof(spk), 0, 10, &m);
  wally_descriptor_free(desc);
  if (found || found2)
    FAIL("nothing should match");
  else if (single_calls != 10)
    FAIL("expected 10 generations for a single-path miss");
  else if (to_script_calls != 20)
    FAIL("expected 20 generations for a two-path miss");
  else
    PASS();
}

int main(void) {
  printf("=== address_match tests ===\n\n");

  if (!key_load_from_mnemonic(TEST_MNEMONIC, "", false)) {
    printf("ABORT: failed to load mnemonic\n");
    return 1;
  }

  test_singlesig_base58_case_variant();
  test_singlesig_uppercase_bech32();
  test_wrong_network_rejected();
  test_descriptor_base58_case_variant();
  test_single_path_sweeps_receive_only();

  key_unload();

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
