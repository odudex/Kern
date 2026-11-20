#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_core.h>
#include <wally_descriptor.h>

#include "core/address_match.h"
#include "core/key.h"
#include "core/wallet.h"

wallet_network_t wallet_get_network(void) { return WALLET_NETWORK_MAINNET; }

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

/* Counts script generations past child 0, to pin how much of a wallet a sweep
 * walks; a per-branch copy is checked at child 0 before a sweep uses it. */
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
  if (child_num > 0)
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
  else if (single_calls != 9)
    FAIL("expected 9 generations past child 0 for a single-path miss");
  else if (to_script_calls != 18)
    FAIL("expected 18 generations past child 0 for a two-path miss");
  else
    PASS();
}

/* BIP173 and BIP350 testnet vectors, and their bcrt forms: the same witness
 * program re-encoded with the reference bech32 implementation */
static const char TESTNET_P2WSH[] =
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
static const char REGTEST_P2WSH[] =
    "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry";
static const char TESTNET_P2TR[] =
    "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c";
static const char REGTEST_P2TR[] =
    "bcrt1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesyga46z";

static void expect_regtest_form(const char *name, const char *testnet,
                                const char *regtest) {
  char *out = NULL;
  TEST(name);
  if (address_match_regtest_alloc(testnet, &out) && strcmp(out, regtest) == 0)
    PASS();
  else
    FAIL(out ? out : "no regtest address");
  free(out);
}

static void test_regtest_forms(void) {
  expect_regtest_form("a testnet P2WSH address re-encodes under bcrt",
                      TESTNET_P2WSH, REGTEST_P2WSH);
  expect_regtest_form("a testnet P2TR address re-encodes under bcrt (bech32m)",
                      TESTNET_P2TR, REGTEST_P2TR);

  char *out = NULL;
  TEST("a mainnet or base58 address has no regtest form");
  if (!address_match_regtest_alloc("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                                   &out) &&
      !address_match_regtest_alloc("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
                                   &out) &&
      out == NULL)
    PASS();
  else
    FAIL("regtest form of a non testnet segwit address");
  free(out);
}

static void test_regtest_decode(void) {
  uint8_t regtest[ADDRESS_MATCH_SPK_MAX], testnet[ADDRESS_MATCH_SPK_MAX];
  size_t regtest_len = 0, testnet_len = 0;

  TEST("a bcrt address decodes to its testnet twin's scriptPubKey");
  if (address_match_decode_regtest(REGTEST_P2TR, regtest, sizeof(regtest),
                                   &regtest_len) &&
      address_match_decode(TESTNET_P2TR, true, testnet, sizeof(testnet),
                           &testnet_len) &&
      regtest_len == testnet_len && memcmp(regtest, testnet, regtest_len) == 0)
    PASS();
  else
    FAIL("scriptPubKeys differ");

  TEST("only a bcrt address decodes as regtest");
  if (!address_match_decode_regtest(TESTNET_P2TR, regtest, sizeof(regtest),
                                    &regtest_len) &&
      !address_match_decode_regtest(
          "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", regtest,
          sizeof(regtest), &regtest_len))
    PASS();
  else
    FAIL("a non regtest address decoded");
}

int main(void) {
  /* The host libwally hashes through PSA, as the device does, which needs
   * wally_init. */
  if (wally_init(0) != WALLY_OK) {
    printf("ABORT: wally_init failed\n");
    return 1;
  }
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
  test_regtest_forms();
  test_regtest_decode();

  key_unload();

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
