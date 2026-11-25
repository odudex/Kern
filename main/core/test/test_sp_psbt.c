#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <wally_core.h>
#include <wally_map.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

#include "bip375_fixture.h"
#include "core/dleq.h"
#include "core/key.h"
#include "core/psbt.h"
#include "core/silent_payments.h"
#include "core/sp_psbt.h"
#include "sp_fixture.h"

// libwally keeps these input fields in psbt_fields
#define PSBT_IN_REDEEM_SCRIPT 0x04
#define PSBT_IN_TAP_MERKLE_ROOT 0x18

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

static const char *TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

/* BIP352 receiving vectors' scan secret, whose public key is RECIPIENT_SCAN,
 * and our spend key labeled with it with m = 0 and m = 3 */
static const char RECIPIENT_SCAN_SECRET[] =
    "0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c";
static const char RECIPIENT_SCAN_SPEND_LABEL_0[] =
    "02e673195a3b1a0c7cdfdde5649e6e13be05d01791be238329bb58fdb3ea386f56";
static const char RECIPIENT_SCAN_SPEND_LABEL_3[] =
    "039a85d8ee2d462711a2f76c45d84243634a445caa32f2509f181101ba23eb24da";

static const unsigned char SCALAR_ONE[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

static bool hex_to(const char *hex, unsigned char *out, size_t len) {
  size_t written;
  return wally_hex_to_bytes(hex, out, len, &written) == WALLY_OK &&
         written == len;
}

static struct wally_psbt *parse_hex(const char *hex) {
  size_t len = strlen(hex) / 2, written = 0;
  unsigned char *bytes = malloc(len);
  struct wally_psbt *psbt = NULL;
  if (!bytes || wally_hex_to_bytes(hex, bytes, len, &written) != WALLY_OK ||
      !psbt_parse_payload(bytes, written, &psbt))
    psbt = NULL;
  free(bytes);
  return psbt;
}

static bool script_is(const struct wally_psbt *psbt, size_t index,
                      const char *hex) {
  unsigned char expected[34];
  const struct wally_psbt_output *out = &psbt->outputs[index];
  return hex_to(hex, expected, sizeof(expected)) && out->script &&
         out->script_len == sizeof(expected) &&
         memcmp(out->script, expected, sizeof(expected)) == 0;
}

static const struct wally_map_item *find_scan_field(const struct wally_map *map,
                                                    unsigned char type,
                                                    const char *scan_hex) {
  unsigned char key[1 + SP_PUBKEY_LEN];
  size_t index = 0;
  key[0] = type;
  if (!hex_to(scan_hex, key + 1, SP_PUBKEY_LEN) ||
      wally_map_find(map, key, sizeof(key), &index) != WALLY_OK || !index)
    return NULL;
  return &map->items[index - 1];
}

static bool share_is(const struct wally_psbt *psbt, const char *scan_hex,
                     const char *share_hex) {
  unsigned char expected[SP_PUBKEY_LEN];
  const struct wally_map_item *item =
      find_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_ECDH_SHARE, scan_hex);
  return item && hex_to(share_hex, expected, sizeof(expected)) &&
         item->value_len == sizeof(expected) &&
         memcmp(item->value, expected, sizeof(expected)) == 0;
}

static bool parse_point(const char *hex, secp256k1_pubkey *out) {
  unsigned char bytes[SP_PUBKEY_LEN];
  return hex_to(hex, bytes, sizeof(bytes)) &&
         secp256k1_ec_pubkey_parse(wally_get_secp_context(), out, bytes,
                                   sizeof(bytes)) == 1;
}

static bool proof_verifies(const struct wally_psbt *psbt,
                           const char *input_key_hex, const char *scan_hex,
                           const char *share_hex) {
  secp256k1_pubkey input_key, scan, share, generator;
  const struct wally_map_item *proof =
      find_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_DLEQ, scan_hex);
  return proof && proof->value_len == DLEQ_PROOF_LEN &&
         parse_point(input_key_hex, &input_key) &&
         parse_point(scan_hex, &scan) && parse_point(share_hex, &share) &&
         secp256k1_ec_pubkey_create(wally_get_secp_context(), &generator,
                                    SCALAR_ONE) &&
         dleq_verify(&input_key, &scan, &share, proof->value, &generator, NULL);
}

static void test_parse(void) {
  unsigned char bytes[1024];
  size_t written = 0;
  struct wally_psbt *strict = NULL;
  struct wally_psbt *psbt = parse_hex(UNSIGNED_PSBT);

  TEST("psbt_parse_payload accepts scriptless silent payment outputs");
  if (psbt && sp_psbt_outputs_pending(psbt) &&
      wally_hex_to_bytes(UNSIGNED_PSBT, bytes, sizeof(bytes), &written) ==
          WALLY_OK &&
      wally_psbt_from_bytes(bytes, written, WALLY_PSBT_PARSE_FLAG_COMPLETE,
                            &strict) != WALLY_OK)
    PASS();
  else
    FAIL("scriptless silent payment outputs rejected");

  TEST("a scriptless output without PSBT_OUT_SP_V0_INFO is not pending");
  unsigned char info_key = PSBT_OUT_SP_V0_INFO;
  if (psbt &&
      wally_map_remove(&psbt->outputs[0].unknowns, &info_key, 1) == WALLY_OK &&
      !sp_psbt_outputs_pending(psbt))
    PASS();
  else
    FAIL("output without info counted as pending");
  wally_psbt_free(strict);
  wally_psbt_free(psbt);
}

static void test_complete(void) {
  struct wally_psbt *psbt = parse_hex(UNSIGNED_PSBT);
  size_t flags = 1;

  TEST("sp_psbt_complete writes bwk's output scripts");
  if (psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_OK &&
      script_is(psbt, 0, EXPECTED_SCRIPT_0) &&
      script_is(psbt, 1, EXPECTED_SCRIPT_1))
    PASS();
  else
    FAIL("output scripts differ from bwk");

  TEST("sp_psbt_complete writes bwk's global ECDH shares");
  if (psbt && share_is(psbt, RECIPIENT_SCAN, RECIPIENT_SHARE) &&
      share_is(psbt, OUR_SCAN, OUR_SHARE))
    PASS();
  else
    FAIL("global shares differ from bwk");

  TEST("each global DLEQ proof verifies against the input key");
  if (psbt &&
      proof_verifies(psbt, INPUT_KEY, RECIPIENT_SCAN, RECIPIENT_SHARE) &&
      proof_verifies(psbt, INPUT_KEY, OUR_SCAN, OUR_SHARE))
    PASS();
  else
    FAIL("DLEQ proof does not verify");

  TEST("sp_psbt_complete freezes the transaction");
  if (psbt && wally_psbt_get_tx_modifiable_flags(psbt, &flags) == WALLY_OK &&
      flags == 0)
    PASS();
  else
    FAIL("tx_modifiable not frozen");

  struct wally_psbt *trimmed = NULL;
  unsigned char tx_modifiable = 0x06;
  size_t index = 0;
  TEST("sp_psbt_copy_fields keeps the BIP375 fields and a frozen "
       "TX_MODIFIABLE");
  if (psbt && wally_psbt_clone_alloc(psbt, 0, &trimmed) == WALLY_OK &&
      wally_map_clear(&trimmed->unknowns) == WALLY_OK &&
      wally_map_clear(&trimmed->outputs[0].unknowns) == WALLY_OK &&
      sp_psbt_copy_fields(psbt, trimmed) &&
      share_is(trimmed, RECIPIENT_SCAN, RECIPIENT_SHARE) &&
      find_scan_field(&trimmed->unknowns, PSBT_GLOBAL_SP_DLEQ, OUR_SCAN) &&
      sp_psbt_has_outputs(trimmed) &&
      wally_map_find(&trimmed->unknowns, &tx_modifiable, 1, &index) ==
          WALLY_OK &&
      index && trimmed->unknowns.items[index - 1].value_len == 1 &&
      trimmed->unknowns.items[index - 1].value[0] == 0)
    PASS();
  else
    FAIL("BIP375 fields dropped");
  wally_psbt_free(trimmed);
  wally_psbt_free(psbt);
}

// `share` holds `scan_hex`, `share_hex` and the proof `map` keeps for it
static bool share_entry_is(const sp_share_t *share, const struct wally_map *map,
                           unsigned char proof_type, const char *scan_hex,
                           const char *share_hex) {
  unsigned char scan[SP_PUBKEY_LEN], expected[SP_PUBKEY_LEN];
  const struct wally_map_item *proof =
      find_scan_field(map, proof_type, scan_hex);
  return proof && hex_to(scan_hex, scan, sizeof(scan)) &&
         hex_to(share_hex, expected, sizeof(expected)) &&
         memcmp(share->scan, scan, sizeof(scan)) == 0 &&
         memcmp(share->share, expected, sizeof(expected)) == 0 &&
         memcmp(share->proof, proof->value, DLEQ_PROOF_LEN) == 0;
}

static bool global_share_is(const sp_share_t *share,
                            const struct wally_psbt *psbt, const char *scan_hex,
                            const char *share_hex) {
  return share->global && share->input_index == 0 &&
         share_entry_is(share, &psbt->unknowns, PSBT_GLOBAL_SP_DLEQ, scan_hex,
                        share_hex);
}

static void test_shares(void) {
  struct wally_psbt *psbt = parse_hex(UNSIGNED_PSBT);
  sp_share_t *shares = NULL;
  size_t count = 0;

  TEST("sp_psbt_shares_alloc fails before the shares are written");
  if (psbt && !sp_psbt_shares_alloc(psbt, false, &shares, &count) && !shares &&
      count == 0)
    PASS();
  else
    FAIL("shares read from an uncompleted PSBT");

  TEST("sp_psbt_shares_alloc reads each scan key's global share and proof in "
       "output order");
  if (psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_OK &&
      sp_psbt_shares_alloc(psbt, false, &shares, &count) && count == 2 &&
      global_share_is(&shares[0], psbt, RECIPIENT_SCAN, RECIPIENT_SHARE) &&
      global_share_is(&shares[1], psbt, OUR_SCAN, OUR_SHARE))
    PASS();
  else
    FAIL("shares differ from the PSBT fields");
  free(shares);
  shares = NULL;

  TEST("sp_psbt_shares_alloc fails when a proof is missing");
  unsigned char proof_key[1 + SP_PUBKEY_LEN] = {PSBT_GLOBAL_SP_DLEQ};
  if (psbt && hex_to(OUR_SCAN, proof_key + 1, SP_PUBKEY_LEN) &&
      wally_map_remove(&psbt->unknowns, proof_key, sizeof(proof_key)) ==
          WALLY_OK &&
      !sp_psbt_shares_alloc(psbt, false, &shares, &count) && !shares)
    PASS();
  else
    FAIL("share without its proof accepted");
  wally_psbt_free(psbt);
}

static void expect_refusal(const char *name, struct wally_psbt *psbt,
                           sp_psbt_result_t expected) {
  TEST(name);
  if (psbt && sp_psbt_complete(&psbt, false) == expected)
    PASS();
  else
    FAIL(sp_psbt_result_message(expected));
  wally_psbt_free(psbt);
}

// Another signer holds an eligible input and has not shared yet: no global
// share, every silent payment output still scriptless
static void expect_waiting(const char *name, struct wally_psbt *psbt) {
  TEST(name);
  if (psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_PENDING &&
      sp_psbt_outputs_pending(psbt) &&
      !find_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_ECDH_SHARE,
                       RECIPIENT_SCAN))
    PASS();
  else
    FAIL("not left waiting for the other signer");
  wally_psbt_free(psbt);
}

static void test_refusals(void) {
  unsigned char tweak_key = PSBT_IN_SP_TWEAK;
  unsigned char info_key = PSBT_OUT_SP_V0_INFO;
  unsigned char wrong_tweak[32], script[34];
  struct wally_psbt *psbt;

  expect_refusal("a foreign key hash input naming no key is refused",
                 parse_hex(FOREIGN_PSBT), SP_PSBT_ERR_INPUT_KEY);

  psbt = parse_hex(UNSIGNED_PSBT);
  if (psbt &&
      wally_psbt_set_input_sighash(psbt, 0, WALLY_SIGHASH_NONE) != WALLY_OK) {
    wally_psbt_free(psbt);
    psbt = NULL;
  }
  expect_refusal("a SIGHASH_NONE input is refused", psbt, SP_PSBT_ERR_SIGHASH);

  memset(wrong_tweak, 0x12, sizeof(wrong_tweak));
  psbt = parse_hex(UNSIGNED_PSBT);
  if (psbt && wally_map_replace(&psbt->inputs[0].unknowns, &tweak_key, 1,
                                wrong_tweak, sizeof(wrong_tweak)) != WALLY_OK) {
    wally_psbt_free(psbt);
    psbt = NULL;
  }
  expect_waiting("an input with a wrong tweak is another signer's", psbt);

  psbt = parse_hex(UNSIGNED_PSBT);
  if (psbt && (!hex_to(EXPECTED_SCRIPT_1, script, sizeof(script)) ||
               wally_psbt_set_output_script(psbt, 0, script, sizeof(script)) !=
                   WALLY_OK)) {
    wally_psbt_free(psbt);
    psbt = NULL;
  }
  expect_refusal("a preset script differing from the derived one is refused",
                 psbt, SP_PSBT_ERR_SCRIPT);

  psbt = parse_hex(UNSIGNED_PSBT);
  if (psbt && wally_map_replace(&psbt->outputs[0].unknowns, &info_key, 1,
                                script, SP_PUBKEY_LEN) != WALLY_OK) {
    wally_psbt_free(psbt);
    psbt = NULL;
  }
  expect_refusal("a short PSBT_OUT_SP_V0_INFO is refused", psbt,
                 SP_PSBT_ERR_FIELD);
}

// Completes `psbt_hex` and checks embit's script, share and proof
static void expect_completion(const char *name, const char *psbt_hex,
                              const char *script, const char *share,
                              const char *input_key) {
  struct wally_psbt *psbt = parse_hex(psbt_hex);
  TEST(name);
  if (psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_OK &&
      script_is(psbt, 0, script) && share_is(psbt, RECIPIENT_SCAN, share) &&
      proof_verifies(psbt, input_key, RECIPIENT_SCAN, share))
    PASS();
  else
    FAIL("output, share or proof differs from embit");
  wally_psbt_free(psbt);
}

static void test_bip352_inputs(void) {
  expect_completion("P2WPKH, P2TR, P2SH-P2WPKH and P2PKH keys are summed",
                    ALL_TYPES_PSBT, ALL_TYPES_SCRIPT, ALL_TYPES_SHARE,
                    ALL_TYPES_INPUT_KEY);
  expect_completion("a P2WPKH input keyed on a BIP86 path is P2WPKH",
                    PATH_IGNORED_PSBT, PATH_IGNORED_SCRIPT, PATH_IGNORED_SHARE,
                    PATH_IGNORED_INPUT_KEY);
  expect_completion("a NUMS input proven by its merkle root is not summed",
                    NUMS_PSBT, NUMS_SCRIPT, NUMS_SHARE, NUMS_INPUT_KEY);
}

// Flips the last byte of an input field libwally keeps in psbt_fields
static bool flip_input_field(struct wally_psbt *psbt, size_t i, uint32_t type) {
  const struct wally_map_item *item =
      wally_map_get_integer(&psbt->inputs[i].psbt_fields, type);
  if (!item || !item->value_len)
    return false;
  item->value[item->value_len - 1] ^= 1;
  return true;
}

static struct wally_psbt *checked(struct wally_psbt *psbt, bool mutated) {
  if (psbt && !mutated) {
    wally_psbt_free(psbt);
    return NULL;
  }
  return psbt;
}

static void test_input_refusals(void) {
  struct wally_psbt *psbt = parse_hex(PATH_IGNORED_PSBT);
  // The origin still names our key, the script now hashes another one
  if (psbt && psbt->inputs[0].witness_utxo)
    psbt->inputs[0].witness_utxo->script[2] ^= 1;
  expect_refusal("a key origin our key not hashed by the script is refused",
                 psbt, SP_PSBT_ERR_INPUT_KEY);

  psbt = parse_hex(ALL_TYPES_PSBT);
  expect_waiting("a P2TR key not reaching the output key is another signer's",
                 checked(psbt, psbt && flip_input_field(
                                           psbt, 2, PSBT_IN_TAP_MERKLE_ROOT)));

  psbt = parse_hex(ALL_TYPES_PSBT);
  expect_refusal(
      "a redeem script not hashing to its script is refused",
      checked(psbt, psbt && flip_input_field(psbt, 3, PSBT_IN_REDEEM_SCRIPT)),
      SP_PSBT_ERR_INPUT);

  psbt = parse_hex(NUMS_PSBT);
  expect_waiting(
      "an unproven NUMS input stays eligible, and is another signer's",
      checked(psbt,
              psbt && flip_input_field(psbt, 1, PSBT_IN_TAP_MERKLE_ROOT)));
}

static bool copy_global_field(const struct wally_psbt *from,
                              struct wally_psbt *to, unsigned char type) {
  for (size_t i = 0; i < from->unknowns.num_items; i++) {
    const struct wally_map_item *item = &from->unknowns.items[i];
    if (item->key_len && item->key[0] == type)
      return wally_map_replace(&to->unknowns, item->key, item->key_len,
                               item->value, item->value_len) == WALLY_OK;
  }
  return false;
}

// UNSIGNED_PSBT holding the share and proof of RECIPIENT_SCAN that a first
// completion wrote
static struct wally_psbt *with_declared_share(void) {
  struct wally_psbt *completed = parse_hex(UNSIGNED_PSBT);
  struct wally_psbt *psbt = parse_hex(UNSIGNED_PSBT);
  bool ok = completed && psbt &&
            sp_psbt_complete(&completed, false) == SP_PSBT_OK &&
            copy_global_field(completed, psbt, PSBT_GLOBAL_SP_ECDH_SHARE) &&
            copy_global_field(completed, psbt, PSBT_GLOBAL_SP_DLEQ);
  wally_psbt_free(completed);
  return checked(psbt, ok);
}

static bool flip_global_field(struct wally_psbt *psbt, unsigned char type) {
  for (size_t i = 0; i < psbt->unknowns.num_items; i++) {
    struct wally_map_item *item = &psbt->unknowns.items[i];
    if (item->key_len && item->key[0] == type) {
      item->value[item->value_len - 1] ^= 1;
      return true;
    }
  }
  return false;
}

static void expect_untouched_refusal(const char *name, struct wally_psbt *psbt,
                                     sp_psbt_result_t expected) {
  struct wally_psbt *before = psbt;
  TEST(name);
  if (psbt && sp_psbt_complete(&psbt, false) == expected && psbt == before &&
      sp_psbt_outputs_pending(psbt))
    PASS();
  else
    FAIL(sp_psbt_result_message(expected));
  wally_psbt_free(psbt);
}

static void test_field_checks(void) {
  struct wally_psbt *psbt = parse_hex(V0_SP_PSBT);
  expect_refusal("silent payment fields in a PSBTv0 are refused", psbt,
                 SP_PSBT_ERR_PSBT);

  psbt = with_declared_share();
  const struct wally_map_item *proof = NULL;
  unsigned char declared[DLEQ_PROOF_LEN];
  TEST("a declared share and proof that match ours are kept");
  proof = psbt ? find_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_DLEQ,
                                 RECIPIENT_SCAN)
               : NULL;
  if (proof)
    memcpy(declared, proof->value, sizeof(declared));
  if (proof && sp_psbt_complete(&psbt, false) == SP_PSBT_OK &&
      share_is(psbt, RECIPIENT_SCAN, RECIPIENT_SHARE) &&
      (proof = find_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_DLEQ,
                               RECIPIENT_SCAN)) &&
      memcmp(proof->value, declared, sizeof(declared)) == 0)
    PASS();
  else
    FAIL("declared share or proof replaced");
  wally_psbt_free(psbt);

  psbt = with_declared_share();
  expect_untouched_refusal(
      "a declared share differing from ours is refused, the PSBT untouched",
      checked(psbt, psbt && flip_global_field(psbt, PSBT_GLOBAL_SP_ECDH_SHARE)),
      SP_PSBT_ERR_FIELD);

  psbt = with_declared_share();
  expect_untouched_refusal(
      "a declared proof that does not verify is refused, the PSBT untouched",
      checked(psbt, psbt && flip_global_field(psbt, PSBT_GLOBAL_SP_DLEQ)),
      SP_PSBT_ERR_FIELD);
}

static bool input_share_is(const struct wally_psbt *psbt, size_t i,
                           const char *scan_hex, const char *share_hex) {
  unsigned char expected[SP_PUBKEY_LEN];
  const struct wally_map_item *item = find_scan_field(
      &psbt->inputs[i].unknowns, PSBT_IN_SP_ECDH_SHARE, scan_hex);
  return item && hex_to(share_hex, expected, sizeof(expected)) &&
         item->value_len == sizeof(expected) &&
         memcmp(item->value, expected, sizeof(expected)) == 0;
}

static bool input_proof_verifies(const struct wally_psbt *psbt, size_t i,
                                 const char *input_key_hex,
                                 const char *scan_hex, const char *share_hex) {
  secp256k1_pubkey input_key, scan, share, generator;
  const struct wally_map_item *proof =
      find_scan_field(&psbt->inputs[i].unknowns, PSBT_IN_SP_DLEQ, scan_hex);
  return proof && proof->value_len == DLEQ_PROOF_LEN &&
         parse_point(input_key_hex, &input_key) &&
         parse_point(scan_hex, &scan) && parse_point(share_hex, &share) &&
         secp256k1_ec_pubkey_create(wally_get_secp_context(), &generator,
                                    SCALAR_ONE) &&
         dleq_verify(&input_key, &scan, &share, proof->value, &generator, NULL);
}

static bool input_entry_is(const sp_share_t *share,
                           const struct wally_psbt *psbt, size_t i,
                           const char *scan_hex, const char *share_hex) {
  return !share->global && share->input_index == i &&
         share_entry_is(share, &psbt->inputs[i].unknowns, PSBT_IN_SP_DLEQ,
                        scan_hex, share_hex);
}

// Holding input 0 of two, our per-input shares are a_0*B_scan, the global
// shares UNSIGNED_PSBT gets for the same key
static void test_first_signer(void) {
  struct wally_psbt *psbt = parse_hex(TWO_SIGNER_PSBT);
  sp_share_t *shares = NULL;
  size_t count = 0;

  TEST("holding some inputs, sp_psbt_complete writes per-input shares and "
       "waits");
  if (psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_PENDING &&
      input_share_is(psbt, 0, RECIPIENT_SCAN, RECIPIENT_SHARE) &&
      input_share_is(psbt, 0, OUR_SCAN, OUR_SHARE) &&
      input_proof_verifies(psbt, 0, INPUT_KEY, RECIPIENT_SCAN,
                           RECIPIENT_SHARE) &&
      input_proof_verifies(psbt, 0, INPUT_KEY, OUR_SCAN, OUR_SHARE) &&
      !find_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_ECDH_SHARE,
                       RECIPIENT_SCAN) &&
      !find_scan_field(&psbt->inputs[1].unknowns, PSBT_IN_SP_ECDH_SHARE,
                       RECIPIENT_SCAN) &&
      sp_psbt_outputs_pending(psbt))
    PASS();
  else
    FAIL("per-input shares missing or outputs derived");

  TEST("sp_psbt_shares_alloc reads the per-input shares of input 0");
  if (psbt && sp_psbt_shares_alloc(psbt, false, &shares, &count) &&
      count == 2 &&
      input_entry_is(&shares[0], psbt, 0, RECIPIENT_SCAN, RECIPIENT_SHARE) &&
      input_entry_is(&shares[1], psbt, 0, OUR_SCAN, OUR_SHARE))
    PASS();
  else
    FAIL("per-input shares not read");
  free(shares);
  wally_psbt_free(psbt);
}

static bool flip_input_unknown(struct wally_psbt *psbt, size_t i,
                               unsigned char type) {
  for (size_t j = 0; j < psbt->inputs[i].unknowns.num_items; j++) {
    struct wally_map_item *item = &psbt->inputs[i].unknowns.items[j];
    if (item->key_len && item->key[0] == type) {
      item->value[item->value_len - 1] ^= 1;
      return true;
    }
  }
  return false;
}

// The other signer's shares on input 1 complete both scan keys: the scripts
// come from the summed shares alone
static void test_second_signer(void) {
  struct wally_psbt *psbt = parse_hex(TWO_SIGNER_SHARED_PSBT);
  size_t flags = 1;

  TEST("the other signer's shares complete the outputs");
  if (psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_OK &&
      script_is(psbt, 0, TWO_SIGNER_SCRIPT_0) &&
      script_is(psbt, 1, TWO_SIGNER_SCRIPT_1) &&
      input_share_is(psbt, 0, RECIPIENT_SCAN, RECIPIENT_SHARE) &&
      input_share_is(psbt, 0, OUR_SCAN, OUR_SHARE) &&
      wally_psbt_get_tx_modifiable_flags(psbt, &flags) == WALLY_OK &&
      flags == 0)
    PASS();
  else
    FAIL("scripts differ from the BIP352 reference");
  wally_psbt_free(psbt);

  psbt = parse_hex(TWO_SIGNER_SHARED_PSBT);
  expect_untouched_refusal(
      "another signer's share failing its proof is refused, the PSBT untouched",
      checked(psbt, psbt && flip_input_unknown(psbt, 1, PSBT_IN_SP_DLEQ)),
      SP_PSBT_ERR_FIELD);

  psbt = parse_hex(TWO_SIGNER_SHARED_PSBT);
  unsigned char proof_key[1 + SP_PUBKEY_LEN] = {PSBT_IN_SP_DLEQ};
  bool removed = psbt && hex_to(OUR_SCAN, proof_key + 1, SP_PUBKEY_LEN) &&
                 wally_map_remove(&psbt->inputs[1].unknowns, proof_key,
                                  sizeof(proof_key)) == WALLY_OK;
  expect_untouched_refusal(
      "another signer's share without its proof is refused, the PSBT "
      "untouched",
      checked(psbt, removed), SP_PSBT_ERR_FIELD);
}

// The pending PSBT serializes without PSBT_OUT_SCRIPT on its scriptless
// outputs and parses back with its shares
static void test_serialize_pending(void) {
  struct wally_psbt *psbt = parse_hex(TWO_SIGNER_PSBT), *back = NULL;
  uint8_t *bytes = NULL;
  size_t len = 0;

  TEST("sp_psbt_serialize_alloc writes a pending PSBT BIP375 parses back");
  if (psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_PENDING &&
      sp_psbt_serialize_alloc(psbt, &bytes, &len) &&
      psbt_parse_payload(bytes, len, &back) && sp_psbt_outputs_pending(back) &&
      !back->outputs[0].script && !back->outputs[1].script &&
      input_share_is(back, 0, RECIPIENT_SCAN, RECIPIENT_SHARE) &&
      input_share_is(back, 0, OUR_SCAN, OUR_SHARE))
    PASS();
  else
    FAIL("pending PSBT does not round trip");
  free(bytes);
  wally_psbt_free(back);
  wally_psbt_free(psbt);

  TEST("sp_psbt_serialize_alloc writes a complete PSBT as libwally does");
  psbt = parse_hex(UNSIGNED_PSBT);
  bytes = NULL;
  size_t wally_len = 0, written = 0;
  unsigned char *wally_bytes = NULL;
  bool same = psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_OK &&
              sp_psbt_serialize_alloc(psbt, &bytes, &len) &&
              wally_psbt_get_length(psbt, 0, &wally_len) == WALLY_OK &&
              (wally_bytes = malloc(wally_len)) != NULL &&
              wally_psbt_to_bytes(psbt, 0, wally_bytes, wally_len, &written) ==
                  WALLY_OK &&
              written == len && memcmp(bytes, wally_bytes, len) == 0;
  if (same)
    PASS();
  else
    FAIL("serialization differs from libwally's");
  free(wally_bytes);
  free(bytes);
  wally_psbt_free(psbt);
}

// The BIP375 vectors' P2WPKH inputs pay a key hash other than their
// PSBT_IN_BIP32_DERIVATION key's, a key BIP352 never sums: pay that key's hash,
// as a spendable input does
static struct wally_psbt *parse_vector(const char *hex) {
  struct wally_psbt *psbt = parse_hex(hex);
  for (size_t i = 0; psbt && i < psbt->num_inputs; i++) {
    struct wally_psbt_input *in = &psbt->inputs[i];
    struct wally_tx_output *utxo = in->witness_utxo;
    size_t type = 0, written = 0;
    if (!utxo || !in->keypaths.num_items ||
        wally_scriptpubkey_get_type(utxo->script, utxo->script_len, &type) !=
            WALLY_OK ||
        type != WALLY_SCRIPT_TYPE_P2WPKH)
      continue;
    if (wally_witness_program_from_bytes(
            in->keypaths.items[0].key, in->keypaths.items[0].key_len,
            WALLY_SCRIPT_HASH160, utxo->script, utxo->script_len,
            &written) != WALLY_OK ||
        written != utxo->script_len) {
      wally_psbt_free(psbt);
      psbt = NULL;
    }
  }
  return psbt;
}

static bool scripts_match(const struct wally_psbt *psbt,
                          const bip375_derivation_t *vector) {
  for (size_t i = 0; i < psbt->num_outputs && i < BIP375_MAX_OUTPUTS; i++)
    if (vector->scripts[i] && !script_is(psbt, i, vector->scripts[i]))
      return false;
  return true;
}

// Every "can finalize" vector, its silent payment scripts left out: they are
// derived again from its shares, which other signers made
static void test_bip375_derivations(void) {
  size_t n = sizeof(BIP375_DERIVATIONS) / sizeof(BIP375_DERIVATIONS[0]);
  for (size_t i = 0; i < n; i++) {
    struct wally_psbt *psbt = parse_vector(BIP375_DERIVATIONS[i].psbt);
    TEST(BIP375_DERIVATIONS[i].name);
    if (psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_OK &&
        scripts_match(psbt, &BIP375_DERIVATIONS[i]))
      PASS();
    else
      FAIL("scripts differ from the vector's");
    wally_psbt_free(psbt);
  }
  expect_refusal("a foreign P2WPKH input whose script does not hash its key "
                 "is refused",
                 parse_hex(BIP375_DERIVATIONS[1].psbt), SP_PSBT_ERR_INPUT_KEY);
}

static int bip375_result(const char *hex) {
  struct wally_psbt *psbt = parse_vector(hex);
  int result;
  if (!psbt)
    return BIP375_PARSE_REFUSED;
  result = sp_psbt_complete(&psbt, false);
  wally_psbt_free(psbt);
  return result;
}

// Every other vector, in progress or invalid, gives its result
static void test_bip375_results(void) {
  size_t n = sizeof(BIP375_RESULTS) / sizeof(BIP375_RESULTS[0]);
  for (size_t i = 0; i < n; i++) {
    TEST(BIP375_RESULTS[i].name);
    if (bip375_result(BIP375_RESULTS[i].psbt) == BIP375_RESULTS[i].result)
      PASS();
    else
      FAIL("unexpected result");
  }
}

static void test_ownership(void) {
  struct wally_psbt *psbt = parse_hex(UNSIGNED_PSBT);

  TEST("sp_psbt_input_is_ours recognizes our tweaked spend key");
  if (psbt && sp_psbt_input_is_ours(psbt, 0, false) &&
      !sp_psbt_input_is_ours(psbt, 0, true))
    PASS();
  else
    FAIL("input ownership wrong");

  TEST("sp_psbt_output_ownership spots only our m=0 change output");
  if (psbt &&
      sp_psbt_output_ownership(psbt, 1, NULL, false) == SP_OUTPUT_CHANGE &&
      sp_psbt_output_ownership(psbt, 0, NULL, false) == SP_OUTPUT_FOREIGN &&
      sp_psbt_output_ownership(psbt, 1, NULL, true) == SP_OUTPUT_FOREIGN)
    PASS();
  else
    FAIL("change detection wrong");
  wally_psbt_free(psbt);
}

// Ownership of output 1 of UNSIGNED_PSBT once it pays `scan_hex` and
// `spend_hex`, with PSBT_OUT_SP_V0_LABEL `label`, or none when it is NULL,
// for our spend key's account with `scan_secret_hex`, ours when NULL
static sp_output_ownership_t ownership_of(const char *scan_hex,
                                          const char *spend_hex,
                                          const uint32_t *label,
                                          const char *scan_secret_hex) {
  unsigned char scan_secret[SP_SECRET_LEN];
  struct wally_psbt *psbt = parse_hex(UNSIGNED_PSBT);
  unsigned char info_key = PSBT_OUT_SP_V0_INFO,
                label_key = PSBT_OUT_SP_V0_LABEL;
  unsigned char info[2 * SP_PUBKEY_LEN], label_bytes[sizeof(uint32_t)];
  sp_output_ownership_t ownership = SP_OUTPUT_FOREIGN;
  struct wally_map *unknowns;
  bool ok;

  if (!psbt)
    return SP_OUTPUT_FOREIGN;
  unknowns = &psbt->outputs[1].unknowns;
  ok = hex_to(scan_hex, info, SP_PUBKEY_LEN) &&
       hex_to(spend_hex, info + SP_PUBKEY_LEN, SP_PUBKEY_LEN) &&
       wally_map_replace(unknowns, &info_key, 1, info, sizeof(info)) ==
           WALLY_OK &&
       wally_map_remove(unknowns, &label_key, 1) == WALLY_OK;
  if (ok && label) {
    for (size_t i = 0; i < sizeof(label_bytes); i++)
      label_bytes[i] = (unsigned char)(*label >> (8 * i));
    ok = wally_map_replace(unknowns, &label_key, 1, label_bytes,
                           sizeof(label_bytes)) == WALLY_OK;
  }
  if (ok && scan_secret_hex)
    ok = hex_to(scan_secret_hex, scan_secret, sizeof(scan_secret));
  if (ok)
    ownership = sp_psbt_output_ownership(
        psbt, 1, scan_secret_hex ? scan_secret : NULL, false);
  wally_psbt_free(psbt);
  return ownership;
}

static void expect_ownership(const char *name, const char *scan_hex,
                             const char *spend_hex, const uint32_t *label,
                             const char *scan_secret_hex,
                             sp_output_ownership_t expected) {
  TEST(name);
  if (ownership_of(scan_hex, spend_hex, label, scan_secret_hex) == expected)
    PASS();
  else
    FAIL("output ownership wrong");
}

static void test_labels(void) {
  const uint32_t change = 0, three = 3;

  expect_ownership("label 0 on the m=0 key is change", OUR_SCAN,
                   OUR_SPEND_LABEL_0, &change, NULL, SP_OUTPUT_CHANGE);
  expect_ownership("label 3 on the m=3 key is a self-transfer", OUR_SCAN,
                   OUR_SPEND_LABEL_3, &three, NULL, SP_OUTPUT_SELF);
  expect_ownership("no label on the unlabeled key is a self-transfer", OUR_SCAN,
                   OUR_SPEND, NULL, NULL, SP_OUTPUT_SELF);
  expect_ownership("no label on the m=0 key is change", OUR_SCAN,
                   OUR_SPEND_LABEL_0, NULL, NULL, SP_OUTPUT_CHANGE);
  expect_ownership("label 3 on the m=0 key is not ours", OUR_SCAN,
                   OUR_SPEND_LABEL_0, &three, NULL, SP_OUTPUT_FOREIGN);
  expect_ownership("a foreign scan key with our m=0 key is not ours",
                   RECIPIENT_SCAN, OUR_SPEND_LABEL_0, &change, NULL,
                   SP_OUTPUT_FOREIGN);
  expect_ownership("our account does not take the other scan key's change",
                   RECIPIENT_SCAN, RECIPIENT_SCAN_SPEND_LABEL_0, NULL, NULL,
                   SP_OUTPUT_FOREIGN);
  expect_ownership("label 0 with the account's scan key is change",
                   RECIPIENT_SCAN, RECIPIENT_SCAN_SPEND_LABEL_0, &change,
                   RECIPIENT_SCAN_SECRET, SP_OUTPUT_CHANGE);
  expect_ownership("no label with the account's scan key is change",
                   RECIPIENT_SCAN, RECIPIENT_SCAN_SPEND_LABEL_0, NULL,
                   RECIPIENT_SCAN_SECRET, SP_OUTPUT_CHANGE);
  expect_ownership("label 3 with the account's scan key is a self-transfer",
                   RECIPIENT_SCAN, RECIPIENT_SCAN_SPEND_LABEL_3, &three,
                   RECIPIENT_SCAN_SECRET, SP_OUTPUT_SELF);
  expect_ownership("our unlabeled key with the account's scan key is ours",
                   RECIPIENT_SCAN, OUR_SPEND, NULL, RECIPIENT_SCAN_SECRET,
                   SP_OUTPUT_SELF);
  expect_ownership("the account does not take our scan key's change", OUR_SCAN,
                   OUR_SPEND_LABEL_0, &change, RECIPIENT_SCAN_SECRET,
                   SP_OUTPUT_FOREIGN);
}

static bool signature_verifies(struct wally_psbt *psbt, size_t i) {
  unsigned char key_bytes[SP_PUBKEY_LEN], hash[32], sig[64];
  struct wally_tx *tx = NULL;
  secp256k1_xonly_pubkey key;
  size_t written = 0;
  bool ok =
      hex_to(INPUT_KEY, key_bytes, sizeof(key_bytes)) &&
      secp256k1_xonly_pubkey_parse(wally_get_secp_context(), &key,
                                   key_bytes + 1) &&
      wally_psbt_get_input_taproot_signature(psbt, i, sig, sizeof(sig),
                                             &written) == WALLY_OK &&
      written == sizeof(sig) &&
      wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx) == WALLY_OK &&
      wally_psbt_get_input_signature_hash(psbt, i, tx, NULL, 0, 0, hash,
                                          sizeof(hash)) == WALLY_OK &&
      secp256k1_schnorrsig_verify(wally_get_secp_context(), sig, hash,
                                  sizeof(hash), &key);
  wally_tx_free(tx);
  return ok;
}

static void test_sign(void) {
  struct wally_psbt *psbt = parse_hex(UNSIGNED_PSBT);
  TEST("sp_psbt_sign_input makes a key path signature of the output key");
  if (psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_OK &&
      sp_psbt_sign_input(psbt, 0, false) && signature_verifies(psbt, 0))
    PASS();
  else
    FAIL("no valid signature");
  wally_psbt_free(psbt);

  psbt = parse_hex(FOREIGN_PSBT);
  TEST("sp_psbt_sign_input refuses an input that is not ours");
  size_t written = 0;
  if (psbt && !sp_psbt_sign_input(psbt, 1, false) &&
      wally_psbt_get_input_taproot_signature_len(psbt, 1, &written) ==
          WALLY_OK &&
      written == 0)
    PASS();
  else
    FAIL("signed a foreign input");
  wally_psbt_free(psbt);
}

// Our spend branch key m/352'/coin'/0'/0'/`index`: its secret and public key
static bool spend_branch_key(bool is_testnet, uint32_t index,
                             unsigned char *secret, unsigned char *pubkey) {
  uint32_t path[SP_PATH_DEPTH];
  struct ext_key *key = NULL;

  sp_account_key_path(is_testnet, SP_SPEND_BRANCH, path);
  path[SP_PATH_DEPTH - 1] = index;
  if (!key_get_derived_key_components(path, SP_PATH_DEPTH, &key))
    return false;
  memcpy(secret, key->priv_key + 1, SP_SECRET_LEN);
  memcpy(pubkey, key->pub_key, SP_PUBKEY_LEN);
  bip32_key_free(key);
  return true;
}

// Adds to input 0 of `psbt` a PSBT_IN_SP_SPEND_BIP32_DERIVATION naming
// `pubkey` at m/352'/coin'/0'/0'/`index` under `fingerprint`
static bool add_spend_derivation(struct wally_psbt *psbt,
                                 const unsigned char *pubkey,
                                 const unsigned char *fingerprint,
                                 bool is_testnet, uint32_t index) {
  uint32_t path[SP_PATH_DEPTH];
  unsigned char key[1 + SP_PUBKEY_LEN];
  unsigned char value[4 + 4 * SP_PATH_DEPTH];

  sp_account_key_path(is_testnet, SP_SPEND_BRANCH, path);
  path[SP_PATH_DEPTH - 1] = index;
  key[0] = PSBT_IN_SP_SPEND_BIP32_DERIVATION;
  memcpy(key + 1, pubkey, SP_PUBKEY_LEN);
  memcpy(value, fingerprint, 4);
  for (size_t i = 0; i < SP_PATH_DEPTH; i++)
    for (size_t b = 0; b < 4; b++)
      value[4 + 4 * i + b] = (unsigned char)(path[i] >> (8 * b));
  return wally_map_replace(&psbt->inputs[0].unknowns, key, sizeof(key), value,
                           sizeof(value)) == WALLY_OK;
}

// Moves input 0's PSBT_IN_SP_TWEAK from our account's spend key to the spend
// key at `index`, so that both give the same output key: t' = t + b0 - b_index
static bool retweak_for_index(struct wally_psbt *psbt, bool is_testnet,
                              uint32_t index, unsigned char *pubkey_out) {
  unsigned char type = PSBT_IN_SP_TWEAK, tweak[32];
  unsigned char b0[SP_SECRET_LEN], b0_pub[SP_PUBKEY_LEN];
  unsigned char bi[SP_SECRET_LEN];
  struct wally_map *unknowns = &psbt->inputs[0].unknowns;
  const secp256k1_context *ctx = wally_get_secp_context();
  size_t found = 0;

  if (wally_map_find(unknowns, &type, 1, &found) != WALLY_OK || !found ||
      unknowns->items[found - 1].value_len != sizeof(tweak))
    return false;
  memcpy(tweak, unknowns->items[found - 1].value, sizeof(tweak));
  return spend_branch_key(false, 0, b0, b0_pub) &&
         spend_branch_key(is_testnet, index, bi, pubkey_out) &&
         secp256k1_ec_seckey_negate(ctx, bi) &&
         secp256k1_ec_seckey_tweak_add(ctx, tweak, b0) &&
         secp256k1_ec_seckey_tweak_add(ctx, tweak, bi) &&
         wally_map_replace(unknowns, &type, 1, tweak, sizeof(tweak)) ==
             WALLY_OK;
}

static bool input_unsigned(struct wally_psbt *psbt, size_t i) {
  size_t written = 0;
  return wally_psbt_get_input_taproot_signature_len(psbt, i, &written) ==
             WALLY_OK &&
         written == 0;
}

// Whether input 0 of UNSIGNED_PSBT, once `edit` changed it, is ours and gets
// a valid signature
static void expect_spend(const char *name,
                         bool (*edit)(struct wally_psbt *psbt), bool signs) {
  struct wally_psbt *psbt = parse_hex(UNSIGNED_PSBT);
  bool ok = psbt && edit(psbt);

  TEST(name);
  if (ok && signs)
    ok = sp_psbt_input_is_ours(psbt, 0, false) &&
         sp_psbt_complete(&psbt, false) == SP_PSBT_OK &&
         sp_psbt_sign_input(psbt, 0, false) && signature_verifies(psbt, 0);
  else if (ok)
    ok = !sp_psbt_input_is_ours(psbt, 0, false) &&
         !sp_psbt_sign_input(psbt, 0, false) && input_unsigned(psbt, 0);
  if (ok)
    PASS();
  else
    FAIL(signs ? "input not signed" : "input signed");
  wally_psbt_free(psbt);
}

static const uint32_t OTHER_SPEND_INDEX = 5;
static const unsigned char ZERO_FINGERPRINT[4] = {0};
static const unsigned char FOREIGN_FINGERPRINT[4] = {0xde, 0xad, 0xbe, 0xef};

// Input 0 spends with the key at `index` on the spend branch of `is_testnet`,
// named by its PSBT_IN_SP_SPEND_BIP32_DERIVATION under our fingerprint
static bool spend_at(struct wally_psbt *psbt, bool is_testnet, uint32_t index) {
  unsigned char pubkey[SP_PUBKEY_LEN], fingerprint[4];
  return retweak_for_index(psbt, is_testnet, index, pubkey) &&
         key_get_fingerprint(fingerprint) &&
         add_spend_derivation(psbt, pubkey, fingerprint, is_testnet, index);
}

static bool spend_at_other_index(struct wally_psbt *psbt) {
  return spend_at(psbt, false, OTHER_SPEND_INDEX);
}

static bool spend_on_testnet_branch(struct wally_psbt *psbt) {
  return spend_at(psbt, true, 0);
}

static bool other_index_without_field(struct wally_psbt *psbt) {
  unsigned char pubkey[SP_PUBKEY_LEN];
  return retweak_for_index(psbt, false, OTHER_SPEND_INDEX, pubkey);
}

static bool key_not_derived_by_path(struct wally_psbt *psbt) {
  unsigned char secret[SP_SECRET_LEN], b0_pub[SP_PUBKEY_LEN];
  unsigned char pubkey[SP_PUBKEY_LEN], fingerprint[4];
  return retweak_for_index(psbt, false, OTHER_SPEND_INDEX, pubkey) &&
         spend_branch_key(false, 0, secret, b0_pub) &&
         key_get_fingerprint(fingerprint) &&
         add_spend_derivation(psbt, b0_pub, fingerprint, false,
                              OTHER_SPEND_INDEX);
}

static bool named_with(struct wally_psbt *psbt,
                       const unsigned char *fingerprint) {
  unsigned char secret[SP_SECRET_LEN], pubkey[SP_PUBKEY_LEN];
  return spend_branch_key(false, 0, secret, pubkey) &&
         add_spend_derivation(psbt, pubkey, fingerprint, false, 0);
}

static bool zero_fingerprint(struct wally_psbt *psbt) {
  return named_with(psbt, ZERO_FINGERPRINT);
}

static bool foreign_fingerprint(struct wally_psbt *psbt) {
  return named_with(psbt, FOREIGN_FINGERPRINT);
}

static bool our_default_key_named(struct wally_psbt *psbt) {
  unsigned char fingerprint[4];
  return key_get_fingerprint(fingerprint) && named_with(psbt, fingerprint);
}

// BIP376: the spend key of a silent payment input is the one its
// PSBT_IN_SP_SPEND_BIP32_DERIVATION names
static void test_spend_derivation(void) {
  expect_spend("our account's spend key named by its path signs",
               our_default_key_named, true);
  expect_spend("a spend key at another index on our spend branch signs",
               spend_at_other_index, true);
  expect_spend("without the field, only our account's spend key is tried",
               other_index_without_field, false);
  expect_spend("a spend path off our network's spend branch is not ours",
               spend_on_testnet_branch, false);
  expect_spend("a field key its path does not derive is not ours",
               key_not_derived_by_path, false);
  expect_spend("a zero fingerprint falls back to our account's spend key",
               zero_fingerprint, true);
  expect_spend("a foreign fingerprint is not ours", foreign_fingerprint, false);
}

// UNSIGNED_PSBT with its one input turned into a P2WPKH input of our key at
// `path`, listed under our fingerprint
static struct wally_psbt *p2wpkh_input_at(const char *path) {
  struct wally_psbt *psbt = parse_hex(UNSIGNED_PSBT);
  struct ext_key *key = NULL;
  uint32_t comps[KEY_MAX_DERIVATION_DEPTH];
  size_t depth = 0, spk_len = 0;
  unsigned char spk[WALLY_SCRIPTPUBKEY_P2WPKH_LEN];
  unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
  struct wally_tx_output *utxo = NULL;
  bool ok = psbt && key_get_fingerprint(fp) &&
            bip32_path_parse(path, comps, &depth, KEY_MAX_DERIVATION_DEPTH) &&
            key_get_derived_key(path, &key) &&
            wally_witness_program_from_bytes(
                key->pub_key, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160, spk,
                sizeof(spk), &spk_len) == WALLY_OK &&
            wally_tx_output_init_alloc(100000, spk, spk_len, &utxo) == WALLY_OK;
  if (ok) {
    struct wally_psbt_input *in = &psbt->inputs[0];
    wally_map_clear(&in->unknowns);
    wally_map_clear(&in->taproot_leaf_paths);
    wally_map_clear(&in->taproot_leaf_hashes);
    // The input set is frozen, so the keypath goes on the input itself
    ok = wally_psbt_set_input_witness_utxo(psbt, 0, utxo) == WALLY_OK &&
         wally_psbt_input_keypath_add(in, key->pub_key, EC_PUBLIC_KEY_LEN, fp,
                                      sizeof(fp), comps, depth) == WALLY_OK;
  }
  wally_tx_output_free(utxo);
  bip32_key_free(key);
  if (!ok) {
    wally_psbt_free(psbt);
    return NULL;
  }
  return psbt;
}

// An input of the exported scan key is not ours: Kern makes no share with it
static void test_scan_key_input(void) {
  struct wally_psbt *psbt = p2wpkh_input_at("m/352'/0'/0'/0'/0");
  TEST("an input of the BIP352 spend key gives the shares");
  if (psbt && sp_psbt_complete(&psbt, false) == SP_PSBT_OK)
    PASS();
  else
    FAIL("expected the outputs completed");
  wally_psbt_free(psbt);

  expect_waiting("an input of the BIP352 scan key is another signer's",
                 p2wpkh_input_at("m/352'/0'/0'/1'/0"));
}

int main(void) {
  if (!key_load_from_mnemonic(TEST_MNEMONIC, NULL, false)) {
    printf("FAIL: could not load the test mnemonic\n");
    return 1;
  }
  test_parse();
  test_complete();
  test_shares();
  test_refusals();
  test_bip352_inputs();
  test_input_refusals();
  test_field_checks();
  test_first_signer();
  test_second_signer();
  test_serialize_pending();
  test_bip375_derivations();
  test_bip375_results();
  test_ownership();
  test_labels();
  test_sign();
  test_spend_derivation();
  test_scan_key_input();
  key_unload();

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
