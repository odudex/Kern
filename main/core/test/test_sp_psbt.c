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
#include <wally_transaction.h>

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

static const unsigned char SCALAR_ONE[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

static bool hex_to(const char *hex, unsigned char *out, size_t len) {
  size_t written;
  return wally_hex_to_bytes(hex, out, len, &written) == WALLY_OK &&
         written == len;
}

static struct wally_psbt *parse_hex(const char *hex) {
  unsigned char bytes[2048];
  size_t written = 0;
  struct wally_psbt *psbt = NULL;
  if (wally_hex_to_bytes(hex, bytes, sizeof(bytes), &written) != WALLY_OK ||
      !psbt_parse_payload(bytes, written, &psbt))
    return NULL;
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

static void expect_refusal(const char *name, struct wally_psbt *psbt,
                           sp_psbt_result_t expected) {
  TEST(name);
  if (psbt && sp_psbt_complete(&psbt, false) == expected)
    PASS();
  else
    FAIL(sp_psbt_result_message(expected));
  wally_psbt_free(psbt);
}

static void test_refusals(void) {
  unsigned char tweak_key = PSBT_IN_SP_TWEAK;
  unsigned char info_key = PSBT_OUT_SP_V0_INFO;
  unsigned char wrong_tweak[32], script[34];
  struct wally_psbt *psbt;

  expect_refusal("a foreign eligible input is refused", parse_hex(FOREIGN_PSBT),
                 SP_PSBT_ERR_FOREIGN);

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
  expect_refusal("an input with a wrong tweak is not ours", psbt,
                 SP_PSBT_ERR_FOREIGN);

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
  expect_refusal("a key origin our key not hashed by the script is foreign",
                 psbt, SP_PSBT_ERR_FOREIGN);

  psbt = parse_hex(ALL_TYPES_PSBT);
  expect_refusal(
      "a P2TR key not reaching the output key is foreign",
      checked(psbt, psbt && flip_input_field(psbt, 2, PSBT_IN_TAP_MERKLE_ROOT)),
      SP_PSBT_ERR_FOREIGN);

  psbt = parse_hex(ALL_TYPES_PSBT);
  expect_refusal(
      "a redeem script not hashing to its script is refused",
      checked(psbt, psbt && flip_input_field(psbt, 3, PSBT_IN_REDEEM_SCRIPT)),
      SP_PSBT_ERR_INPUT);

  psbt = parse_hex(NUMS_PSBT);
  expect_refusal(
      "an unproven NUMS input stays eligible, and is foreign",
      checked(psbt, psbt && flip_input_field(psbt, 1, PSBT_IN_TAP_MERKLE_ROOT)),
      SP_PSBT_ERR_FOREIGN);
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

static void test_ownership(void) {
  struct wally_psbt *psbt = parse_hex(UNSIGNED_PSBT);

  TEST("sp_psbt_input_is_ours recognizes our tweaked spend key");
  if (psbt && sp_psbt_input_is_ours(psbt, 0, false) &&
      !sp_psbt_input_is_ours(psbt, 0, true))
    PASS();
  else
    FAIL("input ownership wrong");

  TEST("sp_psbt_output_ownership spots only our m=0 change output");
  if (psbt && sp_psbt_output_ownership(psbt, 1, false) == SP_OUTPUT_CHANGE &&
      sp_psbt_output_ownership(psbt, 0, false) == SP_OUTPUT_FOREIGN &&
      sp_psbt_output_ownership(psbt, 1, true) == SP_OUTPUT_FOREIGN)
    PASS();
  else
    FAIL("change detection wrong");
  wally_psbt_free(psbt);
}

// Ownership of output 1 of UNSIGNED_PSBT once it pays `scan_hex` and
// `spend_hex`, with PSBT_OUT_SP_V0_LABEL `label`, or none when it is NULL
static sp_output_ownership_t ownership_of(const char *scan_hex,
                                          const char *spend_hex,
                                          const uint32_t *label) {
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
  if (ok)
    ownership = sp_psbt_output_ownership(psbt, 1, false);
  wally_psbt_free(psbt);
  return ownership;
}

static void expect_ownership(const char *name, const char *scan_hex,
                             const char *spend_hex, const uint32_t *label,
                             sp_output_ownership_t expected) {
  TEST(name);
  if (ownership_of(scan_hex, spend_hex, label) == expected)
    PASS();
  else
    FAIL("output ownership wrong");
}

static void test_labels(void) {
  const uint32_t change = 0, three = 3;

  expect_ownership("label 0 on the m=0 key is change", OUR_SCAN,
                   OUR_SPEND_LABEL_0, &change, SP_OUTPUT_CHANGE);
  expect_ownership("label 3 on the m=3 key is a self-transfer", OUR_SCAN,
                   OUR_SPEND_LABEL_3, &three, SP_OUTPUT_SELF);
  expect_ownership("no label on the unlabeled key is a self-transfer", OUR_SCAN,
                   OUR_SPEND, NULL, SP_OUTPUT_SELF);
  expect_ownership("no label on the m=0 key is change", OUR_SCAN,
                   OUR_SPEND_LABEL_0, NULL, SP_OUTPUT_CHANGE);
  expect_ownership("label 3 on the m=0 key is not ours", OUR_SCAN,
                   OUR_SPEND_LABEL_0, &three, SP_OUTPUT_FOREIGN);
  expect_ownership("a foreign scan key with our m=0 key is not ours",
                   RECIPIENT_SCAN, OUR_SPEND_LABEL_0, &change,
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

int main(void) {
  if (!key_load_from_mnemonic(TEST_MNEMONIC, NULL, false)) {
    printf("FAIL: could not load the test mnemonic\n");
    return 1;
  }
  test_parse();
  test_complete();
  test_refusals();
  test_bip352_inputs();
  test_input_refusals();
  test_field_checks();
  test_ownership();
  test_labels();
  test_sign();
  key_unload();

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
