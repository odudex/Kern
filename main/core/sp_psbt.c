/*
 * BIP375 signer: ECDH shares, DLEQ proofs and silent payment output scripts,
 * mirroring bwk's SpSigner (sp/src/signer.rs) and its BIP375 rules
 * (sp/src/account/bip375.rs). The BIP352 output derivation is libsecp256k1's.
 */

#include "sp_psbt.h"
#include "../utils/secure_mem.h"
#include "bip32_path.h"
#include "crypto_utils.h"
#include "dleq.h"
#include "key.h"
#include "silent_payments.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_silentpayments.h>
#include <secure_memory.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_map.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

// BIP370 PSBT_GLOBAL_TX_MODIFIABLE
#define GLOBAL_TX_MODIFIABLE 0x06
// BIP371 PSBT_IN_TAP_MERKLE_ROOT, held in libwally's psbt_fields map
#define PSBT_IN_TAP_MERKLE_ROOT 0x18
#define SP_V0_INFO_LEN (2 * SP_PUBKEY_LEN)
#define SP_LABEL_LEN 4
#define SP_TWEAK_LEN 32
#define SHARE_KEY_LEN (1 + SP_PUBKEY_LEN)
#define OUTPOINT_LEN (WALLY_TXHASH_LEN + 4)
#define XONLY_LEN 32
#define P2TR_SCRIPT_LEN 34
#define P2TR_KEY_OFFSET 2
#define P2SH_HASH_OFFSET 2
#define P2WPKH_HASH_OFFSET 2
#define P2PKH_HASH_OFFSET 3
#define OP_1 0x51
#define OP_16 0x60
#define PUSH_32 0x20
// BIP352 reserves label m = 0 for change
#define SP_CHANGE_LABEL 0
#define SCHNORR_SIG_LEN 64
// Smallest and largest witness program, BIP141
#define WITNESS_PROGRAM_MIN 2
#define WITNESS_PROGRAM_MAX 40
// Largest push a P2SH redeem script can be
#define MAX_REDEEM_SCRIPT_LEN 520
// Deepest derivation path a PSBT key origin may name
#define MAX_KEYPATH_DEPTH 32
// Tag of the hash that binds the DLEQ aux randomness to the proven secret
#define DLEQ_AUX_HEDGE_TAG "KERN/DLEQAux"

// BIP341 NUMS point H, the provably unspendable internal key
static const unsigned char NUMS_H[XONLY_LEN] = {
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b,
    0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec,
    0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0};

static const unsigned char SCALAR_ONE[SP_SECRET_LEN] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

typedef struct {
  unsigned char scan[SP_PUBKEY_LEN];
  unsigned char spend[SP_PUBKEY_LEN];
  size_t output_index;
} sp_recipient_t;

// Parity-adjusted signing keys of the inputs we own
typedef struct {
  unsigned char (*keys)[SP_SECRET_LEN];
  size_t count;
} owned_inputs_t;

static const secp256k1_context *secp_ctx(void) {
  return wally_get_secp_context();
}

static const struct wally_map_item *find_field(const struct wally_map *map,
                                               const unsigned char *key,
                                               size_t key_len) {
  size_t index = 0;
  if (wally_map_find(map, key, key_len, &index) != WALLY_OK || !index)
    return NULL;
  return &map->items[index - 1];
}

static const struct wally_map_item *
find_unkeyed_field(const struct wally_map *map, unsigned char type) {
  return find_field(map, &type, 1);
}

static bool parse_point(const unsigned char *bytes, secp256k1_pubkey *out) {
  return secp256k1_ec_pubkey_parse(secp_ctx(), out, bytes, SP_PUBKEY_LEN) == 1;
}

static bool serialize_point(const secp256k1_pubkey *point, unsigned char *out) {
  size_t len = SP_PUBKEY_LEN;
  return secp256k1_ec_pubkey_serialize(secp_ctx(), out, &len, point,
                                       SECP256K1_EC_COMPRESSED) == 1;
}

// *info is NULL when the output carries no PSBT_OUT_SP_V0_INFO
static sp_psbt_result_t read_output_info(const struct wally_psbt_output *out,
                                         const unsigned char **info) {
  const struct wally_map_item *item =
      find_unkeyed_field(&out->unknowns, PSBT_OUT_SP_V0_INFO);
  const struct wally_map_item *label =
      find_unkeyed_field(&out->unknowns, PSBT_OUT_SP_V0_LABEL);
  secp256k1_pubkey point;

  *info = NULL;
  if (!item)
    return label ? SP_PSBT_ERR_FIELD : SP_PSBT_OK;
  if (item->value_len != SP_V0_INFO_LEN ||
      (label && label->value_len != SP_LABEL_LEN) ||
      !parse_point(item->value, &point) ||
      !parse_point(item->value + SP_PUBKEY_LEN, &point))
    return SP_PSBT_ERR_FIELD;
  *info = item->value;
  return SP_PSBT_OK;
}

bool sp_output_keys(const struct wally_psbt_output *output,
                    unsigned char *scan_out, unsigned char *spend_out) {
  const unsigned char *info = NULL;
  if (!output || read_output_info(output, &info) != SP_PSBT_OK || !info)
    return false;
  memcpy(scan_out, info, SP_PUBKEY_LEN);
  memcpy(spend_out, info + SP_PUBKEY_LEN, SP_PUBKEY_LEN);
  return true;
}

static bool output_has_info(const struct wally_psbt_output *out) {
  return find_unkeyed_field(&out->unknowns, PSBT_OUT_SP_V0_INFO) != NULL;
}

bool sp_psbt_has_outputs(const struct wally_psbt *psbt) {
  if (!psbt)
    return false;
  for (size_t i = 0; i < psbt->num_outputs; i++)
    if (output_has_info(&psbt->outputs[i]))
      return true;
  return false;
}

static bool is_field_type(const struct wally_map_item *item,
                          unsigned char type) {
  return item->key_len && item->key[0] == type;
}

static bool has_field_type_in(const struct wally_map *map, unsigned char first,
                              unsigned char last) {
  for (size_t i = 0; i < map->num_items; i++) {
    const struct wally_map_item *item = &map->items[i];
    if (item->key_len && item->key[0] >= first && item->key[0] <= last)
      return true;
  }
  return false;
}

bool sp_psbt_has_fields(const struct wally_psbt *psbt) {
  if (!psbt)
    return false;
  if (has_field_type_in(&psbt->unknowns, PSBT_GLOBAL_SP_ECDH_SHARE,
                        PSBT_GLOBAL_SP_DLEQ))
    return true;
  for (size_t i = 0; i < psbt->num_inputs; i++)
    if (has_field_type_in(&psbt->inputs[i].unknowns, PSBT_IN_SP_ECDH_SHARE,
                          PSBT_IN_SP_TWEAK))
      return true;
  for (size_t i = 0; i < psbt->num_outputs; i++)
    if (has_field_type_in(&psbt->outputs[i].unknowns, PSBT_OUT_SP_V0_INFO,
                          PSBT_OUT_SP_V0_LABEL))
      return true;
  return false;
}

bool sp_psbt_outputs_pending(const struct wally_psbt *psbt) {
  bool pending = false;
  if (!psbt)
    return false;
  for (size_t i = 0; i < psbt->num_outputs; i++) {
    const struct wally_psbt_output *out = &psbt->outputs[i];
    if (out->script)
      continue;
    if (!output_has_info(out))
      return false;
    pending = true;
  }
  return pending;
}

static int compare_recipients(const void *a, const void *b) {
  const sp_recipient_t *ra = a, *rb = b;
  int cmp = memcmp(ra->scan, rb->scan, SP_PUBKEY_LEN);
  if (cmp)
    return cmp;
  cmp = memcmp(ra->spend, rb->spend, SP_PUBKEY_LEN);
  if (cmp)
    return cmp;
  return (ra->output_index > rb->output_index) -
         (ra->output_index < rb->output_index);
}

// Sorted by scan key, then spend key, then output index: bwk assigns k in
// this order within a scan key group (bip375.rs output_scripts).
static sp_psbt_result_t collect_recipients(const struct wally_psbt *psbt,
                                           sp_recipient_t **out,
                                           size_t *count) {
  sp_recipient_t *recipients = calloc(psbt->num_outputs, sizeof(*recipients));
  size_t n = 0;

  if (!recipients)
    return SP_PSBT_ERR_CRYPTO;
  for (size_t i = 0; i < psbt->num_outputs; i++) {
    const unsigned char *info = NULL;
    sp_psbt_result_t result = read_output_info(&psbt->outputs[i], &info);
    if (result != SP_PSBT_OK) {
      free(recipients);
      return result;
    }
    if (!info)
      continue;
    memcpy(recipients[n].scan, info, SP_PUBKEY_LEN);
    memcpy(recipients[n].spend, info + SP_PUBKEY_LEN, SP_PUBKEY_LEN);
    recipients[n].output_index = i;
    n++;
  }
  qsort(recipients, n, sizeof(*recipients), compare_recipients);
  *out = recipients;
  *count = n;
  return SP_PSBT_OK;
}

static bool same_prevout(const struct wally_tx_output *a,
                         const struct wally_tx_output *b) {
  return a->satoshi == b->satoshi && a->script_len == b->script_len &&
         memcmp(a->script, b->script, a->script_len) == 0;
}

// The output an input spends, from witness_utxo and non_witness_utxo, which
// must agree when both are present.
static sp_psbt_result_t input_prevout(const struct wally_psbt_input *in,
                                      const struct wally_tx_output **out) {
  const struct wally_tx_output *non_witness = NULL;
  unsigned char txid[WALLY_TXHASH_LEN];

  if (in->utxo) {
    if (wally_tx_get_txid(in->utxo, txid, sizeof(txid)) != WALLY_OK ||
        memcmp(txid, in->txhash, sizeof(txid)) != 0 ||
        in->index >= in->utxo->num_outputs)
      return SP_PSBT_ERR_INPUT;
    non_witness = &in->utxo->outputs[in->index];
  }
  if (in->witness_utxo && non_witness &&
      !same_prevout(in->witness_utxo, non_witness))
    return SP_PSBT_ERR_INPUT;
  *out = in->witness_utxo ? in->witness_utxo : non_witness;
  return *out ? SP_PSBT_OK : SP_PSBT_ERR_INPUT;
}

// BIP352 defines no input key for segwit v2 and later
static bool is_future_witness_version(const struct wally_tx_output *prevout) {
  const unsigned char *script = prevout->script;
  size_t len = prevout->script_len;
  return len >= WITNESS_PROGRAM_MIN + 2 && len <= WITNESS_PROGRAM_MAX + 2 &&
         script[0] > OP_1 && script[0] <= OP_16 && script[1] == len - 2;
}

static uint32_t script_type(const struct wally_tx_output *prevout) {
  size_t type = WALLY_SCRIPT_TYPE_UNKNOWN;
  if (wally_scriptpubkey_get_type(prevout->script, prevout->script_len,
                                  &type) != WALLY_OK)
    return WALLY_SCRIPT_TYPE_UNKNOWN;
  return (uint32_t)type;
}

// The input's BIP371 merkle root, NULL when it commits to no script tree
static const unsigned char *
input_merkle_root(const struct wally_psbt_input *in) {
  const struct wally_map_item *item =
      wally_map_get_integer(&in->psbt_fields, PSBT_IN_TAP_MERKLE_ROOT);
  return item && item->value_len == SHA256_LEN ? item->value : NULL;
}

static size_t merkle_root_len(const unsigned char *merkle_root) {
  return merkle_root ? SHA256_LEN : 0;
}

// A NUMS internal key excludes the input only when it provably reaches the
// output key: a false claim would drop a real key from the input sum.
static bool commits_to_nums(const struct wally_psbt *psbt, size_t i,
                            const unsigned char *output_key) {
  const unsigned char *merkle_root = input_merkle_root(&psbt->inputs[i]);
  unsigned char internal_key[XONLY_LEN], tweaked[EC_PUBLIC_KEY_LEN];
  size_t written = 0;

  if (wally_psbt_get_input_taproot_internal_key(
          psbt, i, internal_key, sizeof(internal_key), &written) != WALLY_OK ||
      written != XONLY_LEN || memcmp(internal_key, NUMS_H, XONLY_LEN) != 0)
    return false;
  if (memcmp(output_key, NUMS_H, XONLY_LEN) == 0)
    return true;
  return wally_ec_public_key_bip341_tweak(
             NUMS_H, XONLY_LEN, merkle_root, merkle_root_len(merkle_root), 0,
             tweaked, sizeof(tweaked)) == WALLY_OK &&
         memcmp(tweaked + 1, output_key, XONLY_LEN) == 0;
}

// The redeem script of P2SH input `i`, which must hash to the script it
// spends. *redeem_len is 0 when the PSBT gives none.
static sp_psbt_result_t proven_redeem_script(const struct wally_psbt *psbt,
                                             size_t i,
                                             const unsigned char *script,
                                             unsigned char *redeem,
                                             size_t *redeem_len) {
  unsigned char hash[HASH160_LEN];

  if (wally_psbt_get_input_redeem_script_len(psbt, i, redeem_len) != WALLY_OK ||
      !*redeem_len) {
    *redeem_len = 0;
    return SP_PSBT_OK;
  }
  if (*redeem_len > MAX_REDEEM_SCRIPT_LEN ||
      wally_psbt_get_input_redeem_script(psbt, i, redeem, MAX_REDEEM_SCRIPT_LEN,
                                         redeem_len) != WALLY_OK ||
      wally_hash160(redeem, *redeem_len, hash, sizeof(hash)) != WALLY_OK ||
      memcmp(hash, script + P2SH_HASH_OFFSET, sizeof(hash)) != 0)
    return SP_PSBT_ERR_INPUT;
  return SP_PSBT_OK;
}

// P2SH counts only as P2SH-P2WPKH
static sp_psbt_result_t p2sh_eligibility(const struct wally_psbt *psbt,
                                         size_t i, const unsigned char *script,
                                         bool *eligible) {
  unsigned char redeem[MAX_REDEEM_SCRIPT_LEN];
  size_t redeem_len = 0, type = WALLY_SCRIPT_TYPE_UNKNOWN;
  sp_psbt_result_t result =
      proven_redeem_script(psbt, i, script, redeem, &redeem_len);

  *eligible =
      result == SP_PSBT_OK && redeem_len &&
      wally_scriptpubkey_get_type(redeem, redeem_len, &type) == WALLY_OK &&
      type == WALLY_SCRIPT_TYPE_P2WPKH;
  return result;
}

// Whether BIP352 sums this input's key, from the script it spends alone
static sp_psbt_result_t input_eligibility(const struct wally_psbt *psbt,
                                          size_t i,
                                          const struct wally_tx_output *prevout,
                                          bool *eligible) {
  switch (script_type(prevout)) {
  case WALLY_SCRIPT_TYPE_P2PKH:
  case WALLY_SCRIPT_TYPE_P2WPKH:
    *eligible = true;
    return SP_PSBT_OK;
  case WALLY_SCRIPT_TYPE_P2TR:
    *eligible = !commits_to_nums(psbt, i, prevout->script + P2TR_KEY_OFFSET);
    return SP_PSBT_OK;
  case WALLY_SCRIPT_TYPE_P2SH:
    return p2sh_eligibility(psbt, i, prevout->script, eligible);
  default:
    *eligible = false;
    return SP_PSBT_OK;
  }
}

// The fingerprint our key origins carry, and the silent payment keys
typedef struct {
  const struct sp_keys *keys;
  unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
} signer_t;

// The key a PSBT key origin names, when the origin is our seed. The path only
// locates the key: the caller proves it against the script it spends.
static bool derive_origin_key(const unsigned char *keypath, size_t keypath_len,
                              const unsigned char *fingerprint,
                              struct ext_key **key_out) {
  uint32_t path[MAX_KEYPATH_DEPTH];
  size_t depth = 0;

  return keypath_len >= BIP32_KEY_FINGERPRINT_LEN &&
         memcmp(keypath, fingerprint, BIP32_KEY_FINGERPRINT_LEN) == 0 &&
         bip32_path_from_keypath(keypath, keypath_len, path, &depth,
                                 MAX_KEYPATH_DEPTH) &&
         key_get_derived_key_components(path, depth, key_out);
}

// Keeps `key` when its x-only public key is `output_key`, negated to the
// even-Y key BIP352 sums; wipes it otherwise
static sp_psbt_result_t match_output_key(unsigned char *key,
                                         const unsigned char *output_key,
                                         bool *owned) {
  secp256k1_keypair keypair;
  secp256k1_xonly_pubkey xonly;
  unsigned char x[XONLY_LEN];
  int parity = 0;
  bool ok =
      secp256k1_keypair_create(secp_ctx(), &keypair, key) &&
      secp256k1_keypair_xonly_pub(secp_ctx(), &xonly, &parity, &keypair) &&
      secp256k1_xonly_pubkey_serialize(secp_ctx(), x, &xonly);

  *owned = false;
  secure_memzero(&keypair, sizeof(keypair));
  if (ok && memcmp(x, output_key, XONLY_LEN) != 0) {
    secure_memzero(key, SP_SECRET_LEN);
    return SP_PSBT_OK;
  }
  if (!ok || (parity && !secp256k1_ec_seckey_negate(secp_ctx(), key))) {
    secure_memzero(key, SP_SECRET_LEN);
    return SP_PSBT_ERR_CRYPTO;
  }
  *owned = true;
  return SP_PSBT_OK;
}

// d = b_spend + tweak, ours when x(d*G) is the P2TR output key it spends
// (signer.rs reconstruct_signing_key)
static sp_psbt_result_t sp_tweak_signing_key(
    const struct wally_psbt_input *in, const struct wally_tx_output *prevout,
    const unsigned char *spend_secret, bool *owned, unsigned char *key_out) {
  const struct wally_map_item *tweak =
      find_unkeyed_field(&in->unknowns, PSBT_IN_SP_TWEAK);

  *owned = false;
  if (!tweak)
    return SP_PSBT_OK;
  if (tweak->value_len != SP_TWEAK_LEN)
    return SP_PSBT_ERR_FIELD;
  if (script_type(prevout) != WALLY_SCRIPT_TYPE_P2TR)
    return SP_PSBT_OK;
  memcpy(key_out, spend_secret, SP_SECRET_LEN);
  if (!secp256k1_ec_seckey_tweak_add(secp_ctx(), key_out, tweak->value)) {
    secure_memzero(key_out, SP_SECRET_LEN);
    return SP_PSBT_ERR_FIELD;
  }
  return match_output_key(key_out, prevout->script + P2TR_KEY_OFFSET, owned);
}

// One PSBT_IN_TAP_BIP32_DERIVATION entry: its key, BIP341 tweaked by the
// input's merkle root, must be the output key
static sp_psbt_result_t taproot_candidate(const struct wally_map_item *item,
                                          const unsigned char *merkle_root,
                                          const unsigned char *output_key,
                                          const unsigned char *fingerprint,
                                          bool *owned, unsigned char *key_out) {
  struct ext_key *key = NULL;
  bool ok;

  *owned = false;
  if (!derive_origin_key(item->value, item->value_len, fingerprint, &key))
    return SP_PSBT_OK;
  // The entry's key must be the one its origin derives
  ok = item->key_len == XONLY_LEN &&
       memcmp(key->pub_key + 1, item->key, XONLY_LEN) == 0 &&
       wally_ec_private_key_bip341_tweak(
           key->priv_key + 1, SP_SECRET_LEN, merkle_root,
           merkle_root_len(merkle_root), 0, key_out, SP_SECRET_LEN) == WALLY_OK;
  bip32_key_free(key);
  if (!ok) {
    secure_memzero(key_out, SP_SECRET_LEN);
    return SP_PSBT_OK;
  }
  return match_output_key(key_out, output_key, owned);
}

static sp_psbt_result_t taproot_origin_key(const struct wally_psbt_input *in,
                                           const unsigned char *output_key,
                                           const unsigned char *fingerprint,
                                           bool *owned,
                                           unsigned char *key_out) {
  const struct wally_map *paths = &in->taproot_leaf_paths;
  const unsigned char *merkle_root = input_merkle_root(in);
  sp_psbt_result_t result = SP_PSBT_OK;

  *owned = false;
  for (size_t j = 0; result == SP_PSBT_OK && !*owned && j < paths->num_items;
       j++)
    result = taproot_candidate(&paths->items[j], merkle_root, output_key,
                               fingerprint, owned, key_out);
  return result;
}

// A spend of one of our silent payments carries its tweak; any other P2TR
// input is a BIP341 key path spend
static sp_psbt_result_t taproot_signing_key(
    const struct wally_psbt_input *in, const struct wally_tx_output *prevout,
    const signer_t *signer, bool *owned, unsigned char *key_out) {
  if (find_unkeyed_field(&in->unknowns, PSBT_IN_SP_TWEAK))
    return sp_tweak_signing_key(in, prevout, signer->keys->spend_secret, owned,
                                key_out);
  return taproot_origin_key(in, prevout->script + P2TR_KEY_OFFSET,
                            signer->fingerprint, owned, key_out);
}

static sp_psbt_result_t p2sh_key_hash(const struct wally_psbt *psbt, size_t i,
                                      const unsigned char *script,
                                      unsigned char *hash_out) {
  unsigned char redeem[MAX_REDEEM_SCRIPT_LEN];
  size_t redeem_len = 0;
  sp_psbt_result_t result =
      proven_redeem_script(psbt, i, script, redeem, &redeem_len);

  if (result != SP_PSBT_OK)
    return result;
  if (!redeem_len)
    return SP_PSBT_ERR_INPUT;
  memcpy(hash_out, redeem + P2WPKH_HASH_OFFSET, HASH160_LEN);
  return SP_PSBT_OK;
}

// The key hash a P2WPKH, P2PKH or P2SH-P2WPKH script commits to
static sp_psbt_result_t
committed_key_hash(const struct wally_psbt *psbt, size_t i,
                   const struct wally_tx_output *prevout,
                   unsigned char *hash_out) {
  switch (script_type(prevout)) {
  case WALLY_SCRIPT_TYPE_P2WPKH:
    memcpy(hash_out, prevout->script + P2WPKH_HASH_OFFSET, HASH160_LEN);
    return SP_PSBT_OK;
  case WALLY_SCRIPT_TYPE_P2PKH:
    memcpy(hash_out, prevout->script + P2PKH_HASH_OFFSET, HASH160_LEN);
    return SP_PSBT_OK;
  case WALLY_SCRIPT_TYPE_P2SH:
    return p2sh_key_hash(psbt, i, prevout->script, hash_out);
  default:
    return SP_PSBT_ERR_INPUT;
  }
}

// One PSBT_IN_BIP32_DERIVATION entry: the key its origin derives must be the
// entry's key and hash to the one the script commits to
static bool key_hash_candidate(const struct wally_map_item *item,
                               const unsigned char *hash,
                               const unsigned char *fingerprint,
                               unsigned char *key_out) {
  struct ext_key *key = NULL;
  unsigned char key_hash[HASH160_LEN];
  bool owned;

  if (!derive_origin_key(item->value, item->value_len, fingerprint, &key))
    return false;
  owned = item->key_len == EC_PUBLIC_KEY_LEN &&
          memcmp(key->pub_key, item->key, EC_PUBLIC_KEY_LEN) == 0 &&
          wally_hash160(key->pub_key, EC_PUBLIC_KEY_LEN, key_hash,
                        sizeof(key_hash)) == WALLY_OK &&
          memcmp(key_hash, hash, HASH160_LEN) == 0;
  if (owned)
    memcpy(key_out, key->priv_key + 1, SP_SECRET_LEN);
  bip32_key_free(key);
  return owned;
}

static sp_psbt_result_t
key_hash_signing_key(const struct wally_psbt *psbt, size_t i,
                     const struct wally_tx_output *prevout,
                     const signer_t *signer, bool *owned,
                     unsigned char *key_out) {
  const struct wally_map *keypaths = &psbt->inputs[i].keypaths;
  unsigned char hash[HASH160_LEN];
  sp_psbt_result_t result = committed_key_hash(psbt, i, prevout, hash);

  *owned = false;
  for (size_t j = 0; result == SP_PSBT_OK && !*owned && j < keypaths->num_items;
       j++)
    *owned = key_hash_candidate(&keypaths->items[j], hash, signer->fingerprint,
                                key_out);
  return result;
}

// Our key for an eligible input, found from the script it spends (BIP352): a
// PSBT key origin only names a candidate, kept once it reproduces the script
static sp_psbt_result_t input_signing_key(const struct wally_psbt *psbt,
                                          size_t i,
                                          const struct wally_tx_output *prevout,
                                          const signer_t *signer, bool *owned,
                                          unsigned char *key_out) {
  switch (script_type(prevout)) {
  case WALLY_SCRIPT_TYPE_P2TR:
    return taproot_signing_key(&psbt->inputs[i], prevout, signer, owned,
                               key_out);
  case WALLY_SCRIPT_TYPE_P2WPKH:
  case WALLY_SCRIPT_TYPE_P2PKH:
  case WALLY_SCRIPT_TYPE_P2SH:
    return key_hash_signing_key(psbt, i, prevout, signer, owned, key_out);
  default:
    *owned = false;
    return SP_PSBT_OK;
  }
}

// Input rules checked before deriving the outputs (bip375.rs
// validate_input_eligibility), then the owned key of an eligible input
static sp_psbt_result_t check_input(const struct wally_psbt *psbt, size_t i,
                                    const signer_t *signer,
                                    owned_inputs_t *owned) {
  const struct wally_psbt_input *in = &psbt->inputs[i];
  const struct wally_tx_output *prevout = NULL;
  bool eligible = false, is_ours = false;
  sp_psbt_result_t result = input_prevout(in, &prevout);

  if (result != SP_PSBT_OK)
    return result;
  if (is_future_witness_version(prevout))
    return SP_PSBT_ERR_INPUT;
  // Any other sighash lets a signer change outputs derived from the inputs
  if (in->sighash && in->sighash != WALLY_SIGHASH_ALL)
    return SP_PSBT_ERR_SIGHASH;
  result = input_eligibility(psbt, i, prevout, &eligible);
  if (result != SP_PSBT_OK || !eligible)
    return result;
  result = input_signing_key(psbt, i, prevout, signer, &is_ours,
                             owned->keys[owned->count]);
  if (result != SP_PSBT_OK)
    return result;
  if (!is_ours)
    return SP_PSBT_ERR_FOREIGN;
  owned->count++;
  return SP_PSBT_OK;
}

static void owned_inputs_free(owned_inputs_t *owned) {
  if (owned->keys) {
    secure_memzero(owned->keys, owned->count * sizeof(*owned->keys));
    free(owned->keys);
  }
  owned->keys = NULL;
  owned->count = 0;
}

// The global share needs every eligible input's key, so all must be ours
static sp_psbt_result_t collect_owned_inputs(const struct wally_psbt *psbt,
                                             const signer_t *signer,
                                             owned_inputs_t *owned) {
  owned->count = 0;
  owned->keys = kern_secret_alloc(psbt->num_inputs * sizeof(*owned->keys));
  if (!owned->keys)
    return SP_PSBT_ERR_CRYPTO;
  for (size_t i = 0; i < psbt->num_inputs; i++) {
    sp_psbt_result_t result = check_input(psbt, i, signer, owned);
    if (result != SP_PSBT_OK) {
      owned_inputs_free(owned);
      return result;
    }
  }
  if (owned->count)
    return SP_PSBT_OK;
  owned_inputs_free(owned);
  return SP_PSBT_ERR_INPUT;
}

static bool sum_owned_keys(const owned_inputs_t *owned, unsigned char *sum) {
  memcpy(sum, owned->keys[0], SP_SECRET_LEN);
  for (size_t i = 1; i < owned->count; i++)
    if (!secp256k1_ec_seckey_tweak_add(secp_ctx(), sum, owned->keys[i]))
      return false;
  return true;
}

static void scan_field_key(unsigned char type, const unsigned char *scan,
                           unsigned char *key) {
  key[0] = type;
  memcpy(key + 1, scan, SP_PUBKEY_LEN);
}

static bool set_scan_field(struct wally_map *map, unsigned char type,
                           const unsigned char *scan,
                           const unsigned char *value, size_t value_len) {
  unsigned char key[SHARE_KEY_LEN];
  scan_field_key(type, scan, key);
  return wally_map_replace(map, key, sizeof(key), value, value_len) == WALLY_OK;
}

static const struct wally_map_item *find_scan_field(const struct wally_map *map,
                                                    unsigned char type,
                                                    const unsigned char *scan) {
  unsigned char key[SHARE_KEY_LEN];
  scan_field_key(type, scan, key);
  return find_field(map, key, sizeof(key));
}

// H(rng || a_sum || B_scan): a weak RNG still yields a proof nonce bound to
// the secret it proves (embit _default_aux_rand)
static bool hedged_aux(const unsigned char *sum, const unsigned char *scan,
                       unsigned char *aux_out) {
  unsigned char buf[DLEQ_AUX_LEN + SP_SECRET_LEN + SP_PUBKEY_LEN];
  bool ok = crypto_random_bytes(buf, DLEQ_AUX_LEN) == CRYPTO_OK;

  memcpy(buf + DLEQ_AUX_LEN, sum, SP_SECRET_LEN);
  memcpy(buf + DLEQ_AUX_LEN + SP_SECRET_LEN, scan, SP_PUBKEY_LEN);
  ok = ok && secp256k1_tagged_sha256(
                 secp_ctx(), aux_out, (const unsigned char *)DLEQ_AUX_HEDGE_TAG,
                 sizeof(DLEQ_AUX_HEDGE_TAG) - 1, buf, sizeof(buf)) == 1;
  secure_memzero(buf, sizeof(buf));
  return ok;
}

// A share and proof the PSBT already holds must be ours: the same share, and
// a proof that verifies against A_sum = a_sum*G
static sp_psbt_result_t
check_declared_share(const struct wally_psbt *psbt, const unsigned char *scan,
                     const secp256k1_pubkey *scan_point,
                     const secp256k1_pubkey *share,
                     const unsigned char *share_bytes, const unsigned char *sum,
                     const secp256k1_pubkey *generator, bool *declared) {
  const struct wally_map_item *declared_share =
      find_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_ECDH_SHARE, scan);
  const struct wally_map_item *declared_proof =
      find_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_DLEQ, scan);
  secp256k1_pubkey public;

  *declared = declared_share || declared_proof;
  if (!*declared)
    return SP_PSBT_OK;
  if (!declared_share || !declared_proof ||
      declared_share->value_len != SP_PUBKEY_LEN ||
      memcmp(declared_share->value, share_bytes, SP_PUBKEY_LEN) != 0 ||
      declared_proof->value_len != DLEQ_PROOF_LEN)
    return SP_PSBT_ERR_FIELD;
  if (!secp256k1_ec_pubkey_create(secp_ctx(), &public, sum))
    return SP_PSBT_ERR_CRYPTO;
  return dleq_verify(&public, scan_point, share, declared_proof->value,
                     generator, NULL)
             ? SP_PSBT_OK
             : SP_PSBT_ERR_FIELD;
}

// share = a_sum*B_scan, with its proof over A_sum = a_sum*G
static sp_psbt_result_t write_scan_share(struct wally_psbt *psbt,
                                         const unsigned char *scan,
                                         const unsigned char *sum,
                                         const secp256k1_pubkey *generator) {
  secp256k1_pubkey scan_point, share;
  unsigned char share_bytes[SP_PUBKEY_LEN], proof[DLEQ_PROOF_LEN];
  unsigned char aux[DLEQ_AUX_LEN];
  bool declared = false, ok;
  sp_psbt_result_t result;

  if (!parse_point(scan, &scan_point))
    return SP_PSBT_ERR_FIELD;
  share = scan_point;
  if (!secp256k1_ec_pubkey_tweak_mul(secp_ctx(), &share, sum) ||
      !serialize_point(&share, share_bytes))
    return SP_PSBT_ERR_CRYPTO;
  result = check_declared_share(psbt, scan, &scan_point, &share, share_bytes,
                                sum, generator, &declared);
  if (result != SP_PSBT_OK || declared)
    return result;
  ok = hedged_aux(sum, scan, aux) &&
       dleq_prove(sum, &scan_point, aux, generator, NULL, proof) &&
       set_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_ECDH_SHARE, scan,
                      share_bytes, sizeof(share_bytes)) &&
       set_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_DLEQ, scan, proof,
                      sizeof(proof));
  secure_memzero(aux, sizeof(aux));
  return ok ? SP_PSBT_OK : SP_PSBT_ERR_CRYPTO;
}

// One global share and DLEQ proof per distinct scan key (signer.rs
// write_shares)
static sp_psbt_result_t write_shares(struct wally_psbt *psbt,
                                     const owned_inputs_t *owned,
                                     const sp_recipient_t *recipients,
                                     size_t count) {
  unsigned char sum[SP_SECRET_LEN];
  secp256k1_pubkey generator;
  sp_psbt_result_t result =
      sum_owned_keys(owned, sum) &&
              secp256k1_ec_pubkey_create(secp_ctx(), &generator, SCALAR_ONE)
          ? SP_PSBT_OK
          : SP_PSBT_ERR_CRYPTO;

  for (size_t i = 0; result == SP_PSBT_OK && i < count; i++) {
    if (i && !memcmp(recipients[i].scan, recipients[i - 1].scan, SP_PUBKEY_LEN))
      continue;
    result = write_scan_share(psbt, recipients[i].scan, sum, &generator);
  }
  secure_memzero(sum, sizeof(sum));
  return result;
}

// BIP352 hashes the smallest outpoint of all inputs, eligible or not
static void smallest_outpoint(const struct wally_psbt *psbt,
                              unsigned char *out) {
  unsigned char candidate[OUTPOINT_LEN];
  for (size_t i = 0; i < psbt->num_inputs; i++) {
    const struct wally_psbt_input *in = &psbt->inputs[i];
    memcpy(candidate, in->txhash, WALLY_TXHASH_LEN);
    candidate[WALLY_TXHASH_LEN] = in->index & 0xff;
    candidate[WALLY_TXHASH_LEN + 1] = (in->index >> 8) & 0xff;
    candidate[WALLY_TXHASH_LEN + 2] = (in->index >> 16) & 0xff;
    candidate[WALLY_TXHASH_LEN + 3] = (in->index >> 24) & 0xff;
    if (!i || memcmp(candidate, out, OUTPOINT_LEN) < 0)
      memcpy(out, candidate, OUTPOINT_LEN);
  }
}

// A signer never overwrites a script another party committed to
static sp_psbt_result_t set_output_script(struct wally_psbt *psbt, size_t index,
                                          const secp256k1_xonly_pubkey *key) {
  struct wally_psbt_output *out = &psbt->outputs[index];
  unsigned char script[P2TR_SCRIPT_LEN] = {OP_1, PUSH_32};

  if (!secp256k1_xonly_pubkey_serialize(secp_ctx(), script + P2TR_KEY_OFFSET,
                                        key))
    return SP_PSBT_ERR_CRYPTO;
  if (out->script)
    return out->script_len == sizeof(script) &&
                   memcmp(out->script, script, sizeof(script)) == 0
               ? SP_PSBT_OK
               : SP_PSBT_ERR_SCRIPT;
  return wally_psbt_output_set_script(out, script, sizeof(script)) == WALLY_OK
             ? SP_PSBT_OK
             : SP_PSBT_ERR_CRYPTO;
}

typedef struct {
  const unsigned char **seckey_ptrs;
  secp256k1_silentpayments_recipient *recipients;
  const secp256k1_silentpayments_recipient **recipient_ptrs;
  secp256k1_xonly_pubkey *outputs;
  secp256k1_xonly_pubkey **output_ptrs;
} sender_buffers_t;

static void sender_buffers_free(sender_buffers_t *b) {
  free(b->seckey_ptrs);
  free(b->recipients);
  free(b->recipient_ptrs);
  free(b->outputs);
  free(b->output_ptrs);
}

static bool sender_buffers_alloc(sender_buffers_t *b, size_t seckey_count,
                                 size_t recipient_count) {
  memset(b, 0, sizeof(*b));
  b->seckey_ptrs = calloc(seckey_count, sizeof(*b->seckey_ptrs));
  b->recipients = calloc(recipient_count, sizeof(*b->recipients));
  b->recipient_ptrs = calloc(recipient_count, sizeof(*b->recipient_ptrs));
  b->outputs = calloc(recipient_count, sizeof(*b->outputs));
  b->output_ptrs = calloc(recipient_count, sizeof(*b->output_ptrs));
  return b->seckey_ptrs && b->recipients && b->recipient_ptrs && b->outputs &&
         b->output_ptrs;
}

// libsecp256k1 keeps the given order within a scan key group, so recipients
// already sorted the bwk way give bwk's k for every output. The owned keys go
// in as plain secret keys: the taproot ones are already even-Y, and passing
// them as keypairs would negate an odd-Y P2WPKH or P2PKH key.
static bool fill_sender_buffers(sender_buffers_t *b,
                                const owned_inputs_t *owned,
                                const sp_recipient_t *recipients,
                                size_t count) {
  for (size_t i = 0; i < owned->count; i++)
    b->seckey_ptrs[i] = owned->keys[i];
  for (size_t i = 0; i < count; i++) {
    if (!parse_point(recipients[i].scan, &b->recipients[i].scan_pubkey) ||
        !parse_point(recipients[i].spend, &b->recipients[i].spend_pubkey))
      return false;
    b->recipients[i].index = i;
    b->recipient_ptrs[i] = &b->recipients[i];
    b->output_ptrs[i] = &b->outputs[i];
  }
  return true;
}

static sp_psbt_result_t fill_output_scripts(struct wally_psbt *psbt,
                                            const owned_inputs_t *owned,
                                            const sp_recipient_t *recipients,
                                            size_t count) {
  unsigned char outpoint[OUTPOINT_LEN];
  sender_buffers_t b;
  sp_psbt_result_t result = SP_PSBT_ERR_CRYPTO;

  smallest_outpoint(psbt, outpoint);
  if (sender_buffers_alloc(&b, owned->count, count) &&
      fill_sender_buffers(&b, owned, recipients, count) &&
      secp256k1_silentpayments_sender_create_outputs(
          secp_ctx(), b.output_ptrs, b.recipient_ptrs, count, outpoint, NULL, 0,
          b.seckey_ptrs, owned->count)) {
    result = SP_PSBT_OK;
    for (size_t i = 0; result == SP_PSBT_OK && i < count; i++)
      result =
          set_output_script(psbt, recipients[i].output_index, &b.outputs[i]);
  }
  sender_buffers_free(&b);
  return result;
}

// The parse let scriptless outputs through, so every check it skipped runs
// again on the completed PSBT
static sp_psbt_result_t reparse_strict(struct wally_psbt **psbt) {
  struct wally_psbt *strict = NULL;
  unsigned char *bytes = NULL;
  size_t len = 0, written = 0;
  bool ok =
      wally_psbt_get_length(*psbt, 0, &len) == WALLY_OK &&
      (bytes = malloc(len)) != NULL &&
      wally_psbt_to_bytes(*psbt, 0, bytes, len, &written) == WALLY_OK &&
      wally_psbt_from_bytes(bytes, written, WALLY_PSBT_PARSE_FLAG_COMPLETE,
                            &strict) == WALLY_OK;
  free(bytes);
  if (!ok)
    return SP_PSBT_ERR_PSBT;
  wally_psbt_free(*psbt);
  *psbt = strict;
  return SP_PSBT_OK;
}

static sp_psbt_result_t complete_with_keys(struct wally_psbt *psbt,
                                           const struct sp_keys *keys) {
  sp_recipient_t *recipients = NULL;
  size_t count = 0;
  owned_inputs_t owned = {0};
  signer_t signer = {.keys = keys};
  sp_psbt_result_t result = collect_recipients(psbt, &recipients, &count);

  if (result == SP_PSBT_OK && !key_get_fingerprint(signer.fingerprint))
    result = SP_PSBT_ERR_KEYS;
  if (result == SP_PSBT_OK)
    result = collect_owned_inputs(psbt, &signer, &owned);
  if (result == SP_PSBT_OK)
    result = write_shares(psbt, &owned, recipients, count);
  if (result == SP_PSBT_OK)
    result = fill_output_scripts(psbt, &owned, recipients, count);
  // The scripts depend on the exact input and output sets, so freeze both
  if (result == SP_PSBT_OK &&
      wally_psbt_set_tx_modifiable_flags(psbt, 0) != WALLY_OK)
    result = SP_PSBT_ERR_PSBT;
  owned_inputs_free(&owned);
  free(recipients);
  return result;
}

sp_psbt_result_t sp_psbt_complete(struct wally_psbt **psbt, bool is_testnet) {
  struct wally_psbt *completed = NULL;
  struct sp_keys keys;
  sp_psbt_result_t result;

  if (!psbt || !*psbt)
    return SP_PSBT_ERR_PSBT;
  // BIP375 and BIP376 fields only exist in PSBTv2
  if ((*psbt)->version != WALLY_PSBT_VERSION_2 && sp_psbt_has_fields(*psbt))
    return SP_PSBT_ERR_PSBT;
  if (!sp_psbt_has_outputs(*psbt))
    return SP_PSBT_OK;
  if (!sp_keys_derive(is_testnet, &keys))
    return SP_PSBT_ERR_KEYS;
  // Completed on a copy, so a refused PSBT is left as it came
  result = wally_psbt_clone_alloc(*psbt, 0, &completed) == WALLY_OK
               ? complete_with_keys(completed, &keys)
               : SP_PSBT_ERR_PSBT;
  sp_keys_wipe(&keys);
  if (result == SP_PSBT_OK)
    result = reparse_strict(&completed);
  if (result != SP_PSBT_OK) {
    wally_psbt_free(completed);
    return result;
  }
  wally_psbt_free(*psbt);
  *psbt = completed;
  return SP_PSBT_OK;
}

bool sp_psbt_input_is_ours(const struct wally_psbt *psbt, size_t i,
                           bool is_testnet) {
  const struct wally_tx_output *prevout = NULL;
  struct sp_keys keys;
  unsigned char key[SP_SECRET_LEN];
  bool owned = false;

  if (!psbt || i >= psbt->num_inputs ||
      !find_unkeyed_field(&psbt->inputs[i].unknowns, PSBT_IN_SP_TWEAK) ||
      input_prevout(&psbt->inputs[i], &prevout) != SP_PSBT_OK ||
      !sp_keys_derive(is_testnet, &keys))
    return false;
  if (sp_tweak_signing_key(&psbt->inputs[i], prevout, keys.spend_secret, &owned,
                           key) != SP_PSBT_OK)
    owned = false;
  sp_keys_wipe(&keys);
  secure_memzero(key, sizeof(key));
  return owned;
}

// Our spend key labeled with m (BIP352 labels)
static bool labeled_spend_key(const struct sp_keys *keys, uint32_t m,
                              unsigned char *out) {
  secp256k1_silentpayments_label label;
  secp256k1_pubkey spend, labeled;
  unsigned char label_tweak[SP_SECRET_LEN];
  bool ok = secp256k1_silentpayments_recipient_label_create(
                secp_ctx(), &label, label_tweak, keys->scan_secret, m) &&
            parse_point(keys->spend_pubkey, &spend) &&
            secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
                secp_ctx(), &labeled, &spend, &label) &&
            serialize_point(&labeled, out);
  secure_memzero(label_tweak, sizeof(label_tweak));
  return ok;
}

static bool is_labeled_spend_key(const struct sp_keys *keys, uint32_t m,
                                 const unsigned char *spend) {
  unsigned char labeled[SP_PUBKEY_LEN];
  return labeled_spend_key(keys, m, labeled) &&
         memcmp(spend, labeled, SP_PUBKEY_LEN) == 0;
}

// Ownership of an output paying our scan key, from its spend key and the
// label it declares. A declared label that does not give its spend key is
// not trusted.
static sp_output_ownership_t
spend_key_ownership(const struct sp_keys *keys, const unsigned char *spend,
                    const struct wally_map_item *label) {
  uint32_t m;

  if (label) {
    m = bip32_path_u32_le(label->value);
    if (!is_labeled_spend_key(keys, m, spend))
      return SP_OUTPUT_FOREIGN;
    return m == SP_CHANGE_LABEL ? SP_OUTPUT_CHANGE : SP_OUTPUT_SELF;
  }
  if (is_labeled_spend_key(keys, SP_CHANGE_LABEL, spend))
    return SP_OUTPUT_CHANGE;
  return memcmp(spend, keys->spend_pubkey, SP_PUBKEY_LEN) == 0
             ? SP_OUTPUT_SELF
             : SP_OUTPUT_FOREIGN;
}

sp_output_ownership_t sp_psbt_output_ownership(const struct wally_psbt *psbt,
                                               size_t i, bool is_testnet) {
  unsigned char scan[SP_PUBKEY_LEN], spend[SP_PUBKEY_LEN];
  struct sp_keys keys;
  sp_output_ownership_t ownership = SP_OUTPUT_FOREIGN;

  if (!psbt || i >= psbt->num_outputs ||
      !sp_output_keys(&psbt->outputs[i], scan, spend) ||
      !sp_keys_derive(is_testnet, &keys))
    return SP_OUTPUT_FOREIGN;
  if (memcmp(scan, keys.scan_pubkey, SP_PUBKEY_LEN) == 0)
    ownership = spend_key_ownership(
        &keys, spend,
        find_unkeyed_field(&psbt->outputs[i].unknowns, PSBT_OUT_SP_V0_LABEL));
  sp_keys_wipe(&keys);
  return ownership;
}

// BIP341 key path signature over the input's sighash, the sighash byte
// appended unless it is SIGHASH_DEFAULT
static bool sign_key_path(struct wally_psbt *psbt, size_t i,
                          const unsigned char *key) {
  struct wally_tx *tx = NULL;
  unsigned char hash[SHA256_LEN], aux[SP_SECRET_LEN];
  unsigned char sig[SCHNORR_SIG_LEN + 1];
  size_t sig_len = SCHNORR_SIG_LEN;
  uint32_t sighash = psbt->inputs[i].sighash;
  bool ok =
      wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx) == WALLY_OK &&
      wally_psbt_get_input_signature_hash(psbt, i, tx, NULL, 0, 0, hash,
                                          sizeof(hash)) == WALLY_OK &&
      crypto_random_bytes(aux, sizeof(aux)) == CRYPTO_OK &&
      wally_ec_sig_from_bytes_aux(key, SP_SECRET_LEN, hash, sizeof(hash), aux,
                                  sizeof(aux), EC_FLAG_SCHNORR, sig,
                                  SCHNORR_SIG_LEN) == WALLY_OK;

  if (sighash != WALLY_SIGHASH_DEFAULT)
    sig[sig_len++] = (unsigned char)sighash;
  ok = ok && wally_psbt_set_input_taproot_signature(psbt, i, sig, sig_len) ==
                 WALLY_OK;
  wally_tx_free(tx);
  secure_memzero(aux, sizeof(aux));
  return ok;
}

bool sp_psbt_sign_input(struct wally_psbt *psbt, size_t i, bool is_testnet) {
  const struct wally_tx_output *prevout = NULL;
  struct sp_keys keys;
  unsigned char key[SP_SECRET_LEN];
  bool owned = false, ok;

  if (!psbt || i >= psbt->num_inputs ||
      input_prevout(&psbt->inputs[i], &prevout) != SP_PSBT_OK ||
      !sp_keys_derive(is_testnet, &keys))
    return false;
  ok = sp_tweak_signing_key(&psbt->inputs[i], prevout, keys.spend_secret,
                            &owned, key) == SP_PSBT_OK &&
       owned && sign_key_path(psbt, i, key);
  sp_keys_wipe(&keys);
  secure_memzero(key, sizeof(key));
  return ok;
}

static bool copy_fields(const struct wally_map *from, struct wally_map *to,
                        unsigned char type_a, unsigned char type_b) {
  for (size_t i = 0; i < from->num_items; i++) {
    const struct wally_map_item *item = &from->items[i];
    if ((is_field_type(item, type_a) || is_field_type(item, type_b)) &&
        wally_map_replace(to, item->key, item->key_len, item->value,
                          item->value_len) != WALLY_OK)
      return false;
  }
  return true;
}

bool sp_psbt_copy_fields(const struct wally_psbt *from, struct wally_psbt *to) {
  const unsigned char frozen = 0;
  unsigned char tx_modifiable = GLOBAL_TX_MODIFIABLE;

  if (!from || !to || from->num_outputs != to->num_outputs)
    return false;
  if (!sp_psbt_has_outputs(from))
    return true;
  if (!copy_fields(&from->unknowns, &to->unknowns, PSBT_GLOBAL_SP_ECDH_SHARE,
                   PSBT_GLOBAL_SP_DLEQ))
    return false;
  for (size_t i = 0; i < from->num_outputs; i++)
    if (!copy_fields(&from->outputs[i].unknowns, &to->outputs[i].unknowns,
                     PSBT_OUT_SP_V0_INFO, PSBT_OUT_SP_V0_LABEL))
      return false;
  return to->tx_modifiable_flags ||
         wally_map_replace(&to->unknowns, &tx_modifiable, 1, &frozen, 1) ==
             WALLY_OK;
}

const char *sp_psbt_result_message(sp_psbt_result_t result) {
  switch (result) {
  case SP_PSBT_OK:
    return "OK";
  case SP_PSBT_ERR_FIELD:
    return "Malformed silent payment field";
  case SP_PSBT_ERR_INPUT:
    return "Inputs not usable with silent payment outputs";
  case SP_PSBT_ERR_SIGHASH:
    return "Silent payment outputs need SIGHASH_ALL inputs";
  case SP_PSBT_ERR_FOREIGN:
    return "Silent payment outputs need every input to be ours";
  case SP_PSBT_ERR_KEYS:
    return "Silent payment keys unavailable";
  case SP_PSBT_ERR_CRYPTO:
    return "Silent payment output derivation failed";
  case SP_PSBT_ERR_SCRIPT:
    return "Output script differs from its silent payment";
  case SP_PSBT_ERR_PSBT:
  default:
    return "Invalid PSBT";
  }
}
