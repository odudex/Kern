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
#include "kern_wally.h"
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
// BIP174 PSBT_IN_SIGHASH_TYPE and its 32-bit little endian value
#define PSBT_IN_SIGHASH_TYPE 0x03
// BIP370 PSBT_OUT_SCRIPT
#define PSBT_OUT_SCRIPT 0x04
#define OP_RETURN 0x6a
#define SIGHASH_TYPE_LEN 4
// BIP174 magic bytes "psbt" and 0xff
#define PSBT_MAGIC_LEN 5
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
// BIP352 tagged hashes
#define BIP352_INPUTS_TAG "BIP0352/Inputs"
#define BIP352_SHARED_SECRET_TAG "BIP0352/SharedSecret"
// Prefix of a compressed public key with an even Y
#define EVEN_Y_PREFIX 0x02

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

// An input as BIP352 sees it: whether its key is summed, that key, and
// whether the seed holds its private key
typedef struct {
  bool eligible;
  bool owned;
  unsigned char pubkey[SP_PUBKEY_LEN];
} sp_input_t;

// Every input of a PSBT, with the parity-adjusted private keys of the owned
// ones at their input index
typedef struct {
  sp_input_t *inputs;
  unsigned char (*keys)[SP_SECRET_LEN];
  size_t count;
  size_t eligible;
  size_t owned;
} input_set_t;

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

// The key BIP352 sums for a key hash input we do not hold: the
// PSBT_IN_BIP32_DERIVATION key hashing to the one the script commits to. BIP375
// has the updater add it for that, and its test vectors refuse an input
// without it, so a partial signature's key does not stand in.
static bool key_hash_match(const struct wally_map *map,
                           const unsigned char *hash,
                           unsigned char *pubkey_out) {
  unsigned char key_hash[HASH160_LEN];
  for (size_t j = 0; j < map->num_items; j++) {
    const struct wally_map_item *item = &map->items[j];
    if (item->key_len == SP_PUBKEY_LEN &&
        wally_hash160(item->key, item->key_len, key_hash, sizeof(key_hash)) ==
            WALLY_OK &&
        memcmp(key_hash, hash, HASH160_LEN) == 0) {
      memcpy(pubkey_out, item->key, SP_PUBKEY_LEN);
      return true;
    }
  }
  return false;
}

// The public key of an eligible input another signer holds. For P2TR it is
// the even-Y lift of the output key, read from the script, never from a key
// origin a PSBT could make up.
static sp_psbt_result_t foreign_input_key(const struct wally_psbt *psbt,
                                          size_t i,
                                          const struct wally_tx_output *prevout,
                                          unsigned char *pubkey_out) {
  const struct wally_psbt_input *in = &psbt->inputs[i];
  unsigned char hash[HASH160_LEN];
  sp_psbt_result_t result;

  if (script_type(prevout) == WALLY_SCRIPT_TYPE_P2TR) {
    pubkey_out[0] = EVEN_Y_PREFIX;
    memcpy(pubkey_out + 1, prevout->script + P2TR_KEY_OFFSET, XONLY_LEN);
    return SP_PSBT_OK;
  }
  result = committed_key_hash(psbt, i, prevout, hash);
  if (result != SP_PSBT_OK)
    return result;
  return key_hash_match(&in->keypaths, hash, pubkey_out)
             ? SP_PSBT_OK
             : SP_PSBT_ERR_INPUT_KEY;
}

static bool secret_pubkey(const unsigned char *secret,
                          unsigned char *pubkey_out) {
  secp256k1_pubkey point;
  return secp256k1_ec_pubkey_create(secp_ctx(), &point, secret) &&
         serialize_point(&point, pubkey_out);
}

// Input rules checked before deriving the outputs (bip375.rs
// validate_input_eligibility), then the key BIP352 sums for an eligible
// input, with its private key when the seed holds it
static sp_psbt_result_t classify_input(const struct wally_psbt *psbt, size_t i,
                                       const signer_t *signer,
                                       input_set_t *set) {
  const struct wally_psbt_input *in = &psbt->inputs[i];
  sp_input_t *input = &set->inputs[i];
  const struct wally_tx_output *prevout = NULL;
  bool owned = false;
  sp_psbt_result_t result = input_prevout(in, &prevout);

  if (result != SP_PSBT_OK)
    return result;
  if (is_future_witness_version(prevout))
    return SP_PSBT_ERR_INPUT;
  // Any other sighash lets a signer change outputs derived from the inputs
  if (in->sighash && in->sighash != WALLY_SIGHASH_ALL)
    return SP_PSBT_ERR_SIGHASH;
  result = input_eligibility(psbt, i, prevout, &input->eligible);
  if (result != SP_PSBT_OK || !input->eligible)
    return result;
  set->eligible++;
  result = input_signing_key(psbt, i, prevout, signer, &owned, set->keys[i]);
  if (result != SP_PSBT_OK)
    return result;
  if (!owned)
    return foreign_input_key(psbt, i, prevout, input->pubkey);
  input->owned = true;
  set->owned++;
  return secret_pubkey(set->keys[i], input->pubkey) ? SP_PSBT_OK
                                                    : SP_PSBT_ERR_CRYPTO;
}

static void input_set_free(input_set_t *set) {
  if (set->keys) {
    secure_memzero(set->keys, set->count * sizeof(*set->keys));
    free(set->keys);
  }
  free(set->inputs);
  memset(set, 0, sizeof(*set));
}

// BIP352 needs at least one eligible input, whoever holds it
static sp_psbt_result_t collect_inputs(const struct wally_psbt *psbt,
                                       const signer_t *signer,
                                       input_set_t *set) {
  sp_psbt_result_t result = SP_PSBT_OK;

  memset(set, 0, sizeof(*set));
  set->count = psbt->num_inputs;
  set->inputs = calloc(set->count, sizeof(*set->inputs));
  set->keys = kern_secret_alloc(set->count * sizeof(*set->keys));
  if (!set->inputs || !set->keys)
    result = SP_PSBT_ERR_CRYPTO;
  for (size_t i = 0; result == SP_PSBT_OK && i < set->count; i++)
    result = classify_input(psbt, i, signer, set);
  if (result == SP_PSBT_OK && !set->eligible)
    result = SP_PSBT_ERR_INPUT;
  if (result != SP_PSBT_OK)
    input_set_free(set);
  return result;
}

static bool owns_all_inputs(const input_set_t *set) {
  return set->owned == set->eligible;
}

static bool sum_owned_keys(const input_set_t *set, unsigned char *sum) {
  bool first = true;
  for (size_t i = 0; i < set->count; i++) {
    if (!set->inputs[i].owned)
      continue;
    if (first)
      memcpy(sum, set->keys[i], SP_SECRET_LEN);
    else if (!secp256k1_ec_seckey_tweak_add(secp_ctx(), sum, set->keys[i]))
      return false;
    first = false;
  }
  return !first;
}

// A_sum, the sum of every eligible input's public key
static sp_psbt_result_t sum_input_keys(const input_set_t *set,
                                       secp256k1_pubkey *sum) {
  secp256k1_pubkey *keys = calloc(set->eligible, sizeof(*keys));
  const secp256k1_pubkey **ptrs = calloc(set->eligible, sizeof(*ptrs));
  sp_psbt_result_t result = keys && ptrs ? SP_PSBT_OK : SP_PSBT_ERR_CRYPTO;
  size_t n = 0;

  for (size_t i = 0; result == SP_PSBT_OK && i < set->count; i++) {
    if (!set->inputs[i].eligible)
      continue;
    if (!parse_point(set->inputs[i].pubkey, &keys[n]))
      result = SP_PSBT_ERR_INPUT_KEY;
    ptrs[n] = &keys[n];
    n++;
  }
  if (result == SP_PSBT_OK &&
      !secp256k1_ec_pubkey_combine(secp_ctx(), sum, ptrs, n))
    result = SP_PSBT_ERR_CRYPTO;
  free(keys);
  free(ptrs);
  return result;
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

// Where a scope keeps its shares and proofs: the global map or an input's
typedef struct {
  unsigned char share;
  unsigned char proof;
} share_types_t;

static const share_types_t GLOBAL_SHARE = {PSBT_GLOBAL_SP_ECDH_SHARE,
                                           PSBT_GLOBAL_SP_DLEQ};
static const share_types_t INPUT_SHARE = {PSBT_IN_SP_ECDH_SHARE,
                                          PSBT_IN_SP_DLEQ};

// Every share in `map` has its proof and every proof its share, each of its
// length (bip375.rs validate_share_maps)
static bool share_map_is_paired(const struct wally_map *map,
                                share_types_t types) {
  for (size_t i = 0; i < map->num_items; i++) {
    const struct wally_map_item *item = &map->items[i];
    bool is_share = is_field_type(item, types.share);
    if (!is_share && !is_field_type(item, types.proof))
      continue;
    if (item->key_len != SHARE_KEY_LEN ||
        item->value_len != (is_share ? SP_PUBKEY_LEN : DLEQ_PROOF_LEN) ||
        !find_scan_field(map, is_share ? types.proof : types.share,
                         item->key + 1))
      return false;
  }
  return true;
}

static bool share_maps_are_paired(const struct wally_psbt *psbt) {
  if (!share_map_is_paired(&psbt->unknowns, GLOBAL_SHARE))
    return false;
  for (size_t i = 0; i < psbt->num_inputs; i++)
    if (!share_map_is_paired(&psbt->inputs[i].unknowns, INPUT_SHARE))
      return false;
  return true;
}

// H(rng || secret || B_scan): a weak RNG still yields a proof nonce bound to
// the secret it proves (embit _default_aux_rand)
static bool hedged_aux(const unsigned char *secret, const unsigned char *scan,
                       unsigned char *aux_out) {
  unsigned char buf[DLEQ_AUX_LEN + SP_SECRET_LEN + SP_PUBKEY_LEN];
  bool ok = crypto_random_bytes(buf, DLEQ_AUX_LEN) == CRYPTO_OK;

  memcpy(buf + DLEQ_AUX_LEN, secret, SP_SECRET_LEN);
  memcpy(buf + DLEQ_AUX_LEN + SP_SECRET_LEN, scan, SP_PUBKEY_LEN);
  ok = ok && secp256k1_tagged_sha256(
                 secp_ctx(), aux_out, (const unsigned char *)DLEQ_AUX_HEDGE_TAG,
                 sizeof(DLEQ_AUX_HEDGE_TAG) - 1, buf, sizeof(buf)) == 1;
  secure_memzero(buf, sizeof(buf));
  return ok;
}

// BIP375 fixes the DLEQ generator to G
static bool dleq_generator(secp256k1_pubkey *out) {
  return secp256k1_ec_pubkey_create(secp_ctx(), out, SCALAR_ONE) == 1;
}

// The share and proof `map` holds for `scan`, if any, must prove the share
// is the discrete log of `public` times the scan key
static sp_psbt_result_t check_declared_share(const struct wally_map *map,
                                             share_types_t types,
                                             const unsigned char *scan,
                                             const unsigned char *public,
                                             bool *declared) {
  const struct wally_map_item *share = find_scan_field(map, types.share, scan);
  const struct wally_map_item *proof = find_scan_field(map, types.proof, scan);
  secp256k1_pubkey public_point, scan_point, share_point, generator;

  *declared = share != NULL;
  if (!share)
    return SP_PSBT_OK;
  if (!proof || !parse_point(public, &public_point) ||
      !parse_point(scan, &scan_point) ||
      !parse_point(share->value, &share_point))
    return SP_PSBT_ERR_FIELD;
  if (!dleq_generator(&generator))
    return SP_PSBT_ERR_CRYPTO;
  return dleq_verify(&public_point, &scan_point, &share_point, proof->value,
                     &generator, NULL)
             ? SP_PSBT_OK
             : SP_PSBT_ERR_FIELD;
}

// share = secret*B_scan and its DLEQ proof, unless `map` already holds a
// share, which must then verify against `public`
static sp_psbt_result_t write_share(struct wally_map *map, share_types_t types,
                                    const unsigned char *scan,
                                    const unsigned char *secret,
                                    const unsigned char *public) {
  secp256k1_pubkey scan_point, share, generator;
  unsigned char share_bytes[SP_PUBKEY_LEN], proof[DLEQ_PROOF_LEN];
  unsigned char aux[DLEQ_AUX_LEN];
  bool declared = false, ok;
  sp_psbt_result_t result =
      check_declared_share(map, types, scan, public, &declared);

  if (result != SP_PSBT_OK || declared)
    return result;
  if (!parse_point(scan, &scan_point))
    return SP_PSBT_ERR_FIELD;
  share = scan_point;
  ok = secp256k1_ec_pubkey_tweak_mul(secp_ctx(), &share, secret) &&
       serialize_point(&share, share_bytes) && dleq_generator(&generator) &&
       hedged_aux(secret, scan, aux) &&
       dleq_prove(secret, &scan_point, aux, &generator, NULL, proof) &&
       set_scan_field(map, types.share, scan, share_bytes,
                      sizeof(share_bytes)) &&
       set_scan_field(map, types.proof, scan, proof, sizeof(proof));
  secure_memzero(aux, sizeof(aux));
  return ok ? SP_PSBT_OK : SP_PSBT_ERR_CRYPTO;
}

// Holding every eligible input, one global share of a_sum (signer.rs
// write_shares)
static sp_psbt_result_t write_global_share(struct wally_psbt *psbt,
                                           const input_set_t *set,
                                           const unsigned char *scan,
                                           const unsigned char *input_sum) {
  unsigned char sum[SP_SECRET_LEN];
  sp_psbt_result_t result =
      sum_owned_keys(set, sum)
          ? write_share(&psbt->unknowns, GLOBAL_SHARE, scan, sum, input_sum)
          : SP_PSBT_ERR_CRYPTO;
  secure_memzero(sum, sizeof(sum));
  return result;
}

// Holding some eligible inputs, a share of each, and the other signers'
// shares checked against their inputs' keys (signer.rs
// write_input_ecdh_share)
static sp_psbt_result_t write_input_shares(struct wally_psbt *psbt,
                                           const input_set_t *set,
                                           const unsigned char *scan,
                                           const unsigned char *input_sum) {
  bool declared = false;
  sp_psbt_result_t result = check_declared_share(&psbt->unknowns, GLOBAL_SHARE,
                                                 scan, input_sum, &declared);

  for (size_t i = 0; result == SP_PSBT_OK && i < set->count; i++) {
    const sp_input_t *input = &set->inputs[i];
    struct wally_map *map = &psbt->inputs[i].unknowns;
    if (input->owned)
      result = write_share(map, INPUT_SHARE, scan, set->keys[i], input->pubkey);
    else if (input->eligible)
      result = check_declared_share(map, INPUT_SHARE, scan, input->pubkey,
                                    &declared);
  }
  return result;
}

// One pass per distinct scan key, recipients being sorted by scan key
static sp_psbt_result_t write_shares(struct wally_psbt *psbt,
                                     const input_set_t *set,
                                     const sp_recipient_t *recipients,
                                     size_t count,
                                     const unsigned char *input_sum) {
  sp_psbt_result_t result = SP_PSBT_OK;
  for (size_t i = 0; result == SP_PSBT_OK && i < count; i++) {
    const unsigned char *scan = recipients[i].scan;
    if (i && !memcmp(scan, recipients[i - 1].scan, SP_PUBKEY_LEN))
      continue;
    result = owns_all_inputs(set)
                 ? write_global_share(psbt, set, scan, input_sum)
                 : write_input_shares(psbt, set, scan, input_sum);
  }
  return result;
}

// The share every eligible input adds up to for `scan`: the global one, else
// the sum of the per-input ones. *complete is false while an eligible input
// still has none (bip375.rs combined_share).
static sp_psbt_result_t combined_share(const struct wally_psbt *psbt,
                                       const input_set_t *set,
                                       const unsigned char *scan,
                                       secp256k1_pubkey *out, bool *complete) {
  const struct wally_map_item *global =
      find_scan_field(&psbt->unknowns, PSBT_GLOBAL_SP_ECDH_SHARE, scan);
  secp256k1_pubkey *shares;
  const secp256k1_pubkey **ptrs;
  sp_psbt_result_t result = SP_PSBT_OK;
  size_t n = 0;

  *complete = true;
  if (global)
    return parse_point(global->value, out) ? SP_PSBT_OK : SP_PSBT_ERR_FIELD;
  shares = calloc(set->eligible, sizeof(*shares));
  ptrs = calloc(set->eligible, sizeof(*ptrs));
  if (!shares || !ptrs)
    result = SP_PSBT_ERR_CRYPTO;
  for (size_t i = 0; result == SP_PSBT_OK && *complete && i < set->count; i++) {
    const struct wally_map_item *share;
    if (!set->inputs[i].eligible)
      continue;
    share =
        find_scan_field(&psbt->inputs[i].unknowns, PSBT_IN_SP_ECDH_SHARE, scan);
    if (!share)
      *complete = false;
    else if (!parse_point(share->value, &shares[n]))
      result = SP_PSBT_ERR_FIELD;
    ptrs[n] = &shares[n];
    n++;
  }
  if (result == SP_PSBT_OK && *complete &&
      !secp256k1_ec_pubkey_combine(secp_ctx(), out, ptrs, n))
    result = SP_PSBT_ERR_CRYPTO;
  free(shares);
  free(ptrs);
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

// input_hash = hash_BIP0352/Inputs(outpoint_L || A_sum)
static bool input_hash(const struct wally_psbt *psbt,
                       const unsigned char *input_sum, unsigned char *out) {
  unsigned char buf[OUTPOINT_LEN + SP_PUBKEY_LEN];
  smallest_outpoint(psbt, buf);
  memcpy(buf + OUTPOINT_LEN, input_sum, SP_PUBKEY_LEN);
  return secp256k1_tagged_sha256(
             secp_ctx(), out, (const unsigned char *)BIP352_INPUTS_TAG,
             sizeof(BIP352_INPUTS_TAG) - 1, buf, sizeof(buf)) == 1;
}

// P_k = B_spend + t_k*G, t_k = hash_BIP0352/SharedSecret(ser(S) || ser32(k))
// with S = input_hash*share: BIP352's output key, from the shares alone
static bool output_key(const unsigned char *shared_secret,
                       const unsigned char *spend, uint32_t k,
                       secp256k1_xonly_pubkey *out) {
  unsigned char buf[SP_PUBKEY_LEN + sizeof(uint32_t)], tweak[SP_SECRET_LEN];
  secp256k1_pubkey point;
  bool ok;

  memcpy(buf, shared_secret, SP_PUBKEY_LEN);
  buf[SP_PUBKEY_LEN] = (k >> 24) & 0xff;
  buf[SP_PUBKEY_LEN + 1] = (k >> 16) & 0xff;
  buf[SP_PUBKEY_LEN + 2] = (k >> 8) & 0xff;
  buf[SP_PUBKEY_LEN + 3] = k & 0xff;
  ok = secp256k1_tagged_sha256(
           secp_ctx(), tweak, (const unsigned char *)BIP352_SHARED_SECRET_TAG,
           sizeof(BIP352_SHARED_SECRET_TAG) - 1, buf, sizeof(buf)) &&
       parse_point(spend, &point) &&
       secp256k1_ec_pubkey_tweak_add(secp_ctx(), &point, tweak) &&
       secp256k1_xonly_pubkey_from_pubkey(secp_ctx(), out, NULL, &point);
  secure_memzero(buf, sizeof(buf));
  secure_memzero(tweak, sizeof(tweak));
  return ok;
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

// S = input_hash*share for the group of `scan`
static sp_psbt_result_t
group_shared_secret(const struct wally_psbt *psbt, const input_set_t *set,
                    const unsigned char *scan, const unsigned char *hash,
                    unsigned char *out, bool *complete) {
  secp256k1_pubkey share;
  sp_psbt_result_t result = combined_share(psbt, set, scan, &share, complete);

  if (result != SP_PSBT_OK || !*complete)
    return result;
  return secp256k1_ec_pubkey_tweak_mul(secp_ctx(), &share, hash) &&
                 serialize_point(&share, out)
             ? SP_PSBT_OK
             : SP_PSBT_ERR_CRYPTO;
}

// The scripts of a group whose shares are all in, k counting up in the
// recipients' order. A group still waiting for a share keeps its outputs
// scriptless: a script set there could not be checked (bip375.rs
// output_scripts).
static sp_psbt_result_t fill_group_scripts(struct wally_psbt *psbt,
                                           const sp_recipient_t *group,
                                           size_t len,
                                           const unsigned char *shared_secret,
                                           bool complete) {
  secp256k1_xonly_pubkey key;
  sp_psbt_result_t result = SP_PSBT_OK;

  for (size_t k = 0; result == SP_PSBT_OK && k < len; k++) {
    if (!complete)
      result = psbt->outputs[group[k].output_index].script ? SP_PSBT_ERR_SCRIPT
                                                           : SP_PSBT_OK;
    else if (!output_key(shared_secret, group[k].spend, (uint32_t)k, &key))
      result = SP_PSBT_ERR_CRYPTO;
    else
      result = set_output_script(psbt, group[k].output_index, &key);
  }
  return result;
}

static size_t group_len(const sp_recipient_t *recipients, size_t count) {
  size_t len = 1;
  while (len < count &&
         !memcmp(recipients[len].scan, recipients[0].scan, SP_PUBKEY_LEN))
    len++;
  return len;
}

// The scripts of every group whose shares are all in. *pending says whether
// a group still waits for another signer's share.
static sp_psbt_result_t
fill_output_scripts(struct wally_psbt *psbt, const input_set_t *set,
                    const sp_recipient_t *recipients, size_t count,
                    const unsigned char *input_sum, bool *pending) {
  unsigned char hash[SHA256_LEN], shared_secret[SP_PUBKEY_LEN];
  sp_psbt_result_t result =
      input_hash(psbt, input_sum, hash) ? SP_PSBT_OK : SP_PSBT_ERR_CRYPTO;
  size_t len;

  *pending = false;
  for (size_t i = 0; result == SP_PSBT_OK && i < count; i += len) {
    bool complete = false;
    len = group_len(recipients + i, count - i);
    // BIP352 fails a group above K_max addresses
    if (len > SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT) {
      result = SP_PSBT_ERR_FIELD;
      break;
    }
    result = group_shared_secret(psbt, set, recipients[i].scan, hash,
                                 shared_secret, &complete);
    if (result == SP_PSBT_OK)
      result = fill_group_scripts(psbt, recipients + i, len, shared_secret,
                                  complete);
    *pending = *pending || !complete;
  }
  secure_memzero(shared_secret, sizeof(shared_secret));
  return result;
}

// The parse let scriptless outputs through, so every check it skipped runs
// again on the completed PSBT
static sp_psbt_result_t reparse_strict(struct wally_psbt **psbt) {
  struct wally_psbt *strict = NULL;
  unsigned char *bytes = NULL;
  size_t len = 0, written = 0;
  bool ok = wally_psbt_get_length(*psbt, 0, &len) == WALLY_OK &&
            (bytes = malloc(len)) != NULL &&
            wally_psbt_to_bytes(*psbt, 0, bytes, len, &written) == WALLY_OK &&
            kern_psbt_from_bytes(bytes, written, WALLY_PSBT_PARSE_FLAG_COMPLETE,
                                 &strict) == WALLY_OK;
  free(bytes);
  if (!ok)
    return SP_PSBT_ERR_PSBT;
  wally_psbt_free(*psbt);
  *psbt = strict;
  return SP_PSBT_OK;
}

// The inputs of `psbt` as BIP352 sees them, for the seed's keys
static sp_psbt_result_t classify_inputs(const struct wally_psbt *psbt,
                                        const struct sp_keys *keys,
                                        input_set_t *set) {
  signer_t signer = {.keys = keys};
  if (!key_get_fingerprint(signer.fingerprint))
    return SP_PSBT_ERR_KEYS;
  return collect_inputs(psbt, &signer, set);
}

static bool sp_scripts_set(const struct wally_psbt *psbt) {
  for (size_t i = 0; i < psbt->num_outputs; i++)
    if (psbt->outputs[i].script && output_has_info(&psbt->outputs[i]))
      return true;
  return false;
}

// A script already set means its setter froze the inputs and outputs it
// depends on (BIP375 signer rule)
static bool preset_scripts_frozen(const struct wally_psbt *psbt) {
  return !sp_scripts_set(psbt) ||
         !(psbt->tx_modifiable_flags &
           (WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS));
}

static sp_psbt_result_t complete_with_keys(struct wally_psbt *psbt,
                                           const struct sp_keys *keys,
                                           bool *pending) {
  sp_recipient_t *recipients = NULL;
  size_t count = 0;
  input_set_t set = {0};
  secp256k1_pubkey input_point;
  unsigned char input_sum[SP_PUBKEY_LEN];
  sp_psbt_result_t result = collect_recipients(psbt, &recipients, &count);

  if (result == SP_PSBT_OK &&
      (!share_maps_are_paired(psbt) || !preset_scripts_frozen(psbt)))
    result = SP_PSBT_ERR_FIELD;
  if (result == SP_PSBT_OK)
    result = classify_inputs(psbt, keys, &set);
  if (result == SP_PSBT_OK)
    result = sum_input_keys(&set, &input_point);
  if (result == SP_PSBT_OK && !serialize_point(&input_point, input_sum))
    result = SP_PSBT_ERR_CRYPTO;
  if (result == SP_PSBT_OK)
    result = write_shares(psbt, &set, recipients, count, input_sum);
  if (result == SP_PSBT_OK)
    result =
        fill_output_scripts(psbt, &set, recipients, count, input_sum, pending);
  // The scripts depend on the exact input and output sets, so freeze both
  // once one is set
  if (result == SP_PSBT_OK && sp_scripts_set(psbt) &&
      wally_psbt_set_tx_modifiable_flags(psbt, 0) != WALLY_OK)
    result = SP_PSBT_ERR_PSBT;
  input_set_free(&set);
  free(recipients);
  return result;
}

// No PSBT_OUT_SP_V0_LABEL without its PSBT_OUT_SP_V0_INFO, which a PSBT with
// no silent payment output could still carry
static bool outputs_well_formed(const struct wally_psbt *psbt) {
  const unsigned char *info = NULL;
  for (size_t i = 0; i < psbt->num_outputs; i++)
    if (read_output_info(&psbt->outputs[i], &info) != SP_PSBT_OK)
      return false;
  return true;
}

sp_psbt_result_t sp_psbt_complete(struct wally_psbt **psbt, bool is_testnet) {
  struct wally_psbt *completed = NULL;
  struct sp_keys keys;
  bool pending = false;
  sp_psbt_result_t result;

  if (!psbt || !*psbt)
    return SP_PSBT_ERR_PSBT;
  // BIP375 and BIP376 fields only exist in PSBTv2
  if ((*psbt)->version != WALLY_PSBT_VERSION_2 && sp_psbt_has_fields(*psbt))
    return SP_PSBT_ERR_PSBT;
  if (!sp_psbt_has_outputs(*psbt))
    return outputs_well_formed(*psbt) ? SP_PSBT_OK : SP_PSBT_ERR_FIELD;
  if (!sp_keys_derive(is_testnet, &keys))
    return SP_PSBT_ERR_KEYS;
  // Completed on a copy, so a refused PSBT is left as it came
  result = kern_psbt_clone_alloc(*psbt, 0, &completed) == WALLY_OK
               ? complete_with_keys(completed, &keys, &pending)
               : SP_PSBT_ERR_PSBT;
  sp_keys_wipe(&keys);
  // A pending PSBT keeps scriptless outputs, which only parse loosely
  if (result == SP_PSBT_OK && !pending)
    result = reparse_strict(&completed);
  if (result != SP_PSBT_OK) {
    wally_psbt_free(completed);
    return result;
  }
  wally_psbt_free(*psbt);
  *psbt = completed;
  return pending ? SP_PSBT_PENDING : SP_PSBT_OK;
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

static bool is_labeled_spend_key(const struct sp_keys *keys, uint32_t m,
                                 const unsigned char *spend) {
  unsigned char labeled[SP_PUBKEY_LEN];
  return sp_labeled_spend_pubkey(keys->scan_secret, keys->spend_pubkey, m,
                                 labeled) &&
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

  if (!from || !to || from->num_inputs != to->num_inputs ||
      from->num_outputs != to->num_outputs)
    return false;
  if (!sp_psbt_has_outputs(from))
    return true;
  if (!copy_fields(&from->unknowns, &to->unknowns, PSBT_GLOBAL_SP_ECDH_SHARE,
                   PSBT_GLOBAL_SP_DLEQ))
    return false;
  for (size_t i = 0; i < from->num_inputs; i++)
    if (!copy_fields(&from->inputs[i].unknowns, &to->inputs[i].unknowns,
                     PSBT_IN_SP_ECDH_SHARE, PSBT_IN_SP_DLEQ))
      return false;
  for (size_t i = 0; i < from->num_outputs; i++)
    if (!copy_fields(&from->outputs[i].unknowns, &to->outputs[i].unknowns,
                     PSBT_OUT_SP_V0_INFO, PSBT_OUT_SP_V0_LABEL))
      return false;
  return to->tx_modifiable_flags ||
         wally_map_replace(&to->unknowns, &tx_modifiable, 1, &frozen, 1) ==
             WALLY_OK;
}

static bool share_listed(const sp_share_t *shares, size_t count,
                         const unsigned char *scan) {
  for (size_t i = 0; i < count; i++)
    if (memcmp(shares[i].scan, scan, SP_PUBKEY_LEN) == 0)
      return true;
  return false;
}

static bool read_share(const struct wally_map *map, share_types_t types,
                       const unsigned char *scan, sp_share_t *out) {
  const struct wally_map_item *share = find_scan_field(map, types.share, scan);
  const struct wally_map_item *proof = find_scan_field(map, types.proof, scan);
  if (!share || !proof || share->value_len != SP_PUBKEY_LEN ||
      proof->value_len != DLEQ_PROOF_LEN)
    return false;
  memcpy(out->scan, scan, SP_PUBKEY_LEN);
  memcpy(out->share, share->value, SP_PUBKEY_LEN);
  memcpy(out->proof, proof->value, DLEQ_PROOF_LEN);
  return true;
}

// The shares of `scan` the seed contributed: the global one, or one per
// eligible input it holds
static bool read_scan_shares(const struct wally_psbt *psbt,
                             const input_set_t *set, const unsigned char *scan,
                             sp_share_t *shares, size_t *n) {
  if (owns_all_inputs(set)) {
    shares[*n].global = true;
    shares[*n].input_index = 0;
    return read_share(&psbt->unknowns, GLOBAL_SHARE, scan, &shares[(*n)++]);
  }
  for (size_t i = 0; i < set->count; i++) {
    if (!set->inputs[i].owned)
      continue;
    shares[*n].global = false;
    shares[*n].input_index = i;
    if (!read_share(&psbt->inputs[i].unknowns, INPUT_SHARE, scan,
                    &shares[(*n)++]))
      return false;
  }
  return true;
}

static bool collect_shares(const struct wally_psbt *psbt,
                           const input_set_t *set, sp_share_t *shares,
                           size_t *n) {
  unsigned char scan[SP_PUBKEY_LEN], spend[SP_PUBKEY_LEN];
  for (size_t i = 0; i < psbt->num_outputs; i++) {
    if (!sp_output_keys(&psbt->outputs[i], scan, spend) ||
        share_listed(shares, *n, scan))
      continue;
    if (!read_scan_shares(psbt, set, scan, shares, n))
      return false;
  }
  return true;
}

bool sp_psbt_shares_alloc(const struct wally_psbt *psbt, bool is_testnet,
                          sp_share_t **out, size_t *count) {
  struct sp_keys keys;
  input_set_t set = {0};
  sp_share_t *shares = NULL;
  size_t n = 0;
  bool ok;

  *out = NULL;
  *count = 0;
  if (!psbt || !sp_psbt_has_outputs(psbt) || !sp_keys_derive(is_testnet, &keys))
    return false;
  ok = classify_inputs(psbt, &keys, &set) == SP_PSBT_OK;
  sp_keys_wipe(&keys);
  if (!ok)
    return false;
  if (set.owned) {
    shares = calloc(psbt->num_outputs * set.owned, sizeof(*shares));
    ok = shares && collect_shares(psbt, &set, shares, &n);
  }
  input_set_free(&set);
  if (!ok) {
    free(shares);
    return false;
  }
  *out = shares;
  *count = n;
  return true;
}

// A read position in a serialized PSBT
typedef struct {
  const uint8_t *pos;
  const uint8_t *end;
} raw_cursor_t;

// One key-value pair of a serialized PSBT map
typedef struct {
  const uint8_t *key;
  size_t key_len;
  const uint8_t *value;
  size_t value_len;
} raw_pair_t;

static bool read_compact_size(raw_cursor_t *c, size_t *out) {
  size_t width, value = 0;

  if (c->pos >= c->end)
    return false;
  switch (*c->pos) {
  case 0xfd:
    width = 2;
    break;
  case 0xfe:
    width = 4;
    break;
  case 0xff:
    width = 8;
    break;
  default:
    *out = *c->pos++;
    return true;
  }
  c->pos++;
  if ((size_t)(c->end - c->pos) < width)
    return false;
  for (size_t i = width; i > 0; i--)
    value = (value << 8) | c->pos[i - 1];
  c->pos += width;
  *out = value;
  return true;
}

static bool read_bytes(raw_cursor_t *c, const uint8_t **out, size_t *len) {
  if (!read_compact_size(c, len) || *len > (size_t)(c->end - c->pos))
    return false;
  *out = c->pos;
  c->pos += *len;
  return true;
}

// Reads the next pair of a map: 1 for a pair, 0 at the map's separator, -1
// for a malformed map
static int read_pair(raw_cursor_t *c, raw_pair_t *pair) {
  raw_cursor_t peek = *c;
  size_t key_len = 0;

  if (!read_compact_size(&peek, &key_len))
    return -1;
  if (!key_len) {
    *c = peek;
    return 0;
  }
  return read_bytes(c, &pair->key, &pair->key_len) &&
                 read_bytes(c, &pair->value, &pair->value_len)
             ? 1
             : -1;
}

static bool skip_map(raw_cursor_t *c) {
  raw_pair_t pair;
  int read;
  while ((read = read_pair(c, &pair)) == 1)
    ;
  return read == 0;
}

static bool pair_is(const raw_pair_t *pair, uint8_t type) {
  return pair->key_len == 1 && pair->key[0] == type;
}

static bool input_map_sighash_is_all(raw_cursor_t *c) {
  raw_pair_t pair;
  int read;
  while ((read = read_pair(c, &pair)) == 1)
    if (pair_is(&pair, PSBT_IN_SIGHASH_TYPE) &&
        (pair.value_len != SIGHASH_TYPE_LEN ||
         bip32_path_u32_le(pair.value) != WALLY_SIGHASH_ALL))
      return false;
  return read == 0;
}

bool sp_psbt_raw_sighash_is_all(const uint8_t *data, size_t len,
                                size_t num_inputs) {
  raw_cursor_t c;

  if (!data || len < PSBT_MAGIC_LEN)
    return false;
  c.pos = data + PSBT_MAGIC_LEN;
  c.end = data + len;
  if (!skip_map(&c))
    return false;
  for (size_t i = 0; i < num_inputs; i++)
    if (!input_map_sighash_is_all(&c))
      return false;
  return true;
}

// Copies the pairs of one map, PSBT_OUT_SCRIPT left out when `drop_script`
static bool copy_raw_map(raw_cursor_t *c, bool drop_script, uint8_t **dst) {
  raw_pair_t pair;
  for (;;) {
    const uint8_t *start = c->pos;
    int read = read_pair(c, &pair);
    if (read < 0)
      return false;
    if (!read || !(drop_script && pair_is(&pair, PSBT_OUT_SCRIPT))) {
      memcpy(*dst, start, (size_t)(c->pos - start));
      *dst += c->pos - start;
    }
    if (!read)
      return true;
  }
}

static bool output_is_pending(const struct wally_psbt_output *out) {
  return !out->script && output_has_info(out);
}

// libwally serializes no PSBTv2 output without a script, so a pending
// output gets PLACEHOLDER_SCRIPT, cut out of the bytes again
static bool serialize_with_placeholders(const struct wally_psbt *psbt,
                                        uint8_t **out, size_t *out_len) {
  static const unsigned char PLACEHOLDER_SCRIPT[] = {OP_RETURN};
  struct wally_psbt *copy = NULL;
  size_t len = 0;
  bool ok = kern_psbt_clone_alloc(psbt, 0, &copy) == WALLY_OK;

  for (size_t i = 0; ok && i < copy->num_outputs; i++)
    if (output_is_pending(&psbt->outputs[i]))
      ok = wally_psbt_output_set_script(&copy->outputs[i], PLACEHOLDER_SCRIPT,
                                        sizeof(PLACEHOLDER_SCRIPT)) == WALLY_OK;
  ok = ok && wally_psbt_get_length(copy, 0, &len) == WALLY_OK &&
       (*out = malloc(len)) != NULL &&
       wally_psbt_to_bytes(copy, 0, *out, len, out_len) == WALLY_OK;
  wally_psbt_free(copy);
  return ok;
}

bool sp_psbt_serialize_alloc(const struct wally_psbt *psbt, uint8_t **out,
                             size_t *out_len) {
  uint8_t *bytes = NULL, *stripped = NULL, *dst;
  size_t len = 0;
  raw_cursor_t c;
  bool ok;

  *out = NULL;
  *out_len = 0;
  if (!psbt || !serialize_with_placeholders(psbt, &bytes, &len) ||
      len < PSBT_MAGIC_LEN || !(stripped = malloc(len))) {
    free(bytes);
    return false;
  }
  memcpy(stripped, bytes, PSBT_MAGIC_LEN);
  dst = stripped + PSBT_MAGIC_LEN;
  c.pos = bytes + PSBT_MAGIC_LEN;
  c.end = bytes + len;
  ok = copy_raw_map(&c, false, &dst);
  for (size_t i = 0; ok && i < psbt->num_inputs; i++)
    ok = copy_raw_map(&c, false, &dst);
  for (size_t i = 0; ok && i < psbt->num_outputs; i++)
    ok = copy_raw_map(&c, output_is_pending(&psbt->outputs[i]), &dst);
  free(bytes);
  if (!ok || c.pos != c.end) {
    free(stripped);
    return false;
  }
  *out = stripped;
  *out_len = (size_t)(dst - stripped);
  return true;
}

bool sp_psbt_base64_alloc(const struct wally_psbt *psbt, char **out) {
  uint8_t *bytes = NULL;
  size_t len = 0;
  bool ok = sp_psbt_serialize_alloc(psbt, &bytes, &len) &&
            wally_base64_from_bytes(bytes, len, 0, out) == WALLY_OK;
  free(bytes);
  return ok;
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
  case SP_PSBT_PENDING:
    return "Waiting for the other signers' silent payment shares";
  case SP_PSBT_ERR_INPUT_KEY:
    return "An input names no key its script commits to";
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
