#include "silent_payments.h"
#include "../utils/secure_mem.h"
#include "key.h"
#include <kern_bech32.h>
#include <secp256k1.h>
#include <secp256k1_silentpayments.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>

#define SP_PURPOSE 352
#define SP_ACCOUNT 0
#define SP_PATH_DEPTH 5
#define SP_VERSION 0

static uint32_t sp_coin(bool is_testnet) { return is_testnet ? 1 : 0; }

// m/352'/coin'/0'/branch'/0
static bool derive_sp_key(bool is_testnet, uint32_t branch,
                          unsigned char *secret_out,
                          unsigned char *pubkey_out) {
  const uint32_t path[SP_PATH_DEPTH] = {
      BIP32_INITIAL_HARDENED_CHILD | SP_PURPOSE,
      BIP32_INITIAL_HARDENED_CHILD | sp_coin(is_testnet),
      BIP32_INITIAL_HARDENED_CHILD | SP_ACCOUNT,
      BIP32_INITIAL_HARDENED_CHILD | branch, 0};
  struct ext_key *key = NULL;

  if (!key_get_derived_key_components(path, SP_PATH_DEPTH, &key))
    return false;
  // priv_key carries a leading 0x00 before the 32-byte secret
  memcpy(secret_out, key->priv_key + 1, SP_SECRET_LEN);
  memcpy(pubkey_out, key->pub_key, SP_PUBKEY_LEN);
  bip32_key_free(key);
  return true;
}

bool sp_keys_derive(bool is_testnet, struct sp_keys *out) {
  if (!out)
    return false;
  if (derive_sp_key(is_testnet, SP_SCAN_BRANCH, out->scan_secret,
                    out->scan_pubkey) &&
      derive_sp_key(is_testnet, SP_SPEND_BRANCH, out->spend_secret,
                    out->spend_pubkey))
    return true;
  sp_keys_wipe(out);
  return false;
}

void sp_keys_wipe(struct sp_keys *keys) { secure_memzero(keys, sizeof(*keys)); }

bool sp_path_on_branch(const uint32_t *path, size_t len, bool is_testnet,
                       uint32_t branch) {
  return path && len == SP_PATH_DEPTH &&
         path[0] == (BIP32_INITIAL_HARDENED_CHILD | SP_PURPOSE) &&
         path[1] == (BIP32_INITIAL_HARDENED_CHILD | sp_coin(is_testnet)) &&
         path[2] == (BIP32_INITIAL_HARDENED_CHILD | SP_ACCOUNT) &&
         path[3] == (BIP32_INITIAL_HARDENED_CHILD | branch);
}

bool sp_address_alloc(const unsigned char *scan_pubkey,
                      const unsigned char *spend_pubkey, bool is_testnet,
                      char **out) {
  unsigned char payload[2 * SP_PUBKEY_LEN];
  char address[KERN_BECH32M_MAX_LEN + 1];

  if (!scan_pubkey || !spend_pubkey || !out)
    return false;
  memcpy(payload, scan_pubkey, SP_PUBKEY_LEN);
  memcpy(payload + SP_PUBKEY_LEN, spend_pubkey, SP_PUBKEY_LEN);
  if (kern_bech32m_encode(is_testnet ? "tsp" : "sp", SP_VERSION, payload,
                          sizeof(payload), address,
                          sizeof(address)) != WALLY_OK)
    return false;
  *out = strdup(address);
  return *out != NULL;
}

static bool serialize_point(const secp256k1_pubkey *point, unsigned char *out) {
  size_t len = SP_PUBKEY_LEN;
  return secp256k1_ec_pubkey_serialize(wally_get_secp_context(), out, &len,
                                       point, SECP256K1_EC_COMPRESSED) == 1;
}

bool sp_labeled_spend_pubkey(const unsigned char *scan_secret,
                             const unsigned char *spend_pubkey, uint32_t m,
                             unsigned char *out) {
  const secp256k1_context *ctx = wally_get_secp_context();
  secp256k1_silentpayments_label label;
  secp256k1_pubkey spend, labeled;
  unsigned char label_tweak[SP_SECRET_LEN];
  bool ok =
      secp256k1_silentpayments_recipient_label_create(ctx, &label, label_tweak,
                                                      scan_secret, m) &&
      secp256k1_ec_pubkey_parse(ctx, &spend, spend_pubkey, SP_PUBKEY_LEN) &&
      secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
          ctx, &labeled, &spend, &label) &&
      serialize_point(&labeled, out);
  secure_memzero(label_tweak, sizeof(label_tweak));
  return ok;
}
