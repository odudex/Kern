#include "silent_payments.h"
#include "../utils/secure_mem.h"
#include "descriptor_checksum.h"
#include "key.h"
#include <kern_bech32.h>
#include <secp256k1.h>
#include <secp256k1_silentpayments.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>

#define SP_VERSION 0
#define SP_DESCRIPTOR_PREFIX "sp("

#define FINGERPRINT_HEX_LEN 9
#define CHECKSUM_LEN 9
// Room for sp([fingerprint/352'/coin'/0'] and the closing parenthesis
#define DESCRIPTOR_WRAPPER_LEN 48

static uint32_t sp_coin(bool is_testnet) { return is_testnet ? 1 : 0; }

void sp_account_key_path(bool is_testnet, uint32_t branch,
                         uint32_t path[SP_PATH_DEPTH]) {
  path[0] = BIP32_INITIAL_HARDENED_CHILD | SP_PURPOSE;
  path[1] = BIP32_INITIAL_HARDENED_CHILD | sp_coin(is_testnet);
  path[2] = BIP32_INITIAL_HARDENED_CHILD | SP_ACCOUNT;
  path[3] = BIP32_INITIAL_HARDENED_CHILD | branch;
  path[4] = 0;
}

static bool derive_sp_key(bool is_testnet, uint32_t branch,
                          unsigned char *secret_out,
                          unsigned char *pubkey_out) {
  uint32_t path[SP_PATH_DEPTH];
  struct ext_key *key = NULL;

  sp_account_key_path(is_testnet, branch, path);
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

// m/352'/coin'/0'/branch'/0
static bool is_account_key_path(const uint32_t *path, size_t len,
                                bool is_testnet, uint32_t branch) {
  return sp_path_on_branch(path, len, is_testnet, branch) &&
         path[SP_PATH_DEPTH - 1] == 0;
}

static bool fingerprint_is_ours(const unsigned char *fingerprint) {
  unsigned char ours[BIP32_KEY_FINGERPRINT_LEN];
  return key_get_fingerprint(ours) &&
         memcmp(ours, fingerprint, sizeof(ours)) == 0;
}

static sp_account_t scan_key_account(const unsigned char *scan_key,
                                     bool is_testnet) {
  struct sp_keys keys;
  if (!sp_keys_derive(is_testnet, &keys))
    return SP_ACCOUNT_ERR_KEYS;
  bool ours = secure_memcmp(keys.scan_secret, scan_key, SP_SECRET_LEN) == 0;
  sp_keys_wipe(&keys);
  if (ours)
    return SP_ACCOUNT_OURS;
  return wally_ec_private_key_verify(scan_key, SP_SECRET_LEN) == WALLY_OK
             ? SP_ACCOUNT_FOREIGN_SCAN
             : SP_ACCOUNT_BAD_SCAN_KEY;
}

sp_account_t sp_account_classify(const unsigned char *fingerprint,
                                 const uint32_t *spend_path, size_t spend_len,
                                 const uint32_t *scan_path, size_t scan_len,
                                 const unsigned char *scan_key,
                                 bool is_testnet) {
  if (!fingerprint_is_ours(fingerprint))
    return SP_ACCOUNT_NOT_OURS;
  if (sp_path_on_branch(spend_path, spend_len, !is_testnet, SP_SPEND_BRANCH))
    return SP_ACCOUNT_OTHER_NETWORK;
  if (!is_account_key_path(spend_path, spend_len, is_testnet, SP_SPEND_BRANCH))
    return SP_ACCOUNT_NOT_OURS;
  if (scan_key)
    return scan_key_account(scan_key, is_testnet);
  return is_account_key_path(scan_path, scan_len, is_testnet, SP_SCAN_BRANCH)
             ? SP_ACCOUNT_OURS
             : SP_ACCOUNT_NOT_OURS;
}

// spscan payload: the scan secret then the spend public key
static bool encode_scan_key(const struct sp_keys *keys, bool is_testnet,
                            char *out, size_t out_len) {
  unsigned char payload[SP_SECRET_LEN + SP_PUBKEY_LEN];
  memcpy(payload, keys->scan_secret, SP_SECRET_LEN);
  memcpy(payload + SP_SECRET_LEN, keys->spend_pubkey, SP_PUBKEY_LEN);
  bool ok =
      kern_bech32m_encode(is_testnet ? "tspscan" : "spscan", SP_VERSION,
                          payload, sizeof(payload), out, out_len) == WALLY_OK;
  secure_memzero(payload, sizeof(payload));
  return ok;
}

// `body` followed by '#' and its checksum
static char *append_checksum_alloc(const char *body) {
  char checksum[CHECKSUM_LEN];
  size_t len = strlen(body);
  char *out;

  if (!descriptor_checksum_from_string(body, checksum))
    return NULL;
  out = malloc(len + 1 + CHECKSUM_LEN);
  if (!out)
    return NULL;
  memcpy(out, body, len);
  out[len] = '#';
  memcpy(out + len + 1, checksum, CHECKSUM_LEN);
  return out;
}

bool sp_descriptor_alloc(bool is_testnet, char **out) {
  struct sp_keys keys;
  char fingerprint[FINGERPRINT_HEX_LEN];
  char scan_key[KERN_BECH32M_MAX_LEN + 1];
  char body[sizeof(scan_key) + DESCRIPTOR_WRAPPER_LEN];
  bool ok;

  if (!out)
    return false;
  *out = NULL;
  if (!key_get_fingerprint_hex(fingerprint) ||
      !sp_keys_derive(is_testnet, &keys))
    return false;
  ok = encode_scan_key(&keys, is_testnet, scan_key, sizeof(scan_key));
  sp_keys_wipe(&keys);
  if (ok) {
    int len =
        snprintf(body, sizeof(body), "sp([%s/%u'/%u'/%u']%s)", fingerprint,
                 SP_PURPOSE, sp_coin(is_testnet), SP_ACCOUNT, scan_key);
    if (len > 0 && (size_t)len < sizeof(body))
      *out = append_checksum_alloc(body);
  }
  secure_memzero(scan_key, sizeof(scan_key));
  secure_memzero(body, sizeof(body));
  return *out != NULL;
}

bool sp_descriptor_is_sp(const char *descriptor) {
  return descriptor && strncmp(descriptor, SP_DESCRIPTOR_PREFIX,
                               sizeof(SP_DESCRIPTOR_PREFIX) - 1) == 0;
}

// Length of a descriptor without its #checksum
static size_t descriptor_body_len(const char *descriptor) {
  const char *checksum = strchr(descriptor, '#');
  return checksum ? (size_t)(checksum - descriptor) : strlen(descriptor);
}

bool sp_descriptor_is_ours(const char *descriptor, bool is_testnet) {
  char *ours = NULL;
  bool same;

  if (!descriptor || !sp_descriptor_alloc(is_testnet, &ours))
    return false;
  same = descriptor_body_len(descriptor) == descriptor_body_len(ours) &&
         secure_memcmp(descriptor, ours, descriptor_body_len(ours)) == 0;
  SECURE_FREE_STRING(ours);
  return same;
}

const char *sp_address_hrp(bool is_testnet) {
  return is_testnet ? SP_HRP_TESTNET : SP_HRP_MAINNET;
}

bool sp_address_alloc(const unsigned char *scan_pubkey,
                      const unsigned char *spend_pubkey, const char *hrp,
                      char **out) {
  unsigned char payload[2 * SP_PUBKEY_LEN];
  char address[KERN_BECH32M_MAX_LEN + 1];

  if (!scan_pubkey || !spend_pubkey || !hrp || !out)
    return false;
  memcpy(payload, scan_pubkey, SP_PUBKEY_LEN);
  memcpy(payload + SP_PUBKEY_LEN, spend_pubkey, SP_PUBKEY_LEN);
  if (kern_bech32m_encode(hrp, SP_VERSION, payload, sizeof(payload), address,
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

bool sp_account_keys_derive(bool is_testnet, const unsigned char *scan_secret,
                            struct sp_keys *out) {
  secp256k1_pubkey scan_point;
  if (!sp_keys_derive(is_testnet, out))
    return false;
  if (!scan_secret)
    return true;
  memcpy(out->scan_secret, scan_secret, SP_SECRET_LEN);
  if (secp256k1_ec_pubkey_create(wally_get_secp_context(), &scan_point,
                                 scan_secret) &&
      serialize_point(&scan_point, out->scan_pubkey))
    return true;
  sp_keys_wipe(out);
  return false;
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

static bool is_label_path(const uint32_t *label_path, size_t label_path_len) {
  return label_path_len == 0 ||
         (label_path_len == 1 && label_path[0] != SP_CHANGE_LABEL);
}

sp_address_result_t sp_account_address_alloc(const unsigned char *scan_secret,
                                             const unsigned char *spend_pubkey,
                                             const uint32_t *label_path,
                                             size_t label_path_len,
                                             const char *hrp, char **out) {
  secp256k1_pubkey scan_point, spend_point;
  unsigned char scan_pubkey[SP_PUBKEY_LEN], spend[SP_PUBKEY_LEN];

  *out = NULL;
  if (!is_label_path(label_path, label_path_len))
    return SP_ADDRESS_ERR_LABEL;
  if (!secp256k1_ec_pubkey_create(wally_get_secp_context(), &scan_point,
                                  scan_secret) ||
      !serialize_point(&scan_point, scan_pubkey) ||
      !secp256k1_ec_pubkey_parse(wally_get_secp_context(), &spend_point,
                                 spend_pubkey, SP_PUBKEY_LEN))
    return SP_ADDRESS_ERR_KEY;
  if (label_path_len == 0)
    memcpy(spend, spend_pubkey, SP_PUBKEY_LEN);
  else if (!sp_labeled_spend_pubkey(scan_secret, spend_pubkey, label_path[0],
                                    spend))
    return SP_ADDRESS_ERR_KEY;
  return sp_address_alloc(scan_pubkey, spend, hrp, out) ? SP_ADDRESS_OK
                                                        : SP_ADDRESS_ERR_ALLOC;
}
