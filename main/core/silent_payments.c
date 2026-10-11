#include "silent_payments.h"
#include "../utils/secure_mem.h"
#include "descriptor_checksum.h"
#include "key.h"
#include <kern_bech32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>

#define SP_PURPOSE 352
#define SP_ACCOUNT 0
#define SP_SCAN_BRANCH 1
#define SP_SPEND_BRANCH 0
#define SP_PATH_DEPTH 5
#define SP_VERSION 0

#define FINGERPRINT_HEX_LEN 9
#define CHECKSUM_LEN 9
// Room for sp([fingerprint/352'/coin'/0'] and the closing parenthesis
#define DESCRIPTOR_WRAPPER_LEN 48

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
