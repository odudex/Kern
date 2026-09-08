#include "bip138_backup.h"
#include "../utils/secure_mem.h"
#include "bip138_crypto.h"
#include "bip138_keys.h"
#include "bip32_path.h"
#include "key.h"
#include "wallet.h"
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>

/* Approval mark: a vendor item whose data is HMAC-SHA256 over the descriptor
 * bytes under a key derived from this seed. Recipients of the backup hold only
 * public keys, so they can read it but not forge it. */
static const uint8_t approval_tag[] = "kern-approval";
#define APPROVAL_TAG_LEN (sizeof(approval_tag) - 1)
#define APPROVAL_KEY_TAG "KERN_BIP138_APPROVAL"
static const uint32_t approval_path[] = {0x4B45524Eu | BIP32_PATH_HARDENED,
                                         138u | BIP32_PATH_HARDENED};

static uint32_t wallet_wally_network(void) {
  return wallet_get_network() == WALLET_NETWORK_MAINNET
             ? WALLY_NETWORK_BITCOIN_MAINNET
             : WALLY_NETWORK_BITCOIN_TESTNET;
}

static uint32_t other_network(uint32_t network) {
  return network == WALLY_NETWORK_BITCOIN_MAINNET
             ? WALLY_NETWORK_BITCOIN_TESTNET
             : WALLY_NETWORK_BITCOIN_MAINNET;
}

static bool approval_key(uint8_t out[32]) {
  struct ext_key *key = NULL;
  if (!key_get_derived_key_components(
          approval_path, sizeof(approval_path) / sizeof(approval_path[0]),
          &key))
    return false;
  bool ok = wally_bip340_tagged_hash(key->priv_key + 1, EC_PRIVATE_KEY_LEN,
                                     APPROVAL_KEY_TAG, out, 32) == WALLY_OK;
  bip32_key_free(key);
  return ok;
}

static bool approval_mac(const uint8_t *descriptor, size_t len,
                         uint8_t out[HMAC_SHA256_LEN]) {
  uint8_t mac_key[32];
  if (!approval_key(mac_key))
    return false;
  bool ok = wally_hmac_sha256(mac_key, sizeof(mac_key), descriptor, len, out,
                              HMAC_SHA256_LEN) == WALLY_OK;
  secure_memzero(mac_key, sizeof(mac_key));
  return ok;
}

bool bip138_backup_encrypt(const char *descriptor, uint8_t **blob_out,
                           size_t *blob_len) {
  uint8_t keys[BIP138_KEYS_MAX * BIP138_KEY_LEN];
  bip138_key_origin origins[BIP138_KEYS_MAX];
  bip138_path paths[BIP138_KEYS_MAX];
  uint8_t mac[HMAC_SHA256_LEN];
  size_t count = 0;
  size_t n_paths = 0;

  if (!descriptor || !blob_out || !blob_len)
    return false;
  uint32_t network = wallet_wally_network();
  if (!bip138_keys_from_descriptor(descriptor, network, keys, origins,
                                   BIP138_KEYS_MAX, &count) &&
      !bip138_keys_from_descriptor(descriptor, other_network(network), keys,
                                   origins, BIP138_KEYS_MAX, &count))
    return false;
  for (size_t i = 0; i < count; i++) {
    if (origins[i].depth > 0) {
      paths[n_paths].child = origins[i].child;
      paths[n_paths].depth = origins[i].depth;
      n_paths++;
    }
  }
  size_t descriptor_len = strlen(descriptor);
  if (!approval_mac((const uint8_t *)descriptor, descriptor_len, mac))
    return false;

  bip138_item items[2] = {
      {{BIP138_CONTENT_BIP, BIP138_BIP_DESCRIPTOR, NULL, 0},
       (const uint8_t *)descriptor,
       descriptor_len},
      {{BIP138_CONTENT_PROPRIETARY, 0, approval_tag, APPROVAL_TAG_LEN},
       mac,
       sizeof(mac)}};
  size_t pt_len = bip138_plaintext_size(items, 2, 0);
  size_t cap =
      bip138_encrypt_size(bip138_secret_bucket(count), paths, n_paths, pt_len);
  if (pt_len == 0 || cap == 0)
    return false;
  uint8_t *pt = malloc(pt_len);
  uint8_t *blob = malloc(cap);
  /* Every origin is kept, common ones included, so recovery under any of the
   * descriptor's keys is a single derivation instead of a common-path walk. */
  bool ok =
      pt && blob &&
      bip138_plaintext_encode(items, 2, 0, pt, pt_len, &pt_len) == BIP138_OK &&
      bip138_encrypt_flags(kern_bip138_crypto(), keys, count, paths, n_paths,
                           BIP138_FLAG_KEEP_COMMON_PATHS, pt, pt_len, blob, cap,
                           blob_len) == BIP138_OK;
  SECURE_FREE_BUFFER(pt, pt_len);
  if (!ok) {
    free(blob);
    return false;
  }
  *blob_out = blob;
  return true;
}

/* --- Candidate keys: the wallet's xpub at each path, x-only --- */

static bool candidate_key(const uint32_t *child, size_t depth,
                          uint8_t xonly[32]) {
  char path[BIP138_KEYS_MAX_DEPTH * 12 + 2];
  char *xpub = NULL;
  if (!bip32_path_format(child, depth, path, sizeof(path)) ||
      !key_get_xpub(path, &xpub))
    return false;
  struct ext_key *key = NULL;
  bool ok = bip32_key_from_base58_alloc(xpub, &key) == WALLY_OK;
  if (ok) {
    memcpy(xonly, key->pub_key + 1, EC_XONLY_PUBLIC_KEY_LEN);
    bip32_key_free(key);
  }
  wally_free_string(xpub);
  return ok;
}

/* Common-path xpubs, derived once per loaded key rather than once per file. */
typedef struct {
  uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN];
  bool tried[140];
  bool valid[140];
  uint8_t xonly[140][BIP138_KEY_LEN];
} common_cache_t;

static common_cache_t common_cache;

static bool common_candidate(size_t index, uint8_t xonly[32]) {
  uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN];
  if (index >= sizeof(common_cache.tried) / sizeof(common_cache.tried[0]) ||
      !key_get_fingerprint(fingerprint))
    return false;
  if (memcmp(common_cache.fingerprint, fingerprint, sizeof(fingerprint)) != 0) {
    memset(&common_cache, 0, sizeof(common_cache));
    memcpy(common_cache.fingerprint, fingerprint, sizeof(fingerprint));
  }
  if (!common_cache.tried[index]) {
    uint32_t child[4];
    size_t depth = 0;
    common_cache.tried[index] = true;
    common_cache.valid[index] =
        bip138_common_path(index, child, &depth) == BIP138_OK &&
        candidate_key(child, depth, common_cache.xonly[index]);
  }
  if (!common_cache.valid[index])
    return false;
  memcpy(xonly, common_cache.xonly[index], BIP138_KEY_LEN);
  return true;
}

typedef struct {
  uint32_t child[BIP138_KEYS_MAX_DEPTH];
  size_t depth;
} hint_path_t;

static bool path_equal(const uint32_t *a, size_t a_depth, const uint32_t *b,
                       size_t b_depth) {
  return a_depth == b_depth && memcmp(a, b, a_depth * sizeof(*a)) == 0;
}

/* Distinct container paths. Returns SIZE_MAX when there are more than the
 * cap, since silently dropping origins could hide the one that opens it. */
static size_t collect_hints(const bip138_container *cont, hint_path_t *hints) {
  size_t n = 0;
  for (size_t i = 0; i < cont->path_count; i++) {
    hint_path_t h;
    if (bip138_path_at(cont, i, h.child, BIP138_KEYS_MAX_DEPTH, &h.depth) !=
        BIP138_OK)
      continue;
    size_t j = 0;
    while (j < n &&
           !path_equal(hints[j].child, hints[j].depth, h.child, h.depth))
      j++;
    if (j == n) {
      if (n == BIP138_BACKUP_MAX_PATHS)
        return SIZE_MAX;
      hints[n++] = h;
    }
  }
  return n;
}

static bool find_items(const uint8_t *pt, size_t pt_len, bip138_item *slots,
                       bool *have_mark) {
  bip138_item_iter it;
  bip138_item item;
  bool have_descriptor = false;
  *have_mark = false;
  bip138_item_iter_init(&it, pt, pt_len);
  while (bip138_item_next(&it, &item) == 1) {
    if (!have_descriptor && item.content.type == BIP138_CONTENT_BIP &&
        item.content.bip == BIP138_BIP_DESCRIPTOR) {
      slots[0] = item;
      have_descriptor = true;
    } else if (!*have_mark && item.content.type == BIP138_CONTENT_PROPRIETARY &&
               item.content.tag_len == APPROVAL_TAG_LEN &&
               memcmp(item.content.tag, approval_tag, APPROVAL_TAG_LEN) == 0 &&
               item.data_len == HMAC_SHA256_LEN) {
      slots[1] = item;
      *have_mark = true;
    }
  }
  return have_descriptor;
}

static bool mark_is_valid(const bip138_item *descriptor_item,
                          const bip138_item *mark_item) {
  uint8_t expected[HMAC_SHA256_LEN];
  if (!approval_mac(descriptor_item->data, descriptor_item->data_len, expected))
    return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < HMAC_SHA256_LEN; i++)
    diff |= expected[i] ^ mark_item->data[i];
  return diff == 0;
}

bool bip138_backup_decrypt(const uint8_t *blob, size_t blob_len,
                           char **descriptor_out, bool *approved_out) {
  bip138_container cont;
  hint_path_t hints[BIP138_BACKUP_MAX_PATHS];
  uint8_t xonly[BIP138_KEY_LEN];
  size_t pt_len = 0;
  bool found = false;

  if (approved_out)
    *approved_out = false;
  if (!blob || !descriptor_out || blob_len > BIP138_BACKUP_MAX_LEN ||
      bip138_parse(blob, blob_len, &cont) != BIP138_OK)
    return false;
  size_t n_hints = collect_hints(&cont, hints);
  if (n_hints == SIZE_MAX)
    return false;
  size_t pt_cap = bip138_plaintext_max(&cont);
  uint8_t *pt = malloc(pt_cap);
  if (!pt)
    return false;

  size_t candidates = n_hints + bip138_common_path_count();
  for (size_t i = 0; i < candidates && !found; i++) {
    bool have = i < n_hints
                    ? candidate_key(hints[i].child, hints[i].depth, xonly)
                    : common_candidate(i - n_hints, xonly);
    if (have)
      found = bip138_decrypt(kern_bip138_crypto(), &cont, xonly, 1, pt, pt_cap,
                             &pt_len, NULL) == BIP138_OK;
  }

  bool ok = false;
  bip138_item slots[2];
  bool have_mark = false;
  if (found && find_items(pt, pt_len, slots, &have_mark)) {
    char *descriptor = malloc(slots[0].data_len + 1);
    if (descriptor) {
      memcpy(descriptor, slots[0].data, slots[0].data_len);
      descriptor[slots[0].data_len] = '\0';
      *descriptor_out = descriptor;
      if (approved_out)
        *approved_out = have_mark && mark_is_valid(&slots[0], &slots[1]);
      ok = true;
    }
  }
  SECURE_FREE_BUFFER(pt, pt_cap);
  return ok;
}

bool bip138_backup_encrypt_text(const char *descriptor, char **base64_out) {
  uint8_t *blob = NULL;
  size_t blob_len = 0;
  size_t text_len = 0;
  if (!base64_out || !bip138_backup_encrypt(descriptor, &blob, &blob_len))
    return false;
  char *text = malloc(BIP138_BASE64_LEN(blob_len));
  bool ok = text && bip138_base64_encode(blob, blob_len, text,
                                         BIP138_BASE64_LEN(blob_len),
                                         &text_len) == BIP138_OK;
  free(blob);
  if (!ok) {
    free(text);
    return false;
  }
  *base64_out = text;
  return true;
}

bool bip138_backup_is_container(const uint8_t *data, size_t len) {
  return bip138_is_container(data, len);
}

bool bip138_backup_detect(const uint8_t *data, size_t len) {
  static const char base64_magic[] = "QklQMTM4"; /* base64("BIP138") */
  return bip138_is_container(data, len) ||
         (data && len >= 8 && memcmp(data, base64_magic, 8) == 0);
}

bool bip138_backup_decrypt_any(const uint8_t *data, size_t len,
                               char **descriptor_out, bool *approved_out) {
  if (approved_out)
    *approved_out = false;
  if (!data || len == 0 || len > BIP138_BACKUP_MAX_LEN * 2)
    return false;
  if (bip138_is_container(data, len))
    return bip138_backup_decrypt(data, len, descriptor_out, approved_out);
  size_t cap = BIP138_BASE64_DECODED_MAX(len);
  uint8_t *blob = malloc(cap);
  size_t blob_len = 0;
  bool ok = blob &&
            bip138_base64_decode((const char *)data, len, blob, cap,
                                 &blob_len) == BIP138_OK &&
            bip138_backup_decrypt(blob, blob_len, descriptor_out, approved_out);
  free(blob);
  return ok;
}
