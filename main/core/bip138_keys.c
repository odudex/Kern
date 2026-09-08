#include "bip138_keys.h"
#include "bip32_path.h"
#include "wallet.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>

#define XPUB_MAX_LEN 128

static bool xpub_to_xonly(const char *xpub, uint8_t out[32]) {
  struct ext_key *key = NULL;
  if (bip32_key_from_base58_alloc(xpub, &key) != WALLY_OK || !key)
    return false;
  bool ok = key->priv_key[0] != BIP32_FLAG_KEY_PRIVATE;
  if (ok) {
    memcpy(out, key->pub_key + 1, EC_XONLY_PUBLIC_KEY_LEN);
    ok = wally_ec_xonly_public_key_verify(out, EC_XONLY_PUBLIC_KEY_LEN) ==
         WALLY_OK;
  }
  bip32_key_free(key);
  return ok;
}

/* Copies the base58 key part of "[origin]xpub/..." and returns the remainder
 * after the key, or NULL when the expression has no key part. */
static const char *split_key(const char *expr, char *xpub, size_t xpub_size) {
  const char *p = expr;
  if (*p == '[') {
    p = strchr(p, ']');
    if (!p)
      return NULL;
    p++;
  }
  const char *end = strchr(p, '/');
  size_t len = end ? (size_t)(end - p) : strlen(p);
  if (len == 0 || len >= xpub_size)
    return NULL;
  memcpy(xpub, p, len);
  xpub[len] = '\0';
  return p + len;
}

bool bip138_key_from_expression(const char *expr, uint8_t xonly_out[32]) {
  char xpub[XPUB_MAX_LEN];
  if (!expr || !xonly_out)
    return false;
  const char *rest = split_key(expr, xpub, sizeof(xpub));
  if (!rest || rest[0] != '/' || rest[1] == '\0')
    return false;
  return xpub_to_xonly(xpub, xonly_out);
}

static bool parse_origin(const char *str, bip138_key_origin *origin) {
  origin->depth = 0;
  if (!str || !*str)
    return true;
  if (str[0] == 'm') {
    if (str[1] != '/')
      return false;
    str += 2;
  }
  while (*str) {
    if (!isdigit((unsigned char)*str) || origin->depth == BIP138_KEYS_MAX_DEPTH)
      return false;
    char *end = NULL;
    unsigned long value = strtoul(str, &end, 10);
    if (value >= BIP32_PATH_HARDENED)
      return false;
    if (*end == '\'' || *end == 'h') {
      value |= BIP32_PATH_HARDENED;
      end++;
    }
    origin->child[origin->depth++] = (uint32_t)value;
    if (*end == '/')
      end++;
    else if (*end != '\0')
      return false;
    str = end;
  }
  return true;
}

static bool key_origin(const struct wally_descriptor *desc, size_t index,
                       bip138_key_origin *origin) {
  char *str = NULL;
  if (wally_descriptor_get_key_origin_path_str(desc, index, &str) != WALLY_OK)
    return false;
  bool ok = parse_origin(str, origin);
  wally_free_string(str);
  return ok;
}

bool bip138_keys_from_descriptor(const char *descriptor, uint32_t wally_network,
                                 uint8_t *keys_out,
                                 bip138_key_origin *origins_out,
                                 size_t max_keys, size_t *count_out) {
  struct wally_descriptor *desc = NULL;
  uint32_t num_keys = 0;
  size_t count = 0;
  bool ok = true;

  if (!descriptor || !keys_out || !count_out || max_keys == 0)
    return false;
  uint32_t features = 0;
  if (wallet_descriptor_parse(descriptor, NULL, wally_network, &desc) !=
          WALLY_OK ||
      wally_descriptor_get_num_keys(desc, &num_keys) != WALLY_OK ||
      wally_descriptor_get_features(desc, &features) != WALLY_OK ||
      (features & WALLY_MS_IS_PRIVATE)) {
    wally_descriptor_free(desc);
    return false;
  }

  for (size_t i = 0; ok && i < num_keys; i++) {
    size_t child_len = 0;
    char *key_str = NULL;
    char xpub[XPUB_MAX_LEN];
    uint8_t xonly[EC_XONLY_PUBLIC_KEY_LEN];
    if (wally_descriptor_get_key_child_path_str_len(desc, i, &child_len) !=
            WALLY_OK ||
        child_len == 0)
      continue;
    if (wally_descriptor_get_key(desc, i, &key_str) != WALLY_OK)
      continue;
    bool have_key = split_key(key_str, xpub, sizeof(xpub)) != NULL &&
                    xpub_to_xonly(xpub, xonly);
    wally_free_string(key_str);
    if (!have_key)
      continue;
    size_t j = 0;
    while (j < count &&
           memcmp(keys_out + j * BIP138_KEY_LEN, xonly, BIP138_KEY_LEN) != 0)
      j++;
    if (j < count)
      continue;
    if (count == max_keys) {
      ok = false;
      break;
    }
    memcpy(keys_out + count * BIP138_KEY_LEN, xonly, BIP138_KEY_LEN);
    if (origins_out)
      ok = key_origin(desc, i, &origins_out[count]);
    count++;
  }
  wally_descriptor_free(desc);
  if (!ok || count == 0)
    return false;
  *count_out = count;
  return true;
}
