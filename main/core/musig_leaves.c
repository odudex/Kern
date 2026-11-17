#include "musig_leaves.h"

#include "descriptor_checksum.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_musig.h>

#define MUSIG_OPEN "musig("
#define INTERNAL_KEY_OPEN "tr("
#define CHECKSUM_LEN 8

/* A rewritten key and the musig(...) expression it stands for. Kept for the
 * life of the process, as libwally keeps no trace of the expression. */
typedef struct {
  char *key;
  char *expression;
} rewrite_t;

static rewrite_t *rewrites;
static size_t num_rewrites;

typedef struct {
  char *text;
  size_t len;
  size_t cap;
} text_t;

static bool text_append(text_t *t, const char *s, size_t n) {
  if (t->len + n + 1 > t->cap) {
    size_t cap = (t->len + n + 1) * 2;
    char *text = realloc(t->text, cap);
    if (!text)
      return false;
    t->text = text;
    t->cap = cap;
  }
  memcpy(t->text + t->len, s, n);
  t->len += n;
  t->text[t->len] = '\0';
  return true;
}

const char *musig_leaves_expression(const char *key) {
  for (size_t i = 0; key && i < num_rewrites; i++) {
    if (strcmp(rewrites[i].key, key) == 0)
      return rewrites[i].expression;
  }
  return NULL;
}

static bool remember(const char *key, const char *expression,
                     size_t expression_len) {
  if (musig_leaves_expression(key))
    return true;
  rewrite_t *grown = realloc(rewrites, (num_rewrites + 1) * sizeof(*grown));
  if (!grown)
    return false;
  rewrites = grown;
  rewrite_t *r = &rewrites[num_rewrites];
  r->key = strdup(key);
  r->expression = malloc(expression_len + 1);
  if (!r->key || !r->expression) {
    free(r->key);
    free(r->expression);
    return false;
  }
  memcpy(r->expression, expression, expression_len);
  r->expression[expression_len] = '\0';
  num_rewrites++;
  return true;
}

/* The compressed key of a participant with no derivation of its own. */
static bool participant_key(const char *text, size_t len, unsigned char *out) {
  if (len && text[0] == '[') {
    const char *close = memchr(text, ']', len);
    if (!close)
      return false;
    len -= (size_t)(close + 1 - text);
    text = close + 1;
  }
  if (memchr(text, '/', len))
    return false;
  if (len == 2 * EC_PUBLIC_KEY_LEN) {
    size_t written = 0;
    return wally_hex_n_to_bytes(text, len, out, EC_PUBLIC_KEY_LEN, &written) ==
               WALLY_OK &&
           written == EC_PUBLIC_KEY_LEN;
  }
  struct ext_key xpub;
  bool ok = bip32_key_from_base58_n(text, len, &xpub) == WALLY_OK;
  if (ok)
    memcpy(out, xpub.pub_key, EC_PUBLIC_KEY_LEN);
  wally_bzero(&xpub, sizeof(xpub));
  return ok;
}

static int compare_keys(const void *a, const void *b) {
  return memcmp(a, b, EC_PUBLIC_KEY_LEN);
}

/* The KeyAgg key of the participants `body` lists, sorted as BIP-390 does. */
static bool aggregate_key(const char *body, size_t len, unsigned char *out) {
  size_t n = 1;
  for (size_t i = 0; i < len; i++)
    n += body[i] == ',';
  unsigned char *keys = malloc(n * EC_PUBLIC_KEY_LEN);
  bool ok = keys != NULL;
  const char *participant = body;
  for (size_t p = 0; ok && p < n; p++) {
    const char *end =
        memchr(participant, ',', (size_t)(body + len - participant));
    if (!end)
      end = body + len;
    ok = participant_key(participant, (size_t)(end - participant),
                         keys + p * EC_PUBLIC_KEY_LEN);
    participant = end + 1;
  }
  struct wally_musig_keyagg_cache *cache = NULL;
  unsigned char xonly[EC_XONLY_PUBLIC_KEY_LEN];
  if (ok) {
    qsort(keys, n, EC_PUBLIC_KEY_LEN, compare_keys);
    ok = wally_musig_pubkey_agg(keys, n * EC_PUBLIC_KEY_LEN, xonly,
                                sizeof(xonly), &cache) == WALLY_OK &&
         wally_musig_pubkey_get(cache, out, EC_PUBLIC_KEY_LEN) == WALLY_OK;
  }
  wally_musig_keyagg_cache_free(cache);
  free(keys);
  return ok;
}

/* The key a leaf musig() stands for: the synthetic xpub when a path follows,
 * the x-only aggregate otherwise. The caller frees it with
 * wally_free_string(). */
static char *leaf_key_alloc(const char *body, size_t len, bool has_path,
                            uint32_t network) {
  unsigned char aggregate[EC_PUBLIC_KEY_LEN];
  char *key = NULL;
  if (!aggregate_key(body, len, aggregate))
    return NULL;
  if (!has_path) {
    if (wally_hex_from_bytes(aggregate + 1, EC_XONLY_PUBLIC_KEY_LEN, &key) !=
        WALLY_OK)
      return NULL;
    return key;
  }
  struct ext_key *synthetic = NULL;
  uint32_t version = network == WALLY_NETWORK_BITCOIN_MAINNET
                         ? BIP32_VER_MAIN_PUBLIC
                         : BIP32_VER_TEST_PUBLIC;
  if (wally_musig_pubkey_to_xpub(aggregate, sizeof(aggregate), version,
                                 &synthetic) == WALLY_OK &&
      bip32_key_to_base58(synthetic, BIP32_FLAG_KEY_PUBLIC, &key) != WALLY_OK)
    key = NULL;
  bip32_key_free(synthetic);
  return key;
}

/* Where the derivation path after a key expression ends. */
static const char *path_end(const char *p) {
  if (*p != '/')
    return p;
  while (*p && *p != ',' && *p != ')' && *p != '}')
    p++;
  return p;
}

/* Rewrites the leaf musig() at `open` into `out`, and where it ends. */
static const char *rewrite_one(const char *open, uint32_t network,
                               text_t *out) {
  const char *body = open + strlen(MUSIG_OPEN);
  const char *close = strchr(body, ')');
  if (!close)
    return NULL;
  const char *end = path_end(close + 1);
  char *key =
      leaf_key_alloc(body, (size_t)(close - body), end != close + 1, network);
  bool ok = key && remember(key, open, (size_t)(close + 1 - open)) &&
            text_append(out, key, strlen(key)) &&
            text_append(out, close + 1, (size_t)(end - close - 1));
  wally_free_string(key);
  return ok ? end : NULL;
}

static bool is_internal_key(const char *descriptor, const char *open) {
  size_t prefix = strlen(INTERNAL_KEY_OPEN);
  return (size_t)(open - descriptor) >= prefix &&
         memcmp(open - prefix, INTERNAL_KEY_OPEN, prefix) == 0;
}

/* The descriptor body, checked against its checksum when it carries one. */
static char *checked_body_alloc(const char *descriptor) {
  const char *hash = strchr(descriptor, '#');
  size_t len = hash ? (size_t)(hash - descriptor) : strlen(descriptor);
  char *body = malloc(len + 1);
  if (!body)
    return NULL;
  memcpy(body, descriptor, len);
  body[len] = '\0';
  char checksum[CHECKSUM_LEN + 1];
  if (hash && (!descriptor_checksum_from_string(body, checksum) ||
               strcmp(hash + 1, checksum) != 0)) {
    free(body);
    return NULL;
  }
  return body;
}

static bool has_leaf_musig(const char *descriptor) {
  for (const char *open = strstr(descriptor, MUSIG_OPEN); open;
       open = strstr(open + 1, MUSIG_OPEN)) {
    if (!is_internal_key(descriptor, open))
      return true;
  }
  return false;
}

char *musig_leaves_rewrite_alloc(const char *descriptor, uint32_t network) {
  if (!descriptor)
    return NULL;
  if (!has_leaf_musig(descriptor))
    return strdup(descriptor);
  char *body = checked_body_alloc(descriptor);
  if (!body)
    return NULL;

  text_t out = {0};
  const char *p = body;
  const char *open = NULL;
  bool ok = true;
  while (ok && (open = strstr(p, MUSIG_OPEN))) {
    ok = text_append(&out, p, (size_t)(open - p));
    if (ok && is_internal_key(body, open)) {
      ok = text_append(&out, open, strlen(MUSIG_OPEN));
      p = open + strlen(MUSIG_OPEN);
    } else if (ok) {
      p = rewrite_one(open, network, &out);
      ok = p != NULL;
    }
  }
  ok = ok && text_append(&out, p, strlen(p));
  free(body);
  if (!ok) {
    free(out.text);
    return NULL;
  }
  return out.text;
}

/* `text` with every occurrence of `from` replaced by `to`. */
static bool replace_all(text_t *text, const char *from, const char *to) {
  text_t out = {0};
  size_t from_len = strlen(from);
  const char *p = text->text;
  bool replaced = false;
  for (const char *hit = strstr(p, from); hit; hit = strstr(p, from)) {
    if (!text_append(&out, p, (size_t)(hit - p)) ||
        !text_append(&out, to, strlen(to))) {
      free(out.text);
      return false;
    }
    p = hit + from_len;
    replaced = true;
  }
  if (!replaced)
    return true;
  if (!text_append(&out, p, strlen(p))) {
    free(out.text);
    return false;
  }
  free(text->text);
  *text = out;
  return true;
}

char *musig_leaves_restore_alloc(const char *descriptor) {
  if (!descriptor)
    return NULL;
  const char *hash = strchr(descriptor, '#');
  text_t out = {0};
  bool ok =
      text_append(&out, descriptor,
                  hash ? (size_t)(hash - descriptor) : strlen(descriptor));
  for (size_t i = 0; ok && i < num_rewrites; i++)
    ok = replace_all(&out, rewrites[i].key, rewrites[i].expression);
  char checksum[CHECKSUM_LEN + 1];
  if (ok && hash)
    ok = descriptor_checksum_from_string(out.text, checksum) &&
         text_append(&out, "#", 1) && text_append(&out, checksum, CHECKSUM_LEN);
  if (!ok) {
    free(out.text);
    return NULL;
  }
  return out.text;
}
