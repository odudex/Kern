#include "descriptor_branch.h"
#include "psbt_internal.h"
#include "wallet.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>

#define MAX_BRANCH_STEPS 8

/* One unhardened step of a child path: a number, or alternative `multi_index`
 * of a <a;b;...> multipath step. */
static bool parse_step(const char *s, size_t len, uint32_t multi_index,
                       uint32_t *out) {
  if (len >= 2 && s[0] == '<' && s[len - 1] == '>') {
    s++;
    len -= 2;
    for (uint32_t i = 0; i < multi_index; i++) {
      const char *sep = memchr(s, ';', len);
      if (!sep)
        return false;
      len -= (size_t)(sep - s) + 1;
      s = sep + 1;
    }
    const char *sep = memchr(s, ';', len);
    if (sep)
      len = (size_t)(sep - s);
  }
  if (!len || len > 10)
    return false;
  uint64_t value = 0;
  for (size_t i = 0; i < len; i++) {
    if (s[i] < '0' || s[i] > '9')
      return false;
    value = value * 10 + (uint64_t)(s[i] - '0');
  }
  if (value >= BIP32_INITIAL_HARDENED_CHILD)
    return false;
  *out = (uint32_t)value;
  return true;
}

/* `key` derived along `path` up to its wildcard, as base58. False when the
 * path holds a hardened step, does not end in an unhardened wildcard, or has
 * nothing before it. */
static bool derive_branch_key(const char *key, const char *path,
                              uint32_t multi_index, char **out) {
  uint32_t steps[MAX_BRANCH_STEPS];
  size_t num_steps = 0;
  for (;;) {
    const char *sep = strchr(path, '/');
    if (!sep) {
      if (strcmp(path, "*") != 0)
        return false;
      break;
    }
    if (num_steps == MAX_BRANCH_STEPS ||
        !parse_step(path, (size_t)(sep - path), multi_index, &steps[num_steps]))
      return false;
    num_steps++;
    path = sep + 1;
  }
  struct ext_key parent, branch;
  return num_steps && bip32_key_from_base58(key, &parent) == WALLY_OK &&
         bip32_key_from_parent_path(&parent, steps, num_steps,
                                    BIP32_FLAG_KEY_PUBLIC,
                                    &branch) == WALLY_OK &&
         bip32_key_to_base58(&branch, BIP32_FLAG_KEY_PUBLIC, out) == WALLY_OK;
}

/* Replaces every occurrence of `from` in *text with `to`; false if none. */
static bool replace_all(char **text, const char *from, const char *to) {
  size_t from_len = strlen(from), to_len = strlen(to), count = 0;
  for (const char *p = *text; (p = strstr(p, from)) != NULL; p += from_len)
    count++;
  if (!count)
    return false;
  char *out = malloc(strlen(*text) - count * from_len + count * to_len + 1);
  if (!out)
    return false;
  char *w = out;
  const char *r = *text;
  for (const char *p; (p = strstr(r, from)) != NULL; r = p + from_len) {
    memcpy(w, r, (size_t)(p - r));
    w += p - r;
    memcpy(w, to, to_len);
    w += to_len;
  }
  strcpy(w, r);
  free(*text);
  *text = out;
  return true;
}

/* Rewrites key `i` of `desc` in `text` as its branch key. A key with nothing
 * to derive is left alone, unless it is multipath: the copy would still be. */
static bool rewrite_key(const struct wally_descriptor *desc, uint32_t i,
                        uint32_t multi_index, char **text, bool *changed) {
  uint32_t features = 0;
  if (wally_descriptor_get_key_features(desc, i, &features) != WALLY_OK)
    return false;
  bool multipath = features & WALLY_MS_IS_MULTIPATH;
  if (!(features & WALLY_MS_IS_RANGED) ||
      (features & (WALLY_MS_IS_PRIVATE | WALLY_MS_IS_RAW | WALLY_MS_IS_MUSIG)))
    return !multipath;

  char *key = NULL, *path = NULL, *branch_key = NULL;
  char *from = NULL, *to = NULL;
  bool ok = false;
  if (wally_descriptor_get_key(desc, i, &key) != WALLY_OK ||
      wally_descriptor_get_key_child_path_str(desc, i, &path) != WALLY_OK)
    goto out;
  if (!derive_branch_key(key, path, multi_index, &branch_key)) {
    ok = !multipath;
    goto out;
  }
  from = malloc(strlen(key) + 1 + strlen(path) + 1);
  to = malloc(strlen(branch_key) + 3);
  if (!from || !to)
    goto out;
  strcpy(from, key);
  strcat(from, "/");
  strcat(from, path);
  strcpy(to, branch_key);
  strcat(to, "/*");
  /* A key written twice was rewritten with its first occurrence. */
  ok = replace_all(text, from, to) || strstr(*text, to) != NULL;
  *changed = *changed || ok;

out:
  wally_free_string(key);
  wally_free_string(path);
  wally_free_string(branch_key);
  free(from);
  free(to);
  return ok;
}

static bool same_spk_at_child_0(const struct wally_descriptor *desc,
                                uint32_t multi_index,
                                const struct wally_descriptor *branch) {
  /* Depth 0 builds the inner script in its buffer before hashing it. */
  unsigned char *buf = malloc(2 * PSBT_MAX_INNER_SCRIPT_LEN);
  unsigned char *a = buf, *b = buf + PSBT_MAX_INNER_SCRIPT_LEN;
  size_t a_len = 0, b_len = 0;
  bool same = buf &&
              wally_descriptor_to_script(desc, 0, 0, 0, multi_index, 0, 0, a,
                                         PSBT_MAX_INNER_SCRIPT_LEN,
                                         &a_len) == WALLY_OK &&
              wally_descriptor_to_script(branch, 0, 0, 0, 0, 0, 0, b,
                                         PSBT_MAX_INNER_SCRIPT_LEN,
                                         &b_len) == WALLY_OK &&
              a_len == b_len && a_len <= PSBT_MAX_INNER_SCRIPT_LEN &&
              memcmp(a, b, a_len) == 0;
  free(buf);
  return same;
}

struct wally_descriptor *
descriptor_branch_alloc(const struct wally_descriptor *desc,
                        uint32_t multi_index) {
  uint32_t num_keys = 0, network = 0;
  char *canonical = NULL;
  if (!desc || wally_descriptor_get_num_keys(desc, &num_keys) != WALLY_OK ||
      wally_descriptor_get_network(desc, &network) != WALLY_OK ||
      wally_descriptor_canonicalize(desc, WALLY_MS_CANONICAL_NO_CHECKSUM,
                                    &canonical) != WALLY_OK)
    return NULL;
  char *text = strdup(canonical);
  wally_free_string(canonical);

  bool ok = text != NULL, changed = false;
  for (uint32_t i = 0; ok && i < num_keys; i++)
    ok = rewrite_key(desc, i, multi_index, &text, &changed);

  struct wally_descriptor *branch = NULL;
  if (ok && changed &&
      wallet_descriptor_parse(text, NULL, network, &branch) == WALLY_OK &&
      !same_spk_at_child_0(desc, multi_index, branch)) {
    wally_descriptor_free(branch);
    branch = NULL;
  }
  free(text);
  return branch;
}
