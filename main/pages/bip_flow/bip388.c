#include "bip388.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BIP388_WILDCARD "/**"
#define BIP388_MULTIPATH "/<0;1>/*"

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

// Reads the N of the @N at *p, moving *p past it. False when N names no key.
static bool read_key_index(const char **p, size_t key_count, size_t *index) {
  const char *digits = *p + 1;
  if (!is_digit(*digits))
    return false;
  size_t n = 0;
  for (; is_digit(*digits); digits++) {
    n = n * 10 + (size_t)(*digits - '0');
    if (n >= key_count)
      return false;
  }
  *p = digits;
  *index = n;
  return true;
}

// The length of the descriptor, written to `out` when not NULL. SIZE_MAX when
// an @N names no key.
static size_t expand(const char *policy, const char *const *keys,
                     size_t key_count, char *out) {
  size_t len = 0;
  const char *p = policy;
  while (*p) {
    const char *piece = p;
    size_t piece_len = 1;
    size_t index;
    if (strncmp(p, BIP388_WILDCARD, strlen(BIP388_WILDCARD)) == 0) {
      piece = BIP388_MULTIPATH;
      piece_len = strlen(BIP388_MULTIPATH);
      p += strlen(BIP388_WILDCARD);
    } else if (*p == '@') {
      if (!read_key_index(&p, key_count, &index) || !keys[index])
        return SIZE_MAX;
      piece = keys[index];
      piece_len = strlen(piece);
    } else {
      p++;
    }
    if (out)
      memcpy(out + len, piece, piece_len);
    len += piece_len;
  }
  return len;
}

bool bip388_policy_is_valid(const char *policy, const char *const *keys,
                            size_t key_count) {
  return policy && (keys || key_count == 0) &&
         expand(policy, keys, key_count, NULL) != SIZE_MAX;
}

char *bip388_descriptor_alloc(const char *policy, const char *const *keys,
                              size_t key_count) {
  if (!bip388_policy_is_valid(policy, keys, key_count))
    return NULL;
  size_t len = expand(policy, keys, key_count, NULL);
  char *out = malloc(len + 1);
  if (!out)
    return NULL;
  expand(policy, keys, key_count, out);
  out[len] = '\0';
  return out;
}
