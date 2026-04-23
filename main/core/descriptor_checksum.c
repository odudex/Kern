#include "descriptor_checksum.h"
#include "registry.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#include <wally_descriptor.h>

/*
 * Descriptor checksum (BIP-380) — computed over the h-normalized canonical
 * form so the result matches coordinators like Sparrow that use 'h' for
 * hardened derivation.
 *
 * Algorithm adapted from bitcoin-core / libwally descriptor.c.
 */

// clang-format off
static const unsigned char desc_cksum_pos[] = {
  0x5f,0x3c,0x5d,0x5c,0x1d,0x1e,0x33,0x10,0x0b,0x0c,0x12,0x34,0x0f,0x35,0x36,0x11,
  0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x1c,0x37,0x38,0x39,0x3a,0x3b,
  0x1b,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
  0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x0d,0x5e,0x0e,0x3d,0x3e,
  0x5b,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
  0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x1f,0x3f,0x20,0x40
};
// clang-format on

static const char desc_cksum_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint64_t desc_polymod(uint64_t c, int val) {
  uint8_t c0 = c >> 35;
  c = ((c & 0x7ffffffff) << 5) ^ val;
  if (c0 & 1)
    c ^= 0xf5dee51989;
  if (c0 & 2)
    c ^= 0xa9fdca3312;
  if (c0 & 4)
    c ^= 0x1bab10e32d;
  if (c0 & 8)
    c ^= 0x3706b1677a;
  if (c0 & 16)
    c ^= 0x644d626ffd;
  return c;
}

static bool desc_compute_checksum(const char *str, size_t len, char out[9]) {
  uint64_t c = 1;
  int cls = 0, clscount = 0;

  for (size_t i = 0; i < len; i++) {
    char ch = str[i];
    if (ch < ' ' || ch > '~')
      return false;
    size_t pos = desc_cksum_pos[(unsigned char)(ch - ' ')];
    if (pos == 0)
      return false;
    --pos;
    c = desc_polymod(c, pos & 31);
    cls = cls * 3 + (int)(pos >> 5);
    if (++clscount == 3) {
      c = desc_polymod(c, cls);
      cls = 0;
      clscount = 0;
    }
  }
  if (clscount > 0)
    c = desc_polymod(c, cls);
  for (int i = 0; i < 8; i++)
    c = desc_polymod(c, 0);
  c ^= 1;

  for (int i = 0; i < 8; i++)
    out[i] = desc_cksum_charset[(c >> (5 * (7 - i))) & 31];
  out[8] = '\0';
  return true;
}

bool wallet_get_descriptor_string(char **output) {
  const registry_entry_t *entry = registry_get(0);
  if (!entry || !entry->desc || !output)
    return false;

  /* Get canonical body without checksum (uses ' for hardened) */
  char *canonical = NULL;
  if (wally_descriptor_canonicalize(entry->desc, WALLY_MS_CANONICAL_NO_CHECKSUM,
                                    &canonical) != WALLY_OK)
    return false;

  size_t body_len = strlen(canonical);

  /* Replace ' with h to match most coordinators */
  for (char *p = canonical; *p; p++) {
    if (*p == '\'')
      *p = 'h';
  }

  /* Compute checksum over the h-normalized body */
  char cksum[9];
  if (!desc_compute_checksum(canonical, body_len, cksum)) {
    wally_free_string(canonical);
    return false;
  }

  /* Assemble: body + '#' + checksum */
  char *result = malloc(body_len + 1 + 8 + 1);
  if (!result) {
    wally_free_string(canonical);
    return false;
  }
  memcpy(result, canonical, body_len);
  result[body_len] = '#';
  memcpy(result + body_len + 1, cksum, 8);
  result[body_len + 9] = '\0';

  wally_free_string(canonical);
  *output = result;
  return true;
}

bool wallet_get_descriptor_checksum(char **output) {
  if (!output)
    return false;

  char *desc = NULL;
  if (!wallet_get_descriptor_string(&desc))
    return false;

  /* Checksum is the last 8 chars (after '#') */
  size_t len = strlen(desc);
  *output = (len >= 8) ? strdup(desc + len - 8) : NULL;
  free(desc);
  return (*output != NULL);
}
