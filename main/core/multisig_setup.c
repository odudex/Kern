#include "multisig_setup.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wally_core.h>

// 15 keys is the most a 520-byte inner script holds, enforced for all
// descriptors by VALIDATION_UNSUPPORTED_SCRIPT.
#define MULTISIG_SETUP_MAX_KEYS 15
#define MULTISIG_SETUP_PATH_LEN 64
#define DERIVATION_LABEL "Derivation:"

// Convert extended pubkey with non-standard version bytes to xpub/tpub.
// Handles Zpub, Ypub (mainnet) and vpub, upub (testnet).
static char *convert_xpub_version(const char *key) {
  static const struct {
    uint8_t from[4], to[4];
  } version_map[] = {
      {{0x02, 0xaa, 0x7e, 0xd3}, {0x04, 0x88, 0xb2, 0x1e}}, // Zpub -> xpub
      {{0x02, 0x95, 0xb4, 0x3f}, {0x04, 0x88, 0xb2, 0x1e}}, // Ypub -> xpub
      {{0x04, 0x5f, 0x1c, 0xf6}, {0x04, 0x35, 0x87, 0xcf}}, // vpub -> tpub
      {{0x04, 0x4a, 0x52, 0x62}, {0x04, 0x35, 0x87, 0xcf}}, // upub -> tpub
  };

  uint8_t decoded[78 + BASE58_CHECKSUM_LEN];
  size_t written = 0;
  if (wally_base58_to_bytes(key, BASE58_FLAG_CHECKSUM, decoded, sizeof(decoded),
                            &written) != WALLY_OK ||
      written != 78)
    return NULL;

  for (size_t i = 0; i < sizeof(version_map) / sizeof(version_map[0]); i++) {
    if (memcmp(decoded, version_map[i].from, 4) == 0) {
      memcpy(decoded, version_map[i].to, 4);
      goto encode;
    }
  }

  // Already xpub/tpub — re-encode unchanged
  if (memcmp(decoded, "\x04\x88\xb2\x1e", 4) != 0 &&
      memcmp(decoded, "\x04\x35\x87\xcf", 4) != 0)
    return NULL;

encode:;
  char *wally_str = NULL;
  if (wally_base58_from_bytes(decoded, written, BASE58_FLAG_CHECKSUM,
                              &wally_str) != WALLY_OK)
    return NULL;
  char *result = strdup(wally_str);
  wally_free_string(wally_str);
  return result;
}

// Copy the path of the Derivation line at `line`, minus any "m/" prefix.
static bool read_derivation(const char *line,
                            char out[MULTISIG_SETUP_PATH_LEN]) {
  line += strlen(DERIVATION_LABEL);
  while (*line == ' ' || *line == '\t')
    line++;
  if (line[0] == 'm' && line[1] == '/')
    line += 2;
  size_t len = strcspn(line, " \t\r\n");
  if (len == 0 || len >= MULTISIG_SETUP_PATH_LEN)
    return false;
  memcpy(out, line, len);
  out[len] = '\0';
  return true;
}

char *multisig_setup_to_descriptor(const char *text) {
  if (!text)
    return NULL;

  const char *policy_line = strstr(text, "Policy:");
  const char *format_line = strstr(text, "Format:");
  if (!policy_line || !format_line)
    return NULL;

  unsigned int threshold = 0, num_keys = 0;
  if (sscanf(policy_line, "Policy: %u of %u", &threshold, &num_keys) != 2 ||
      threshold == 0 || num_keys == 0 || threshold > num_keys ||
      num_keys > MULTISIG_SETUP_MAX_KEYS)
    return NULL;

  char format[16] = {0};
  sscanf(format_line, "Format: %15s", format);
  const char *wrapper_open, *wrapper_close;
  if (strcasecmp(format, "P2WSH") == 0) {
    wrapper_open = "wsh(";
    wrapper_close = ")";
  } else if (strcasecmp(format, "P2SH-P2WSH") == 0 ||
             strcasecmp(format, "P2WSH-P2SH") == 0) {
    wrapper_open = "sh(wsh(";
    wrapper_close = "))";
  } else if (strcasecmp(format, "P2SH") == 0) {
    wrapper_open = "sh(";
    wrapper_close = ")";
  } else {
    return NULL;
  }

  char derivation[MULTISIG_SETUP_PATH_LEN] = "";
  char fingerprints[MULTISIG_SETUP_MAX_KEYS][9];
  char origins[MULTISIG_SETUP_MAX_KEYS][MULTISIG_SETUP_PATH_LEN];
  char *xpubs[MULTISIG_SETUP_MAX_KEYS];
  unsigned int found_keys = 0;
  memset(xpubs, 0, sizeof(xpubs));

  const char *line = text;
  while (*line && found_keys < num_keys) {
    while (*line == ' ' || *line == '\t')
      line++;

    if (strncmp(line, DERIVATION_LABEL, strlen(DERIVATION_LABEL)) == 0) {
      if (!read_derivation(line, derivation))
        goto cleanup;
    } else if (strlen(line) > 10) {
      bool is_hex = true;
      for (int i = 0; i < 8 && is_hex; i++)
        is_hex = isxdigit((unsigned char)line[i]);

      if (is_hex && line[8] == ':' && line[9] == ' ') {
        if (!derivation[0])
          goto cleanup;
        for (int i = 0; i < 8; i++)
          fingerprints[found_keys][i] = tolower((unsigned char)line[i]);
        fingerprints[found_keys][8] = '\0';
        memcpy(origins[found_keys], derivation, sizeof(derivation));

        const char *key_start = line + 10;
        const char *key_end = key_start;
        while (*key_end && *key_end != '\n' && *key_end != '\r' &&
               *key_end != ' ')
          key_end++;

        char *raw_key = malloc(key_end - key_start + 1);
        if (!raw_key)
          goto cleanup;
        memcpy(raw_key, key_start, key_end - key_start);
        raw_key[key_end - key_start] = '\0';

        xpubs[found_keys] = convert_xpub_version(raw_key);
        free(raw_key);
        if (!xpubs[found_keys])
          goto cleanup;
        found_keys++;
      }
    }

    while (*line && *line != '\n')
      line++;
    if (*line == '\n')
      line++;
  }

  if (found_keys != num_keys)
    goto cleanup;

  size_t desc_size = 64;
  for (unsigned int i = 0; i < num_keys; i++)
    desc_size += 8 + strlen(origins[i]) + strlen(xpubs[i]) + 5;

  char *descriptor = malloc(desc_size);
  if (!descriptor)
    goto cleanup;

  int pos = snprintf(descriptor, desc_size, "%ssortedmulti(%u", wrapper_open,
                     threshold);
  for (unsigned int i = 0; i < num_keys; i++)
    pos += snprintf(descriptor + pos, desc_size - pos, ",[%s/%s]%s",
                    fingerprints[i], origins[i], xpubs[i]);
  snprintf(descriptor + pos, desc_size - pos, ")%s", wrapper_close);

  for (unsigned int i = 0; i < found_keys; i++)
    free(xpubs[i]);
  return descriptor;

cleanup:
  for (unsigned int i = 0; i < found_keys; i++)
    free(xpubs[i]);
  return NULL;
}
