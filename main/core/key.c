#include "key.h"
#include "../utils/secure_mem.h"
#include <esp_log.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wally_bip39.h>
#include <wally_crypto.h>

static struct ext_key *master_key = NULL;
static unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
static char *stored_mnemonic = NULL;
static bool key_loaded = false;

bool key_init(void) {
  key_loaded = false;
  master_key = NULL;
  secure_memzero(fingerprint, sizeof(fingerprint));
  return true;
}

bool key_is_loaded(void) { return key_loaded; }

bool key_load_from_mnemonic(const char *mnemonic, const char *passphrase,
                            bool is_testnet) {
  if (!mnemonic) {
    return false;
  }

  if (key_loaded) {
    key_unload();
  }

  int ret;
  unsigned char seed[BIP39_SEED_LEN_512];

  ret = bip39_mnemonic_validate(NULL, mnemonic);
  if (ret != WALLY_OK) {
    return false;
  }

  ret = bip39_mnemonic_to_seed512(mnemonic, passphrase, seed, sizeof(seed));
  if (ret != WALLY_OK) {
    secure_memzero(seed, sizeof(seed));
    return false;
  }

  uint32_t bip32_version =
      is_testnet ? BIP32_VER_TEST_PRIVATE : BIP32_VER_MAIN_PRIVATE;
  ret = bip32_key_from_seed_alloc(seed, sizeof(seed), bip32_version, 0,
                                  &master_key);
  if (ret != WALLY_OK) {
    secure_memzero(seed, sizeof(seed));
    return false;
  }

  ret = bip32_key_get_fingerprint(master_key, fingerprint,
                                  BIP32_KEY_FINGERPRINT_LEN);
  if (ret != WALLY_OK) {
    bip32_key_free(master_key);
    master_key = NULL;
    secure_memzero(seed, sizeof(seed));
    return false;
  }

  stored_mnemonic = strdup(mnemonic);
  if (!stored_mnemonic) {
    bip32_key_free(master_key);
    master_key = NULL;
    secure_memzero(seed, sizeof(seed));
    return false;
  }

  secure_memzero(seed, sizeof(seed));
  key_loaded = true;

  return true;
}

void key_unload(void) {
  if (master_key) {
    bip32_key_free(master_key);
    master_key = NULL;
  }
  SECURE_FREE_STRING(stored_mnemonic);
  secure_memzero(fingerprint, sizeof(fingerprint));
  key_loaded = false;
}

bool key_get_fingerprint(unsigned char *fingerprint_out) {
  if (!key_loaded || !fingerprint_out) {
    return false;
  }
  memcpy(fingerprint_out, fingerprint, BIP32_KEY_FINGERPRINT_LEN);
  return true;
}

bool key_get_fingerprint_hex(char *hex_out) {
  if (!key_loaded || !hex_out) {
    return false;
  }
  for (int i = 0; i < BIP32_KEY_FINGERPRINT_LEN; i++) {
    sprintf(hex_out + (i * 2), "%02x", fingerprint[i]);
  }
  hex_out[BIP32_KEY_FINGERPRINT_LEN * 2] = '\0';
  return true;
}

// Parse BIP32 path like "m/84'/0'/0'" into uint32_t array
static bool parse_derivation_path(const char *path, uint32_t *indices_out,
                                  size_t *depth_out, size_t max_depth) {
  if (!path || !path[0] || !indices_out || !depth_out) {
    return false;
  }

  for (const char *c = path; *c; c++) {
    if (*c != 'm' && *c != '/' && *c != '\'' && *c != 'h' &&
        !(*c >= '0' && *c <= '9')) {
      return false;
    }
  }

  const char *p = path;
  if (p[0] == 'm') {
    p++;
    if (p[0] == '/') {
      p++;
      if (p[0] == '\0') {
        return false;
      }
    } else if (p[0] != '\0') {
      return false;
    }
  }
  size_t depth = 0;

  while (*p && depth < max_depth) {
    uint32_t value = 0;
    bool has_digits = false;

    if (*p == '0' && p[1] >= '0' && p[1] <= '9') {
      return false;
    }

    while (*p >= '0' && *p <= '9') {
      uint32_t digit = (uint32_t)(*p - '0');
      if (value > UINT32_MAX / 10 ||
          (value == UINT32_MAX / 10 && digit > UINT32_MAX % 10)) {
        return false;
      }
      value = value * 10 + digit;
      p++;
      has_digits = true;
    }

    if (!has_digits) {
      return false;
    }

    if (*p == '\'' || *p == 'h') {
      if (value >= BIP32_INITIAL_HARDENED_CHILD) {
        return false;
      }
      value |= BIP32_INITIAL_HARDENED_CHILD;
      p++;
    } else if (value >= BIP32_INITIAL_HARDENED_CHILD) {
      return false;
    }

    indices_out[depth++] = value;

    if (*p == '/') {
      p++;
      if (*p == '\0') {
        return false;
      }
    } else if (*p == '\0') {
      break;
    } else {
      return false;
    }
  }

  if (*p != '\0') {
    return false;
  }

  *depth_out = depth;
  return true;
}

bool key_get_xpub(const char *path, char **xpub_out) {
  if (!key_loaded || !path || !xpub_out) {
    return false;
  }

  uint32_t path_indices[10];
  size_t path_depth = 0;

  if (!parse_derivation_path(path, path_indices, &path_depth, 10)) {
    return false;
  }

  struct ext_key *derived_key = NULL;
  int ret =
      bip32_key_from_parent_path_alloc(master_key, path_indices, path_depth,
                                       BIP32_FLAG_KEY_PRIVATE, &derived_key);
  if (ret != WALLY_OK) {
    return false;
  }

  ret = bip32_key_to_base58(derived_key, BIP32_FLAG_KEY_PUBLIC, xpub_out);
  bip32_key_free(derived_key);

  return (ret == WALLY_OK);
}

bool key_get_master_xpub(char **xpub_out) {
  if (!key_loaded || !xpub_out) {
    return false;
  }

  int ret = bip32_key_to_base58(master_key, BIP32_FLAG_KEY_PUBLIC, xpub_out);
  return (ret == WALLY_OK);
}

bool key_get_mnemonic(char **mnemonic_out) {
  if (!key_loaded || !stored_mnemonic || !mnemonic_out) {
    return false;
  }

  *mnemonic_out = strdup(stored_mnemonic);
  return (*mnemonic_out != NULL);
}

bool key_get_mnemonic_words(char ***words_out, size_t *word_count_out) {
  if (!key_loaded || !stored_mnemonic || !words_out || !word_count_out) {
    return false;
  }

  char *mnemonic_copy = strdup(stored_mnemonic);
  if (!mnemonic_copy) {
    return false;
  }

  size_t count = 0;
  char *token = strtok(mnemonic_copy, " ");
  while (token) {
    count++;
    token = strtok(NULL, " ");
  }

  if (count == 0) {
    SECURE_FREE_STRING(mnemonic_copy);
    return false;
  }

  char **words = (char **)malloc(count * sizeof(char *));
  if (!words) {
    SECURE_FREE_STRING(mnemonic_copy);
    return false;
  }

  strcpy(mnemonic_copy, stored_mnemonic);
  token = strtok(mnemonic_copy, " ");
  for (size_t i = 0; i < count && token; i++) {
    words[i] = strdup(token);
    if (!words[i]) {
      for (size_t j = 0; j < i; j++) {
        free(words[j]);
      }
      free(words);
      SECURE_FREE_STRING(mnemonic_copy);
      return false;
    }
    token = strtok(NULL, " ");
  }

  SECURE_FREE_STRING(mnemonic_copy);
  *words_out = words;
  *word_count_out = count;

  return true;
}

bool key_get_derived_key(const char *path, struct ext_key **key_out) {
  if (!key_loaded || !path || !key_out) {
    return false;
  }

  uint32_t path_indices[10];
  size_t path_depth = 0;

  if (!parse_derivation_path(path, path_indices, &path_depth, 10)) {
    return false;
  }

  int ret = bip32_key_from_parent_path_alloc(
      master_key, path_indices, path_depth, BIP32_FLAG_KEY_PRIVATE, key_out);
  return (ret == WALLY_OK);
}

void key_cleanup(void) { key_unload(); }
