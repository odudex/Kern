#include "key.h"
#include "../utils/secure_mem.h"
#include "bip32_path.h"
#include <esp_log.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>

static struct ext_key *master_key = NULL;
static unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
static char *stored_mnemonic = NULL;
static bool key_loaded = false;

#define KEY_MAX_DERIVATION_DEPTH 10

static void fingerprint_to_hex(const unsigned char *fp, char *hex_out) {
  for (int i = 0; i < BIP32_KEY_FINGERPRINT_LEN; i++) {
    sprintf(hex_out + (i * 2), "%02x", fp[i]);
  }
}

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
  fingerprint_to_hex(fingerprint, hex_out);
  return true;
}

bool key_mnemonic_fingerprint_hex(const char *mnemonic, char *hex_out) {
  if (!mnemonic || !hex_out)
    return false;

  if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK)
    return false;

  unsigned char seed[BIP39_SEED_LEN_512];
  unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
  struct ext_key *mnemonic_key = NULL;
  bool ok = false;

  if (bip39_mnemonic_to_seed512(mnemonic, NULL, seed, sizeof(seed)) !=
          WALLY_OK ||
      bip32_key_from_seed_alloc(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0,
                                &mnemonic_key) != WALLY_OK)
    goto cleanup;

  if (bip32_key_get_fingerprint(mnemonic_key, fp, BIP32_KEY_FINGERPRINT_LEN) !=
      WALLY_OK)
    goto cleanup;

  fingerprint_to_hex(fp, hex_out);
  ok = true;

cleanup:
  if (mnemonic_key)
    bip32_key_free(mnemonic_key);
  secure_memzero(seed, sizeof(seed));
  return ok;
}

bool key_get_xpub(const char *path, char **xpub_out) {
  if (!key_loaded || !path || !xpub_out) {
    return false;
  }

  uint32_t path_indices[KEY_MAX_DERIVATION_DEPTH];
  size_t path_depth = 0;

  if (!bip32_path_parse(path, path_indices, &path_depth,
                        KEY_MAX_DERIVATION_DEPTH)) {
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
  *key_out = NULL;

  uint32_t path_indices[KEY_MAX_DERIVATION_DEPTH];
  size_t path_depth = 0;

  if (!bip32_path_parse(path, path_indices, &path_depth,
                        KEY_MAX_DERIVATION_DEPTH)) {
    return false;
  }

  return key_get_derived_key_components(path_indices, path_depth, key_out);
}

bool key_get_derived_key_components(const uint32_t *path, size_t path_depth,
                                    struct ext_key **key_out) {
  if (!key_loaded || !key_out || (!path && path_depth > 0) ||
      path_depth > KEY_MAX_DERIVATION_DEPTH) {
    return false;
  }
  *key_out = NULL;

  if (path_depth == 0) {
    struct ext_key *key_copy = wally_malloc(sizeof(*key_copy));
    if (!key_copy)
      return false;
    memcpy(key_copy, master_key, sizeof(*key_copy));
    *key_out = key_copy;
    return true;
  }

  int ret = bip32_key_from_parent_path_alloc(master_key, path, path_depth,
                                             BIP32_FLAG_KEY_PRIVATE, key_out);
  return (ret == WALLY_OK);
}

void key_cleanup(void) { key_unload(); }
