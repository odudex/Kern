#include "seedqr.h"
#include "../utils/secure_mem.h"
#include "kern_wally.h"
#include "secure_memory.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip39.h>
#include <wally_core.h>

static bool is_all_digits(const char *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (!isdigit((unsigned char)data[i])) {
      return false;
    }
  }
  return true;
}

static bool looks_like_plaintext(const char *data, size_t len) {
  bool has_space = false;
  bool has_letter = false;

  for (size_t i = 0; i < len; i++) {
    char c = data[i];
    if (c == ' ') {
      has_space = true;
    } else if (isalpha((unsigned char)c)) {
      has_letter = true;
    } else if (!isprint((unsigned char)c)) {
      return false;
    }
  }
  return has_space && has_letter;
}

static bool has_non_printable(const char *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (!isprint((unsigned char)data[i]) && !isspace((unsigned char)data[i])) {
      return true;
    }
  }
  return false;
}

mnemonic_qr_format_t mnemonic_qr_detect_format(const char *data, size_t len) {
  if (!data || len == 0) {
    return MNEMONIC_QR_UNKNOWN;
  }

  // Compact SeedQR: exactly 16 or 32 bytes with non-printable characters
  if ((len == COMPACT_SEEDQR_12_WORDS_LEN ||
       len == COMPACT_SEEDQR_24_WORDS_LEN) &&
      has_non_printable(data, len)) {
    return MNEMONIC_QR_COMPACT;
  }

  // SeedQR: exactly 48 or 96 decimal digits
  if ((len == SEEDQR_12_WORDS_LEN || len == SEEDQR_24_WORDS_LEN) &&
      is_all_digits(data, len)) {
    return MNEMONIC_QR_SEEDQR;
  }

  // Plaintext: contains spaces and letters
  if (looks_like_plaintext(data, len)) {
    return MNEMONIC_QR_PLAINTEXT;
  }

  // 16/32 bytes of printable data - try as Compact SeedQR anyway
  if (len == COMPACT_SEEDQR_12_WORDS_LEN ||
      len == COMPACT_SEEDQR_24_WORDS_LEN) {
    return MNEMONIC_QR_COMPACT;
  }

  return MNEMONIC_QR_UNKNOWN;
}

char *mnemonic_qr_compact_to_mnemonic(const unsigned char *data, size_t len) {
  if (!data || (len != COMPACT_SEEDQR_12_WORDS_LEN &&
                len != COMPACT_SEEDQR_24_WORDS_LEN)) {
    return NULL;
  }

  char *wally_mnemonic = NULL;
  if (kern_bip39_mnemonic_from_bytes(NULL, data, len, &wally_mnemonic) !=
          WALLY_OK ||
      !wally_mnemonic) {
    return NULL;
  }

  return wally_mnemonic;
}

char *mnemonic_qr_seedqr_to_mnemonic(const char *data, size_t len) {
  if (!data || (len != SEEDQR_12_WORDS_LEN && len != SEEDQR_24_WORDS_LEN) ||
      !is_all_digits(data, len)) {
    return NULL;
  }

  int word_count = (len == SEEDQR_12_WORDS_LEN) ? 12 : 24;

  struct words *wordlist = NULL;
  if (bip39_get_wordlist(NULL, &wordlist) != WALLY_OK || !wordlist) {
    return NULL;
  }

  size_t max_len = word_count * 12;
  char *mnemonic = kern_secret_alloc(max_len);
  if (!mnemonic) {
    return NULL;
  }

  size_t offset = 0;
  for (int i = 0; i < word_count; i++) {
    char index_str[5] = {data[i * 4], data[i * 4 + 1], data[i * 4 + 2],
                         data[i * 4 + 3], '\0'};
    int word_index = atoi(index_str);

    if (word_index < 0 || word_index > 2047) {
      SECURE_FREE_BUFFER(mnemonic, max_len);
      return NULL;
    }

    const char *word = bip39_get_word_by_index(wordlist, (size_t)word_index);
    if (!word) {
      SECURE_FREE_BUFFER(mnemonic, max_len);
      return NULL;
    }

    if (i > 0) {
      mnemonic[offset++] = ' ';
    }

    size_t word_len = strlen(word);
    if (offset + word_len >= max_len) {
      SECURE_FREE_BUFFER(mnemonic, max_len);
      return NULL;
    }

    memcpy(mnemonic + offset, word, word_len);
    offset += word_len;
  }
  mnemonic[offset] = '\0';

  if (kern_bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    SECURE_FREE_BUFFER(mnemonic, max_len);
    return NULL;
  }

  return mnemonic;
}

char *mnemonic_qr_to_mnemonic(const char *data, size_t len,
                              mnemonic_qr_format_t *format_out) {
  if (!data || len == 0) {
    if (format_out) {
      *format_out = MNEMONIC_QR_UNKNOWN;
    }
    return NULL;
  }

  mnemonic_qr_format_t format = mnemonic_qr_detect_format(data, len);
  if (format_out) {
    *format_out = format;
  }

  switch (format) {
  case MNEMONIC_QR_COMPACT:
    return mnemonic_qr_compact_to_mnemonic((const unsigned char *)data, len);

  case MNEMONIC_QR_SEEDQR:
    return mnemonic_qr_seedqr_to_mnemonic(data, len);

  case MNEMONIC_QR_PLAINTEXT: {
    char *mnemonic = kern_secret_strndup(data, len);
    if (mnemonic && kern_bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
      SECURE_FREE_STRING(mnemonic);
      return NULL;
    }
    return mnemonic;
  }

  default:
    return NULL;
  }
}

char *mnemonic_to_seedqr(const char *mnemonic) {
  if (!mnemonic) {
    return NULL;
  }

  // Validate mnemonic first
  if (kern_bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    return NULL;
  }

  // Get the BIP39 wordlist
  struct words *wordlist = NULL;
  if (bip39_get_wordlist(NULL, &wordlist) != WALLY_OK || !wordlist) {
    return NULL;
  }

  // Count words to determine output size
  int word_count = 0;
  const char *p = mnemonic;
  while (*p) {
    while (*p == ' ')
      p++;
    if (*p) {
      word_count++;
      while (*p && *p != ' ')
        p++;
    }
  }

  if (word_count != 12 && word_count != 24) {
    return NULL;
  }

  // Allocate output buffer (4 digits per word + null terminator)
  size_t output_len = (size_t)word_count * 4 + 1;
  char *seedqr = kern_secret_alloc(output_len);
  if (!seedqr) {
    return NULL;
  }

  // Process each word
  size_t offset = 0;
  p = mnemonic;
  while (*p) {
    // Skip leading spaces
    while (*p == ' ')
      p++;
    if (!*p)
      break;

    // Find word end
    const char *word_start = p;
    while (*p && *p != ' ')
      p++;
    size_t word_len = (size_t)(p - word_start);

    // Create null-terminated word for lookup
    char word[16];
    if (word_len >= sizeof(word)) {
      SECURE_FREE_BUFFER(seedqr, output_len);
      return NULL;
    }
    memcpy(word, word_start, word_len);
    word[word_len] = '\0';

    // Find word index in wordlist
    size_t word_index;
    bool found = false;
    for (size_t i = 0; i < 2048; i++) {
      const char *list_word = bip39_get_word_by_index(wordlist, i);
      if (list_word && strcmp(word, list_word) == 0) {
        word_index = i;
        found = true;
        break;
      }
    }
    secure_memzero(word, sizeof(word));

    if (!found) {
      SECURE_FREE_BUFFER(seedqr, output_len);
      return NULL;
    }

    // Write 4-digit zero-padded index
    snprintf(seedqr + offset, 5, "%04zu", word_index);
    offset += 4;
  }

  seedqr[offset] = '\0';
  return seedqr;
}

unsigned char *mnemonic_to_compact_seedqr(const char *mnemonic,
                                          size_t *out_len) {
  if (!mnemonic || !out_len) {
    return NULL;
  }

  unsigned char *result = kern_secret_alloc(COMPACT_SEEDQR_24_WORDS_LEN);
  if (!result) {
    return NULL;
  }

  size_t entropy_len = 0;
  if (kern_bip39_mnemonic_to_bytes(NULL, mnemonic, result,
                                   COMPACT_SEEDQR_24_WORDS_LEN,
                                   &entropy_len) != WALLY_OK ||
      (entropy_len != COMPACT_SEEDQR_12_WORDS_LEN &&
       entropy_len != COMPACT_SEEDQR_24_WORDS_LEN)) {
    SECURE_FREE_BUFFER(result, COMPACT_SEEDQR_24_WORDS_LEN);
    return NULL;
  }

  *out_len = entropy_len;
  return result;
}
