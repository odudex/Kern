#include "mnemonic_qr.h"
#include <ctype.h>
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
  if (bip39_mnemonic_from_bytes(NULL, data, len, &wally_mnemonic) != WALLY_OK ||
      !wally_mnemonic) {
    return NULL;
  }

  if (bip39_mnemonic_validate(NULL, wally_mnemonic) != WALLY_OK) {
    wally_free_string(wally_mnemonic);
    return NULL;
  }

  char *mnemonic = strdup(wally_mnemonic);
  wally_free_string(wally_mnemonic);
  return mnemonic;
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
  char *mnemonic = malloc(max_len);
  if (!mnemonic) {
    return NULL;
  }

  size_t offset = 0;
  for (int i = 0; i < word_count; i++) {
    char index_str[5] = {data[i * 4], data[i * 4 + 1], data[i * 4 + 2],
                         data[i * 4 + 3], '\0'};
    int word_index = atoi(index_str);

    if (word_index < 0 || word_index > 2047) {
      free(mnemonic);
      return NULL;
    }

    const char *word = bip39_get_word_by_index(wordlist, (size_t)word_index);
    if (!word) {
      free(mnemonic);
      return NULL;
    }

    if (i > 0) {
      mnemonic[offset++] = ' ';
    }

    size_t word_len = strlen(word);
    if (offset + word_len >= max_len) {
      free(mnemonic);
      return NULL;
    }

    memcpy(mnemonic + offset, word, word_len);
    offset += word_len;
  }
  mnemonic[offset] = '\0';

  if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    free(mnemonic);
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
    char *mnemonic = strndup(data, len);
    if (mnemonic && bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
      free(mnemonic);
      return NULL;
    }
    return mnemonic;
  }

  default:
    return NULL;
  }
}

const char *mnemonic_qr_format_name(mnemonic_qr_format_t format) {
  switch (format) {
  case MNEMONIC_QR_PLAINTEXT:
    return "Plaintext";
  case MNEMONIC_QR_COMPACT:
    return "Compact SeedQR";
  case MNEMONIC_QR_SEEDQR:
    return "SeedQR";
  default:
    return "Unknown";
  }
}
