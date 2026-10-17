// BIP39 word filtering utilities for smart keyboard input

#include "bip39_filter.h"
#include "kern_wally.h"
#include "secure_mem.h"
#include <stdio.h>
#include <string.h>
#include <wally_bip39.h>
#include <wally_core.h>

static struct words *wordlist = NULL;

// Cache for valid last words to avoid recalculating on every keystroke
#define MAX_VALID_LAST_WORDS 128
static const char *valid_last_words_cache[MAX_VALID_LAST_WORDS];
static int valid_last_words_count = 0;

bool bip39_filter_init(void) {
  if (wordlist)
    return true;
  return bip39_get_wordlist(NULL, &wordlist) == WALLY_OK;
}

uint32_t bip39_filter_get_valid_letters(const char *prefix, int prefix_len) {
  uint32_t mask = 0;
  if (!wordlist)
    return 0xFFFFFFFF;

  for (int letter = 0; letter < 26; letter++) {
    char test_prefix[BIP39_MAX_PREFIX_LEN + 2];
    int test_len = prefix_len + 1;

    if (prefix && prefix_len > 0) {
      int copy_len =
          prefix_len < BIP39_MAX_PREFIX_LEN ? prefix_len : BIP39_MAX_PREFIX_LEN;
      memcpy(test_prefix, prefix, copy_len);
      test_prefix[copy_len] = 'a' + letter;
      test_prefix[copy_len + 1] = '\0';
    } else {
      test_prefix[0] = 'a' + letter;
      test_prefix[1] = '\0';
      test_len = 1;
    }

    for (size_t i = 0; i < BIP39_WORDLIST_SIZE; i++) {
      const char *word = bip39_get_word_by_index(wordlist, i);
      if (word && strncmp(word, test_prefix, test_len) == 0) {
        mask |= (1u << letter);
        break;
      }
    }
  }
  return mask;
}

int bip39_filter_by_prefix(const char *prefix, int prefix_len,
                           const char **out_words, int max_words) {
  int count = 0;
  if (!wordlist || !out_words || max_words <= 0)
    return 0;
  if (!prefix || prefix_len <= 0)
    return 0;

  for (size_t i = 0; i < BIP39_WORDLIST_SIZE && count < max_words; i++) {
    const char *word = bip39_get_word_by_index(wordlist, i);
    if (word && strncmp(word, prefix, prefix_len) == 0) {
      out_words[count++] = word;
    }
  }
  return count;
}

int bip39_filter_count_matches(const char *prefix, int prefix_len) {
  int count = 0;
  if (!wordlist)
    return 0;
  if (!prefix || prefix_len <= 0)
    return BIP39_WORDLIST_SIZE;

  for (size_t i = 0; i < BIP39_WORDLIST_SIZE; i++) {
    const char *word = bip39_get_word_by_index(wordlist, i);
    if (word && strncmp(word, prefix, prefix_len) == 0)
      count++;
  }
  return count;
}

int bip39_filter_get_word_index(const char *word) {
  if (!wordlist || !word)
    return -1;

  for (size_t i = 0; i < BIP39_WORDLIST_SIZE; i++) {
    const char *w = bip39_get_word_by_index(wordlist, i);
    if (w && strcmp(w, word) == 0)
      return (int)i;
  }
  return -1;
}

/* Appends the low `nbits` of `value` to `packed` at *bit_pos, MSB first. */
static void pack_bits(uint8_t packed[32], int *bit_pos, uint32_t value,
                      int nbits) {
  for (int b = nbits - 1; b >= 0; b--, (*bit_pos)++) {
    uint8_t mask = (uint8_t)(1u << (7 - (*bit_pos % 8)));
    if (value & (1u << b))
      packed[*bit_pos / 8] |= mask;
    else
      packed[*bit_pos / 8] &= (uint8_t)~mask;
  }
}

static bool pack_words(const char entered_words[24][16], int count,
                       uint8_t packed[32], int *bit_pos) {
  for (int i = 0; i < count; i++) {
    int idx = bip39_filter_get_word_index(entered_words[i]);
    if (idx < 0)
      return false;
    pack_bits(packed, bit_pos, (uint32_t)idx, 11);
  }
  return true;
}

void bip39_filter_clear_last_word_cache(void) {
  memset(valid_last_words_cache, 0, sizeof(valid_last_words_cache));
  valid_last_words_count = 0;
}

/* Warms valid_last_words_cache and returns how many entries it holds. */
static int ensure_last_word_cache(const char entered_words[24][16],
                                  int word_count) {
  if (valid_last_words_count == 0) {
    const char *temp[MAX_VALID_LAST_WORDS];
    return bip39_filter_get_valid_last_words(entered_words, word_count, temp,
                                             MAX_VALID_LAST_WORDS);
  }
  return valid_last_words_count;
}

int bip39_filter_get_valid_last_words(const char entered_words[24][16],
                                      int word_count, const char **out_words,
                                      int max_words) {
  if (!wordlist || !entered_words || !out_words || max_words <= 0)
    return 0;
  if (word_count != 12 && word_count != 24)
    return 0;

  // 12 words: 128 bits entropy + 4 bits checksum, last word has 7 entropy bits
  // 24 words: 256 bits entropy + 8 bits checksum, last word has 3 entropy bits
  size_t checksum_bits = word_count / 3;
  size_t entropy_bytes = ((word_count * 11) - checksum_bits) / 8;
  size_t last_word_entropy_bits = 11 - checksum_bits;
  int num_possibilities = 1 << last_word_entropy_bits;

  // Pack word indices (11 bits each) from first N-1 words. Both buffers hold
  // all but a few bits of the seed's entropy.
  uint8_t packed[32] = {0};
  uint8_t test_packed[32];
  int bit_pos = 0;
  int count = 0;

  if (!pack_words(entered_words, word_count - 1, packed, &bit_pos))
    goto cleanup;

  valid_last_words_count = 0;

  for (int entropy_val = 0;
       entropy_val < num_possibilities && count < max_words; entropy_val++) {
    memcpy(test_packed, packed, sizeof(test_packed));

    int test_bit_pos = bit_pos;
    pack_bits(test_packed, &test_bit_pos, (uint32_t)entropy_val,
              (int)last_word_entropy_bits);

    char *new_mnemonic = NULL;
    if (kern_bip39_mnemonic_from_bytes(NULL, test_packed, entropy_bytes,
                                       &new_mnemonic) != WALLY_OK)
      continue;

    char *last_space = strrchr(new_mnemonic, ' ');
    if (last_space) {
      int idx = bip39_filter_get_word_index(last_space + 1);
      if (idx >= 0) {
        const char *w = bip39_get_word_by_index(wordlist, idx);
        out_words[count++] = w;
        if (valid_last_words_count < MAX_VALID_LAST_WORDS)
          valid_last_words_cache[valid_last_words_count++] = w;
      }
    }

    SECURE_FREE_STRING(new_mnemonic);
  }

cleanup:
  secure_memzero(packed, sizeof(packed));
  secure_memzero(test_packed, sizeof(test_packed));
  return count;
}

uint32_t
bip39_filter_get_valid_letters_for_last_word(const char entered_words[24][16],
                                             int word_count, const char *prefix,
                                             int prefix_len) {
  if (!wordlist)
    return 0xFFFFFFFF;

  if (ensure_last_word_cache(entered_words, word_count) == 0)
    return 0;

  uint32_t mask = 0;
  for (int letter = 0; letter < 26; letter++) {
    char test_prefix[BIP39_MAX_PREFIX_LEN + 2];
    int test_len;

    if (prefix && prefix_len > 0) {
      int copy_len =
          prefix_len < BIP39_MAX_PREFIX_LEN ? prefix_len : BIP39_MAX_PREFIX_LEN;
      memcpy(test_prefix, prefix, copy_len);
      test_prefix[copy_len] = 'a' + letter;
      test_prefix[copy_len + 1] = '\0';
      test_len = prefix_len + 1;
    } else {
      test_prefix[0] = 'a' + letter;
      test_prefix[1] = '\0';
      test_len = 1;
    }

    for (int i = 0; i < valid_last_words_count; i++) {
      if (strncmp(valid_last_words_cache[i], test_prefix, test_len) == 0) {
        mask |= (1u << letter);
        break;
      }
    }
  }

  return mask;
}

int bip39_filter_last_word_by_prefix(const char entered_words[24][16],
                                     int word_count, const char *prefix,
                                     int prefix_len, const char **out_words,
                                     int max_words) {
  if (!wordlist || !out_words || max_words <= 0)
    return 0;

  if (ensure_last_word_cache(entered_words, word_count) == 0)
    return 0;

  if (!prefix || prefix_len <= 0) {
    int count =
        valid_last_words_count < max_words ? valid_last_words_count : max_words;
    for (int i = 0; i < count; i++)
      out_words[i] = valid_last_words_cache[i];
    return count;
  }

  int count = 0;
  for (int i = 0; i < valid_last_words_count && count < max_words; i++) {
    if (strncmp(valid_last_words_cache[i], prefix, prefix_len) == 0)
      out_words[count++] = valid_last_words_cache[i];
  }

  return count;
}

bool bip39_filter_complete_last_word(char entered_words[24][16],
                                     int word_count) {
  if (!wordlist || !entered_words || word_count < 12 || word_count > 24 ||
      word_count % 3 != 0)
    return false;

  int checksum_bits = word_count / 3;
  size_t entropy_bytes = (size_t)((word_count * 11) - checksum_bits) / 8;
  uint8_t packed[32] = {0};
  int bit_pos = 0;
  char *mnemonic = NULL;
  bool ok = false;

  if (!pack_words(entered_words, word_count - 1, packed, &bit_pos))
    goto cleanup;
  int last_idx = bip39_filter_get_word_index(entered_words[word_count - 1]);
  if (last_idx >= 0)
    pack_bits(packed, &bit_pos, (uint32_t)last_idx >> checksum_bits,
              11 - checksum_bits);

  if (kern_bip39_mnemonic_from_bytes(NULL, packed, entropy_bytes, &mnemonic) !=
          WALLY_OK ||
      !mnemonic)
    goto cleanup;
  const char *last = strrchr(mnemonic, ' ');
  if (last) {
    snprintf(entered_words[word_count - 1], sizeof(entered_words[0]), "%s",
             last + 1);
    ok = true;
  }

cleanup:
  SECURE_FREE_STRING(mnemonic);
  secure_memzero(packed, sizeof(packed));
  return ok;
}
