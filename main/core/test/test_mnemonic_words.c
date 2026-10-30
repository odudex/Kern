#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_core.h>

#include "core/dice_mnemonic.h"
#include "utils/bip39_filter.h"
#include "utils/secure_mem.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                          \
    tests_passed++;                                                            \
  } while (0)
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

static void fill_words(char words[24][16], const char *mnemonic) {
  memset(words, 0, 24 * 16);
  char copy[24 * 16];
  snprintf(copy, sizeof(copy), "%s", mnemonic);
  int n = 0;
  for (char *tok = strtok(copy, " "); tok && n < 24; tok = strtok(NULL, " "))
    snprintf(words[n++], 16, "%s", tok);
}

static void repeat(char *out, size_t out_len, const char *word, int count,
                   const char *last) {
  out[0] = '\0';
  for (int i = 0; i < count; i++) {
    strncat(out, word, out_len - strlen(out) - 1);
    strncat(out, " ", out_len - strlen(out) - 1);
  }
  strncat(out, last, out_len - strlen(out) - 1);
}

/* Expected words come from an independent BIP39 encoder over libwally's
 * English list: the last word keeps its top 11 - n/3 bits and gains the
 * checksum. */
static void test_complete_last_word(void) {
  TEST("bip39_filter_complete_last_word: keeps the entropy bits, fixes the "
       "checksum");

  static const struct {
    const char *word;
    int before;
    const char *last;
    const char *want;
  } repeats[] = {
      {"abandon", 11, "abandon", "about"}, {"abandon", 23, "abandon", "art"},
      {"abandon", 11, "zoo", "wrap"},      {"abandon", 14, "zoo", "word"},
      {"zoo", 17, "abandon", "advice"},    {"zoo", 20, "zoo", "veteran"},
      {"abandon", 11, "xyzzy", "about"},
  };
  static const struct {
    const char *mnemonic;
    const char *want;
  } phrases[] = {
      {"legal winner thank year wave sausage worth useful legal winner thank "
       "abandon",
       "about"},
      {"legal winner thank year wave sausage worth useful legal winner thank "
       "yellow",
       "yellow"},
  };

  char words[24][16];
  char mnemonic[24 * 16];
  for (size_t i = 0; i < sizeof(repeats) / sizeof(repeats[0]); i++) {
    repeat(mnemonic, sizeof(mnemonic), repeats[i].word, repeats[i].before,
           repeats[i].last);
    fill_words(words, mnemonic);
    int n = repeats[i].before + 1;
    if (!bip39_filter_complete_last_word(words, n) ||
        strcmp(words[n - 1], repeats[i].want) != 0) {
      printf("(%d x %s + %s) ", repeats[i].before, repeats[i].word,
             repeats[i].last);
      FAIL("wrong last word");
      return;
    }
  }
  for (size_t i = 0; i < sizeof(phrases) / sizeof(phrases[0]); i++) {
    fill_words(words, phrases[i].mnemonic);
    if (!bip39_filter_complete_last_word(words, 12) ||
        strcmp(words[11], phrases[i].want) != 0) {
      FAIL(phrases[i].mnemonic);
      return;
    }
  }
  PASS();
}

static void test_complete_last_word_refuses(void) {
  TEST("bip39_filter_complete_last_word: refuses unknown words and counts");

  char words[24][16];
  char mnemonic[24 * 16];
  repeat(mnemonic, sizeof(mnemonic), "abandon", 11, "abandon");
  fill_words(words, mnemonic);
  snprintf(words[3], sizeof(words[3]), "xyzzy");
  bool unknown = bip39_filter_complete_last_word(words, 12);
  bool kept = strcmp(words[11], "abandon") == 0;
  fill_words(words, mnemonic);
  if (unknown || !kept)
    FAIL("an unknown word before the last should refuse and change nothing");
  else if (bip39_filter_complete_last_word(words, 13) ||
           bip39_filter_complete_last_word(words, 9) ||
           bip39_filter_complete_last_word(words, 27))
    FAIL("word counts BIP39 lacks should refuse");
  else
    PASS();
}

/* Every valid last word is its own completion, so the list and the
 * completion pack the words the same way. */
static void test_valid_last_words_agree(void) {
  TEST("bip39_filter_get_valid_last_words: 2^(11 - n/3) words, each its own "
       "completion");

  static const struct {
    int count;
    int expected;
    const char *known;
  } cases[] = {{12, 128, "about"}, {24, 8, "art"}};
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    char words[24][16];
    char mnemonic[24 * 16];
    repeat(mnemonic, sizeof(mnemonic), "abandon", cases[c].count - 1,
           "abandon");
    fill_words(words, mnemonic);
    const char *valid[128];
    int n =
        bip39_filter_get_valid_last_words(words, cases[c].count, valid, 128);
    if (n != cases[c].expected) {
      FAIL("wrong number of valid last words");
      return;
    }
    bool known = false;
    for (int i = 0; i < n; i++) {
      known = known || strcmp(valid[i], cases[c].known) == 0;
      snprintf(words[cases[c].count - 1], 16, "%s", valid[i]);
      if (!bip39_filter_complete_last_word(words, cases[c].count) ||
          strcmp(words[cases[c].count - 1], valid[i]) != 0) {
        FAIL("a valid last word did not complete to itself");
        return;
      }
    }
    if (!known) {
      FAIL("the known vector's last word is missing");
      return;
    }
  }
  PASS();
}

/* Expected mnemonics from Python's hashlib and an independent BIP39 encoder. */
static void test_dice_mnemonic(void) {
  TEST("dice_mnemonic_from_rolls: SHA-256 of the digits as BIP39 entropy");

  static const struct {
    const char *rolls;
    int words;
    const char *want;
  } vectors[] = {
      {"11111111111111111111111111111111111111111111111111", 12,
       "diet glad hat rural panther lawsuit act drop gallery urge where fit"},
      {"11111111111111111111111111111111111111111111111111111111111111111111"
       "1111111111111111111111111111111",
       24,
       "wheel erase puppy pistol chapter accuse carpet drop quote final attend "
       "near scrap satisfy limit style crunch person south inspire lunch "
       "meadow enact tattoo"},
      {"12345612345612345612345612345612345612345612345612345612", 12,
       "chest spatial into brick once toast dog gallery battle flee stem "
       "miracle"},
      {"66666666666666666666666666666666666666666666666666666666666666666666"
       "6666666666666666666666666666666",
       24,
       "leave symbol nuclear chase dentist letter tape program illegal vague "
       "suggest wife copy source soup jacket fee eager loyal zoo keep brisk "
       "dynamic cradle"},
      {"31415326535231332324626433232135622241311633333151652263143445323612"
       "1646622626233262263422534211166",
       24,
       "goat lyrics ripple sunset gasp pair nothing advance shadow follow cave "
       "chief fade useful park manual whisper brick face medal cannon fragile "
       "feature unknown"},
  };
  for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    char *mnemonic = NULL;
    bool ok =
        dice_mnemonic_from_rolls(vectors[i].rolls, strlen(vectors[i].rolls),
                                 vectors[i].words, &mnemonic) &&
        strcmp(mnemonic, vectors[i].want) == 0;
    SECURE_FREE_STRING(mnemonic);
    if (!ok) {
      FAIL(vectors[i].want);
      return;
    }
  }
  char *mnemonic = NULL;
  if (dice_mnemonic_from_rolls("123", 3, 18, &mnemonic) || mnemonic ||
      dice_mnemonic_from_rolls("", 0, 12, &mnemonic) || mnemonic)
    FAIL("an unsupported word count or no rolls should refuse");
  else
    PASS();
}

int main(void) {
  if (wally_init(0) != WALLY_OK || !bip39_filter_init()) {
    printf("ABORT: wally_init or bip39_filter_init failed\n");
    return 1;
  }

  printf("\n=== mnemonic word tests ===\n\n");
  test_complete_last_word();
  test_complete_last_word_refuses();
  test_valid_last_words_agree();
  test_dice_mnemonic();

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  wally_cleanup(0);
  return tests_failed ? 1 : 0;
}
