#include "utils/utf8.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "FAIL: %s\n", message);                                  \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static bool valid(const char *s, size_t len, bool *ascii) {
  return utf8_is_valid((const uint8_t *)s, len, ascii);
}

int main(void) {
  bool ascii = false;

  CHECK(valid("", 0, &ascii) && ascii, "empty is valid ascii");
  CHECK(valid("passphrase 123 !@#", 18, &ascii) && ascii, "plain ascii");
  CHECK(valid("caf\xC3\xA9", 5, &ascii) && !ascii, "2-byte sequence");
  CHECK(valid("\xE2\x82\xAC", 3, &ascii) && !ascii, "3-byte sequence");
  CHECK(valid("\xF0\x9F\x98\x80", 4, &ascii) && !ascii, "4-byte sequence");
  CHECK(valid("a\xC3\xA9z", 4, NULL), "NULL is_ascii accepted");

  CHECK(!valid("\xC0\x80", 2, NULL), "overlong 2-byte rejected");
  CHECK(!valid("\xE0\x80\x80", 3, NULL), "overlong 3-byte rejected");
  CHECK(!valid("\xF0\x80\x80\x80", 4, NULL), "overlong 4-byte rejected");
  CHECK(!valid("\xED\xA0\x80", 3, NULL), "surrogate rejected");
  CHECK(!valid("\xF4\x90\x80\x80", 4, NULL), "above U+10FFFF rejected");
  CHECK(!valid("\xC3", 1, NULL), "truncated 2-byte rejected");
  CHECK(!valid("\xE2\x82", 2, NULL), "truncated 3-byte rejected");
  CHECK(!valid("\xE2\x82\x41", 3, NULL), "bad continuation rejected");
  CHECK(!valid("\x80", 1, NULL), "stray continuation rejected");
  CHECK(!valid("\xFF", 1, NULL), "0xFF rejected");
  CHECK(!valid("\xC1\xBF", 2, NULL), "0xC1 lead rejected");
  CHECK(!valid("\xF5\x80\x80\x80", 4, NULL), "0xF5 lead rejected");

  if (failures) {
    fprintf(stderr, "%d failure(s)\n", failures);
    return 1;
  }
  printf("test_utf8: all tests passed\n");
  return 0;
}
