#include "utf8.h"

bool utf8_is_valid(const uint8_t *s, size_t len, bool *is_ascii) {
  bool ascii = true;
  size_t i = 0;
  while (i < len) {
    uint8_t c = s[i];
    if (c < 0x80) {
      i++;
      continue;
    }
    ascii = false;
    size_t n;
    uint32_t cp;
    if (c >= 0xC2 && c <= 0xDF) {
      n = 1;
      cp = c & 0x1F;
    } else if (c >= 0xE0 && c <= 0xEF) {
      n = 2;
      cp = c & 0x0F;
    } else if (c >= 0xF0 && c <= 0xF4) {
      n = 3;
      cp = c & 0x07;
    } else {
      return false;
    }
    if (len - i <= n)
      return false;
    for (size_t k = 1; k <= n; k++) {
      uint8_t cc = s[i + k];
      if ((cc & 0xC0) != 0x80)
        return false;
      cp = (cp << 6) | (cc & 0x3F);
    }
    if ((n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000) ||
        (cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF)
      return false;
    i += n + 1;
  }
  if (is_ascii)
    *is_ascii = ascii;
  return true;
}
