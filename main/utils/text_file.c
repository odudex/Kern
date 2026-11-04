#include "text_file.h"
#include "secure_mem.h"
#include <stdlib.h>
#include <string.h>

bool text_is_descriptor_prefix(const char *data) {
  return strncmp(data, "wsh(", 4) == 0 || strncmp(data, "sh(", 3) == 0 ||
         strncmp(data, "wpkh(", 5) == 0 || strncmp(data, "pkh(", 4) == 0 ||
         strncmp(data, "tr(", 3) == 0;
}

// Normalizes a text file's contents into the single string the layer-2
// detectors expect from a QR: strips a UTF-8 BOM, drops comment and blank
// lines (a comment's first non-whitespace character is '#'; a descriptor's
// "#checksum" suffix is mid-line and so survives), trims each line, then
// rejoins. Editor-wrapped base64 PSBTs and descriptors are joined without a
// separator; anything else (e.g. a word-per-line mnemonic backup) gets a
// single space between lines. BlueWallet "Policy:" files keep their layout —
// that parser reads the lines itself. Returns a heap string, or NULL when no
// content line exists.
char *text_file_normalize(const uint8_t *data, size_t len) {
  const char *text = (const char *)data;
  if (len >= 3 && memcmp(text, "\xEF\xBB\xBF", 3) == 0) {
    text += 3;
    len -= 3;
  }

  char *out = malloc(len + 1);
  if (!out)
    return NULL;

  size_t n = 0;
  const char *sep = NULL;
  size_t i = 0;
  while (i < len) {
    size_t s = i;
    while (i < len && text[i] != '\n')
      i++;
    size_t e = i;
    if (i < len)
      i++; // step past '\n'

    while (s < e && (text[s] == ' ' || text[s] == '\t' || text[s] == '\r'))
      s++;
    while (e > s &&
           (text[e - 1] == ' ' || text[e - 1] == '\t' || text[e - 1] == '\r'))
      e--;
    if (s == e || text[s] == '#')
      continue; // blank or comment line

    if (!sep) { // first content line decides how the rest are joined
      sep = (e - s >= 6 && (strncmp(text + s, "cHNidP", 6) == 0 ||
                            text_is_descriptor_prefix(text + s)))
                ? ""
                : " ";
    } else if (*sep) {
      out[n++] = ' ';
    }
    memcpy(out + n, text + s, e - s);
    n += e - s;
  }
  out[n] = '\0';

  if (n == 0 || strstr(out, "Policy:")) {
    // BlueWallet files are re-emitted whole; an all-comment/blank file is
    // reported as having no content.
    SECURE_FREE_BUFFER(out, n);
    if (n == 0)
      return NULL;
    out = malloc(len + 1);
    if (!out)
      return NULL;
    memcpy(out, text, len);
    out[len] = '\0';
  }
  return out;
}
