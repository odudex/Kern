#include "descriptor_text.h"
#include "descriptor_checksum.h"
#include <stdlib.h>
#include <string.h>

static bool is_base58_char(char c) {
  return (c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') ||
         (c >= 'J' && c <= 'N') || (c >= 'P' && c <= 'Z') ||
         (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z');
}

char *descriptor_to_unambiguous(const char *descriptor) {
  if (!descriptor)
    return NULL;

  size_t desc_len = strlen(descriptor);

  // Strip checksum if present (#xxxxxxxx)
  size_t content_len = desc_len;
  if (desc_len > 9 && descriptor[desc_len - 9] == '#')
    content_len = desc_len - 9;

  // Count keys needing modification
  size_t modifications_needed = 0;
  const char *search = descriptor;
  const char *content_end = descriptor + content_len;

  while ((search = strstr(search, "pub")) != NULL && search < content_end) {
    if (search > descriptor && (*(search - 1) == 'x' || *(search - 1) == 't')) {
      const char *key_end = search + 3;
      while (key_end < content_end && is_base58_char(*key_end))
        key_end++;

      if (key_end >= content_end || *key_end != '/')
        modifications_needed++;
    }
    search += 3;
  }

  if (modifications_needed == 0)
    return NULL;

  /* The rewrite drops the checksum, which only libwally would otherwise
   * check: verify it here, against the text as written, so a transcription
   * error is still caught. On a mismatch the original goes to libwally and
   * fails to parse. */
  if (content_len < desc_len &&
      !descriptor_checksum_matches(descriptor, content_len,
                                   descriptor + content_len + 1))
    return NULL;

  size_t new_len = content_len + (modifications_needed * 8) + 1;
  char *result = malloc(new_len);
  if (!result)
    return NULL;

  const char *src = descriptor;
  char *dst = result;

  while (src < content_end) {
    if ((src[0] == 'x' || src[0] == 't') && src + 3 < content_end &&
        strncmp(src + 1, "pub", 3) == 0) {
      *dst++ = *src++;
      *dst++ = *src++;
      *dst++ = *src++;
      *dst++ = *src++;

      while (src < content_end && is_base58_char(*src))
        *dst++ = *src++;

      if (src >= content_end || *src != '/') {
        memcpy(dst, "/<0;1>/*", 8);
        dst += 8;
      }
    } else {
      *dst++ = *src++;
    }
  }
  *dst = '\0';

  return result;
}
