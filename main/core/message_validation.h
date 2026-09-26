#ifndef MESSAGE_VALIDATION_H
#define MESSAGE_VALIDATION_H

#include <stdbool.h>
#include <stddef.h>

/* The review font supports printable ASCII. Preserve line endings exactly,
 * allowing LF and CRLF, but reject bytes that would be hidden or ambiguous. */
static inline bool message_text_is_displayable(const unsigned char *message,
                                               size_t len) {
  if (!message)
    return false;
  for (size_t i = 0; i < len; ++i) {
    unsigned char c = message[i];
    if ((c >= 0x20 && c <= 0x7e) || c == '\n')
      continue;
    if (c == '\r' && i + 1 < len && message[i + 1] == '\n') {
      ++i;
      continue;
    }
    return false;
  }
  return true;
}

#endif // MESSAGE_VALIDATION_H
