#ifndef UTF8_H
#define UTF8_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Strict UTF-8 check: rejects overlong forms, surrogates, code points above
// U+10FFFF and truncated sequences. is_ascii (optional) is set true when every
// byte is below 0x80.
bool utf8_is_valid(const uint8_t *s, size_t len, bool *is_ascii);

#endif
