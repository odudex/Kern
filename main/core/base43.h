/*
 * Base43 encoding/decoding
 *
 * Uses the charset "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:".
 * This is a subset of QR code Alphanumeric mode, used by Krux for
 * efficient KEF-encrypted mnemonic QR codes.
 */

#ifndef BASE43_H
#define BASE43_H

#include "../utils/attributes.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Decode a base43 string to bytes.
 *
 * str / str_len  — input base43 string (not null-terminated required)
 * out / out_len  — receives heap-allocated decoded bytes (caller frees)
 *
 * Returns true on success, false on invalid character or allocation failure.
 */
KERN_WARN_UNUSED_RESULT bool base43_decode(const char *str, size_t str_len,
                                           uint8_t **out, size_t *out_len);

/*
 * Encode bytes to a base43 string.
 *
 * data / data_len — input binary data
 * out / out_len   — receives heap-allocated null-terminated base43 string
 *                   (out_len does NOT include the null terminator)
 *
 * Returns true on success, false on allocation failure.
 */
KERN_WARN_UNUSED_RESULT bool base43_encode(const uint8_t *data, size_t data_len,
                                           char **out, size_t *out_len);

#endif /* BASE43_H */
