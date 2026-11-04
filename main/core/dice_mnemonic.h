#ifndef DICE_MNEMONIC_H
#define DICE_MNEMONIC_H

#include "../utils/attributes.h"
#include <stdbool.h>
#include <stddef.h>

/* The mnemonic of d6 rolls typed as digits: the SHA-256 of the digits, all 32
 * bytes for 24 words, the first 16 for 12. SENSITIVE: free *mnemonic_out with
 * SECURE_FREE_STRING(). */
KERN_WARN_UNUSED_RESULT bool dice_mnemonic_from_rolls(const char *rolls,
                                                      size_t rolls_len,
                                                      int word_count,
                                                      char **mnemonic_out);

#endif
