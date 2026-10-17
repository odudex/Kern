#include "../utils/attributes.h"
#pragma once

#include <stdbool.h>
#include <stddef.h>

struct wally_descriptor;

KERN_WARN_UNUSED_RESULT bool
descriptor_string_from_descriptor(const struct wally_descriptor *desc,
                                  char **output);
KERN_WARN_UNUSED_RESULT bool
descriptor_checksum_from_descriptor(const struct wally_descriptor *desc,
                                    char out[9]);

/* True when `cs` is the BIP-380 checksum of the first `len` characters of
 * `body`, taken literally (no 'h' normalisation). */
KERN_WARN_UNUSED_RESULT bool
descriptor_checksum_matches(const char *body, size_t len, const char cs[8]);

/* True if `s` contains an uppercase 'H' as a hardened-derivation marker
 * (i.e. one or more digits at a path-component boundary — after '/', '<', or
 * ';' — followed by 'H'). libwally accepts 'H', 'h', and '\'' interchangeably,
 * but the canonical form used for dedup normalizes only 'h' and '\'', so
 * descriptors using 'H' must be rejected at the input boundary. */
KERN_WARN_UNUSED_RESULT bool
descriptor_text_has_uppercase_hardened(const char *s);
