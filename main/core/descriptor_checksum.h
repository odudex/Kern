#pragma once

#include <stdbool.h>

struct wally_descriptor;

bool descriptor_string_from_descriptor(const struct wally_descriptor *desc,
                                       char **output);
bool descriptor_checksum_from_descriptor(const struct wally_descriptor *desc,
                                         char out[9]);
bool wallet_get_descriptor_string(char **output);
bool wallet_get_descriptor_checksum(char **output);

/* True if `s` contains an uppercase 'H' as a hardened-derivation marker
 * (i.e. one or more digits at a path-component boundary — after '/', '<', or
 * ';' — followed by 'H'). libwally accepts 'H', 'h', and '\'' interchangeably,
 * but the canonical form used for dedup normalizes only 'h' and '\'', so
 * descriptors using 'H' must be rejected at the input boundary. */
bool descriptor_text_has_uppercase_hardened(const char *s);
