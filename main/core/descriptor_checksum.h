#pragma once

#include <stdbool.h>

struct wally_descriptor;

bool descriptor_string_from_descriptor(const struct wally_descriptor *desc,
                                       char **output);
bool descriptor_checksum_from_descriptor(const struct wally_descriptor *desc,
                                         char out[9]);
bool wallet_get_descriptor_string(char **output);
bool wallet_get_descriptor_checksum(char **output);
