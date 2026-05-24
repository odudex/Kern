#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_bip32.h>

bool key_get_derived_key(const char *path, struct ext_key **key_out) {
  (void)path;
  (void)key_out;
  return false;
}

bool key_get_derived_key_components(const uint32_t *path, size_t path_depth,
                                    struct ext_key **key_out) {
  (void)path;
  (void)path_depth;
  (void)key_out;
  return false;
}
