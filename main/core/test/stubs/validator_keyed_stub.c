/* Stand-in for descriptor_validate_keyed() in tests that link registry.c but
 * not the validator: every descriptor counts as validated with key 0. */

#include "core/descriptor_validator.h"

descriptor_validation_result_t
descriptor_validate_keyed(const char *descriptor_str, int *key_index_out) {
  if (!descriptor_str)
    return VALIDATION_INTERNAL_ERROR;
  if (key_index_out)
    *key_index_out = 0;
  return VALIDATION_SUCCESS;
}
