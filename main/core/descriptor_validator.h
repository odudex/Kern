#ifndef DESCRIPTOR_VALIDATOR_H
#define DESCRIPTOR_VALIDATOR_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
  VALIDATION_SUCCESS = 0,
  VALIDATION_FINGERPRINT_NOT_FOUND,
  VALIDATION_USER_DECLINED,
  VALIDATION_XPUB_MISMATCH,
  VALIDATION_PARSE_ERROR,
  VALIDATION_INTERNAL_ERROR,
} descriptor_validation_result_t;

typedef void (*validation_complete_cb)(descriptor_validation_result_t result,
                                       void *user_data);

// UI-agnostic confirmation callback: show message, call proceed() with result.
typedef void (*validation_confirm_cb)(const char *message,
                                      void (*proceed)(bool confirmed,
                                                      void *user_data));

// Validate descriptor against wallet key and load if valid.
// Checks fingerprint, derivation path attributes, and xpub match.
// If settings mismatch, uses confirm_cb to prompt (NULL = auto-decline).
// Calls callback with result (may be async if user confirmation needed).
void descriptor_validate_and_load(const char *descriptor_str,
                                  validation_complete_cb callback,
                                  validation_confirm_cb confirm_cb,
                                  void *user_data);

#endif // DESCRIPTOR_VALIDATOR_H
