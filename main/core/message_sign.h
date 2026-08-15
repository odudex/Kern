#ifndef MESSAGE_SIGN_H
#define MESSAGE_SIGN_H

#include "../utils/attributes.h"
#include <stdbool.h>

typedef struct {
  char *derivation_path; // Full path: "m/84'/0'/0'/0/1"
  char *message;         // ASCII message text
} parsed_sign_message_t;

KERN_WARN_UNUSED_RESULT bool message_sign_parse(const char *content,
                                                parsed_sign_message_t *result);
void message_sign_free_parsed(parsed_sign_message_t *parsed);
KERN_WARN_UNUSED_RESULT bool message_sign_sign(const char *derivation_path,
                                               const char *message,
                                               char **signature_b64_out);
KERN_WARN_UNUSED_RESULT bool
message_sign_get_address(const char *derivation_path, bool is_testnet,
                         char **address_out);

#endif // MESSAGE_SIGN_H
