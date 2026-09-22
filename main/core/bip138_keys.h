#ifndef BIP138_KEYS_H
#define BIP138_KEYS_H

#include "../utils/attributes.h"
#include <bip138.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BIP138_KEYS_MAX BIP138_MAX_KEYS
#define BIP138_KEYS_MAX_DEPTH 10

/* Key origin of a descriptor key; depth 0 when the key has none. */
typedef struct {
  uint32_t child[BIP138_KEYS_MAX_DEPTH];
  uint8_t depth;
} bip138_key_origin;

/* BIP138 recipient key of one descriptor key expression: the x-only root key
 * of an xpub that carries a trailing derivation (fixed, wildcard or
 * multipath). Bare xpubs, private keys and literal pubkeys yield false.
 * Exposed for the BIP's key-type vectors; the firmware extracts keys through
 * bip138_keys_from_descriptor. */
KERN_WARN_UNUSED_RESULT bool bip138_key_from_expression(const char *expr,
                                                        uint8_t xonly_out[32]);

/* Distinct recipient keys of a descriptor, with each key's origin path when
 * origins_out is given. Fails when no key qualifies or more than max_keys do.
 */
KERN_WARN_UNUSED_RESULT bool
bip138_keys_from_descriptor(const char *descriptor, uint32_t wally_network,
                            uint8_t *keys_out, bip138_key_origin *origins_out,
                            size_t max_keys, size_t *count_out);

#endif // BIP138_KEYS_H
