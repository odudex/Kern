#ifndef ADDRESS_MATCH_H
#define ADDRESS_MATCH_H

#include "../utils/attributes.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ss_whitelist.h"

struct wally_descriptor;

/* Longest scriptPubKey an address decodes to (a 40-byte witness program). */
#define ADDRESS_MATCH_SPK_MAX 42

/* Decode `address` into the scriptPubKey it pays on the given network:
 * bech32/bech32m in either all-lower or all-upper case, or base58check.
 * Matching is done on these bytes, never on the text: base58 is
 * case-sensitive, so a case variant that passes the checksum pays someone
 * else. */
KERN_WARN_UNUSED_RESULT bool address_match_decode(const char *address,
                                                  bool is_testnet, uint8_t *spk,
                                                  size_t spk_cap,
                                                  size_t *spk_len);

typedef struct {
  uint32_t chain; /* 0 receive, 1 change */
  uint32_t index;
} address_match_t;

/* Search receive then change addresses [start, limit) of a single-sig account
 * for `spk`. */
KERN_WARN_UNUSED_RESULT bool
address_match_singlesig(ss_script_type_t script, uint32_t account,
                        bool is_testnet, const uint8_t *spk, size_t spk_len,
                        uint32_t start, uint32_t limit, address_match_t *out);

/* Same for a descriptor with `num_paths` multipath branches. A single-path
 * descriptor has no change branch, so only its receive addresses are
 * searched. */
KERN_WARN_UNUSED_RESULT bool
address_match_descriptor(const struct wally_descriptor *desc, size_t num_paths,
                         const uint8_t *spk, size_t spk_len, uint32_t start,
                         uint32_t limit, address_match_t *out);

#endif // ADDRESS_MATCH_H
