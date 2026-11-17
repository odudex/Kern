#ifndef MUSIG_PSBT_H
#define MUSIG_PSBT_H

#include "../utils/attributes.h"
#include <stdbool.h>
#include <stddef.h>

#include "psbt.h"

/* Claims a taproot script for the registered descriptor with a musig() key
 * holding one of our participant keys that generates it. The multipath index
 * and child number are the last two steps of one of the PSBT_*_TAP_BIP32_
 * DERIVATION origins in `tap_paths`: the aggregate key's when the musig() is
 * followed by a path (aggregate then derive), a participant's when its
 * participants are (derive then aggregate). The descriptor, not the PSBT,
 * decides that the script is ours. */
KERN_WARN_UNUSED_RESULT bool musig_psbt_claim(const struct wally_map *tap_paths,
                                              const unsigned char *spk,
                                              size_t spk_len,
                                              claim_t *claim_out);

#endif // MUSIG_PSBT_H
