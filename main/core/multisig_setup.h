#ifndef MULTISIG_SETUP_H
#define MULTISIG_SETUP_H

#include "../utils/attributes.h"

/* Convert a Coldcard-style multisig setup file (as exported by Coldcard,
 * Sparrow, BlueWallet or Nunchuk) into a sortedmulti() descriptor. Each key
 * takes the path of the nearest "Derivation:" line above it, unless the line
 * just before it is BlueWallet's "# derivation:" comment. SLIP-132
 * Ypub/Zpub and upub/vpub keys are re-encoded as xpub/tpub. Returns a malloc'd
 * string, or NULL if `text` is not such a file. */
KERN_WARN_UNUSED_RESULT char *multisig_setup_to_descriptor(const char *text);

#endif // MULTISIG_SETUP_H
