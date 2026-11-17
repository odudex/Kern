#ifndef MUSIG_LEAVES_H
#define MUSIG_LEAVES_H

#include "../utils/attributes.h"
#include <stdint.h>

/* libwally parses a BIP-390 musig() as a tr() internal key only. A musig() in a
 * tapscript leaf is rewritten into the key it stands for, which libwally
 * parses as any other: the BIP-328 synthetic xpub of the aggregate, keeping
 * the path, when a path follows the musig(); the x-only aggregate when none
 * does. The rewrite is remembered, so the participants stay known
 * (descriptor_keys.h) and the descriptor text can be restored.
 *
 * Participants with their own derivation make a different aggregate at every
 * index, which no single key expression stands for: such a leaf musig() is
 * refused. */

/* The descriptor with its leaf musig() rewritten, without checksum when it
 * had one, which is checked first; an unchanged copy when it has no leaf
 * musig(). NULL when a leaf musig() or the checksum is invalid. `network` is a
 * WALLY_NETWORK_*. The caller frees it. */
KERN_WARN_UNUSED_RESULT char *musig_leaves_rewrite_alloc(const char *descriptor,
                                                         uint32_t network);

/* The descriptor with every rewritten key back to its musig() expression, its
 * checksum recomputed when it carries one. The caller frees it. */
KERN_WARN_UNUSED_RESULT char *
musig_leaves_restore_alloc(const char *descriptor);

/* The musig(...) expression a rewritten key stands for, or NULL. `key` is the
 * key without origin or derivation path. */
KERN_WARN_UNUSED_RESULT const char *musig_leaves_expression(const char *key);

#endif // MUSIG_LEAVES_H
