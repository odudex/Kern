#ifndef DESCRIPTOR_BRANCH_H
#define DESCRIPTOR_BRANCH_H

#include "../utils/attributes.h"
#include <stdint.h>

struct wally_descriptor;

/* `desc` at multipath group `multi_index` as a single-path descriptor whose
 * extended keys have their unhardened steps before the wildcard already
 * derived, so generating child n costs one BIP32 step per key instead of the
 * whole child path. NULL when no key has such steps, or when the copy does
 * not pay what `desc` pays at child 0. Free with wally_descriptor_free(). */
KERN_WARN_UNUSED_RESULT struct wally_descriptor *
descriptor_branch_alloc(const struct wally_descriptor *desc,
                        uint32_t multi_index);

#endif // DESCRIPTOR_BRANCH_H
