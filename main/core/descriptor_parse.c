#include "wallet.h"
#include <wally_descriptor.h>

/* Kern relies on the pinned fork rejecting non-sane miniscript unless this
 * flag is passed; a libwally without it may accept such scripts silently. */
#ifndef WALLY_MINISCRIPT_ALLOW_NON_SANE
#error "libwally lacks default non-sane miniscript rejection"
#endif

int wallet_descriptor_parse(const char *descriptor,
                            const struct wally_map *vars_in, uint32_t network,
                            struct wally_descriptor **output) {
  uint32_t flags = KERN_DESCRIPTOR_MAX_DEPTH << WALLY_MINISCRIPT_DEPTH_SHIFT;
  return wally_descriptor_parse(descriptor, vars_in, network, flags, output);
}
