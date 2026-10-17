#ifndef DESCRIPTOR_TEXT_H
#define DESCRIPTOR_TEXT_H

#include "../utils/attributes.h"

/* Append a <0;1> receive/change step and a wildcard to every xpub/tpub
 * written without a derivation, making the descriptor's branches explicit. A
 * trailing checksum is verified against the text as written and then dropped,
 * since the rewrite invalidates it. Returns a malloc'd string, or NULL when
 * nothing needs changing or the checksum does not match (the caller then passes
 * the original on, and a bad checksum fails to parse). */
KERN_WARN_UNUSED_RESULT char *descriptor_to_unambiguous(const char *descriptor);

#endif // DESCRIPTOR_TEXT_H
