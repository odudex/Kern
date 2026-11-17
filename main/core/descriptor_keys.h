#ifndef DESCRIPTOR_KEYS_H
#define DESCRIPTOR_KEYS_H

#include "../utils/attributes.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <wally_descriptor.h>

/* A key of a descriptor: the key expression at `index`, or one participant of
 * the BIP-390 musig() expression at `index`. libwally gives a musig() one key
 * index and no key string of its own, so its keys are reached through the
 * participant. A musig() in a tapscript leaf is the key it was rewritten into
 * (musig_leaves.h), and its participants come from the expression it was
 * rewritten from. */
#define DESCRIPTOR_KEY_NOT_MUSIG SIZE_MAX

typedef struct {
  uint32_t index;
  /* DESCRIPTOR_KEY_NOT_MUSIG for a plain key expression */
  size_t participant;
} descriptor_key_ref_t;

KERN_WARN_UNUSED_RESULT bool
descriptor_key_is_musig(const struct wally_descriptor *desc, uint32_t index);

/* Number of participants of the musig() at `index`, 0 for a plain key. */
KERN_WARN_UNUSED_RESULT size_t descriptor_key_musig_participants(
    const struct wally_descriptor *desc, uint32_t index);

/* The first key whose origin fingerprint is `fingerprint`, a musig()
 * participant included, in key expression order. */
KERN_WARN_UNUSED_RESULT bool
descriptor_key_find(const struct wally_descriptor *desc,
                    const unsigned char *fingerprint,
                    descriptor_key_ref_t *ref_out);

/* True when the key expression at `index`, or one of its musig() participants,
 * has origin fingerprint `fingerprint`. */
KERN_WARN_UNUSED_RESULT bool
descriptor_key_holds_fingerprint(const struct wally_descriptor *desc,
                                 uint32_t index,
                                 const unsigned char *fingerprint);

KERN_WARN_UNUSED_RESULT bool
descriptor_key_origin_fingerprint(const struct wally_descriptor *desc,
                                  descriptor_key_ref_t ref,
                                  unsigned char *fingerprint_out);

/* The origin path without the leading "m/", as a wally string the caller frees
 * with wally_free_string(). NULL when the key has none or on failure. */
KERN_WARN_UNUSED_RESULT char *
descriptor_key_origin_path_alloc(const struct wally_descriptor *desc,
                                 descriptor_key_ref_t ref);

/* The key expression text, as a wally string freed with wally_free_string(). */
KERN_WARN_UNUSED_RESULT char *
descriptor_key_string_alloc(const struct wally_descriptor *desc,
                            descriptor_key_ref_t ref);

/* The derivation steps after key `ref` at tuple position `multi_index` and
 * child `child_num`: a participant's own path, else the key expression's, a
 * musig()'s path after its participants. None for a key without a path. */
KERN_WARN_UNUSED_RESULT bool
descriptor_key_child_steps(const struct wally_descriptor *desc,
                           descriptor_key_ref_t ref, uint32_t multi_index,
                           uint32_t child_num, uint32_t *steps,
                           size_t max_steps, size_t *steps_len);

#endif // DESCRIPTOR_KEYS_H
