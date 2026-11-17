#ifndef MUSIG_PSBT_H
#define MUSIG_PSBT_H

#include "../utils/attributes.h"
#include <bip_nonces_cache.h>
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

/* One of our MuSig2 signatures (ENCODING.md, Signing, MuSig2): an input and the
 * BIP-373 key `participant | aggregate [| leaf_hash]`, the participant being
 * our key. The tr() internal musig() signs the key path, a leaf musig() the
 * leaf script it is pushed in (musig_leaves.h). */
typedef struct {
  size_t input_index;
  const registry_entry_t *entry;
  uint32_t key_index;
  uint32_t multi_index;
  uint32_t child_num;
  /* the nonce cache key expression index of the musig() */
  uint32_t key_expression_index;
  unsigned char participant[BNC_PUBLIC_KEY_LEN];
  /* the aggregate of its BIP-373 key, as Bitcoin Core and Ledger key it: the
   * Taproot output key on the key path, the key the leaf pushes on a leaf,
   * never the KeyAgg key of PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS */
  unsigned char aggregate[BNC_PUBLIC_KEY_LEN];
  uint32_t path[MAX_KEYPATH_TOTAL_DEPTH];
  size_t path_len;
  bool has_leaf_hash;
  unsigned char leaf_hash[BNC_HASH_LEN];
  /* the input's TAP_LEAF_SCRIPT entry of the leaf, when it has one */
  size_t leaf_item;
} musig_slot_t;

/* What the PSBT asks of our MuSig2 signatures, in increasing precedence. */
typedef enum {
  /* no MuSig2 signature of ours */
  MUSIG_STEP_NONE,
  /* our public nonces are in, another participant's is missing */
  MUSIG_STEP_NOTHING,
  /* round 2: the partial signature of each one with every participant's
   * public nonce */
  MUSIG_STEP_PARTIAL_SIGS,
  /* round 1: the public nonce of each one, and no signature of any kind */
  MUSIG_STEP_PUB_NONCES,
  /* PSBT_GLOBAL_NONCE_CACHE_SESSION: the partial signature of each one in one
   * round, from the cached session */
  MUSIG_STEP_CACHED,
} musig_step_t;

typedef struct {
  musig_step_t step;
  musig_slot_t *slots;
  size_t num_slots;
  /* CACHED: the session the PSBT names; otherwise the two-round session the
   * signer derives from the descriptors of the slots */
  uint8_t session_id[BNC_SESSION_ID_LEN];
  uint8_t session_ref[BNC_SESSION_REF_LEN];
} musig_plan_t;

typedef enum {
  MUSIG_PSBT_OK,
  /* a session missing, consumed or mismatched: ERROR 0x0D */
  MUSIG_PSBT_ERR_SESSION,
  /* MuSig2 data the signer cannot sign with */
  MUSIG_PSBT_ERR_INVALID,
  /* our public nonces are in and nothing else of ours is to sign: waiting for
   * another participant's nonce */
  MUSIG_PSBT_ERR_NOTHING,
  MUSIG_PSBT_ERR_INTERNAL,
} musig_psbt_result_t;

/* Our MuSig2 signatures, on the inputs `signable` clears (every input when
 * NULL), and the step the PSBT asks. Free with musig_plan_free(). */
KERN_WARN_UNUSED_RESULT musig_psbt_result_t
musig_psbt_plan(const struct wally_psbt *psbt, const bool *signable,
                musig_plan_t *plan_out);

void musig_plan_free(musig_plan_t *plan);

/* Checks, without taking it, that the session the plan signs from is held and
 * gives the public nonces the PSBT carries: run before asking the user. */
KERN_WARN_UNUSED_RESULT musig_psbt_result_t
musig_psbt_check_session(struct wally_psbt *psbt, const musig_plan_t *plan);

/* Runs the plan's step: round 1 stores a new session then sets our
 * PSBT_IN_MUSIG2_PUB_NONCE on every slot; round 2 and CACHED take the session,
 * deleted durably before any signature is written, then set our
 * PSBT_IN_MUSIG2_PARTIAL_SIG on every slot they sign, all or none. Writes the
 * number of entries set to *added_out. */
KERN_WARN_UNUSED_RESULT musig_psbt_result_t musig_psbt_sign(
    struct wally_psbt *psbt, const musig_plan_t *plan, size_t *added_out);

/* Checks a PSBT to sign before the user is asked: the session its MuSig2
 * signatures need is held and gives the nonces it carries, and it asks
 * something of us. A PSBT that does not parse is left to the review. */
KERN_WARN_UNUSED_RESULT musig_psbt_result_t musig_psbt_check_request(
    const uint8_t *psbt_bytes, size_t psbt_len, bool is_testnet);

/* True when `path` derives one of our participant keys of a musig() of `desc`:
 * the participant's own path, followed by the steps its key expression adds
 * when it has any, at the multipath index and child number `path` ends
 * with. */
KERN_WARN_UNUSED_RESULT bool
musig_psbt_is_participant_path(const struct wally_descriptor *desc,
                               const uint32_t *path, size_t path_len);

/* True when `participant` is the participant key of one of our MuSig2
 * signatures on input `input_index`. */
KERN_WARN_UNUSED_RESULT bool
musig_psbt_is_own_participant(const struct wally_psbt *psbt, size_t input_index,
                              const unsigned char *participant);

#endif // MUSIG_PSBT_H
