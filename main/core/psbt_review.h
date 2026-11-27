#ifndef PSBT_REVIEW_H
#define PSBT_REVIEW_H

#include "../utils/attributes.h"
#include "psbt.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Per-input and per-output ownership classification, taken once per review and
 * shared by the sign-policy gate and the review model builder. */
typedef struct {
  input_ownership_t *inputs;
  output_ownership_t *outputs;
  size_t num_inputs;
  size_t num_outputs;
} psbt_owners_t;

typedef enum {
  PSBT_OUTPUT_SELF_TRANSFER,
  PSBT_OUTPUT_CHANGE,
  /* fp + derive verifies the spk on a non-standard path — factually ours */
  PSBT_OUTPUT_OWNED_UNSAFE,
  /* fp matches but derive doesn't reach the spk — harness state, not
   * provably ours */
  PSBT_OUTPUT_EXPECTED_OWNED,
  PSBT_OUTPUT_SPEND,
} psbt_output_type_t;

typedef struct {
  size_t index;
  psbt_output_type_t type;
  uint64_t value;
  char *address;
  uint32_t address_index;
  bool change_chain; /* owned output on its wallet's change chain */
  bool is_dust;      /* below the relay dust threshold for its script type */
  psbt_destination_kind_t dest_kind;
  size_t script_len;
  char policy[64]; /* wallet of an owned output, as for inputs */
  char path[80];   /* populated for OWNED_UNSAFE / EXPECTED_OWNED */
} psbt_review_output_t;

typedef struct {
  size_t index;
  psbt_ownership_t ownership;
  uint64_t value;
  char *address; /* heap-allocated, may be NULL if spk can't be read */
  psbt_destination_kind_t dest_kind;
  size_t script_len;
  /* Human-readable policy this input is signed under, e.g. "Native SegWit @
   * account 0" for whitelisted singlesig or the registered descriptor's label
   * / id for registry matches. Empty for inputs that aren't OWNED_SAFE. */
  char policy[64];
  char path[80]; /* populated for OWNED_UNSAFE / EXPECTED_OWNED */
  claim_t claim; /* valid when ownership is OWNED_SAFE */
} psbt_review_input_t;

/* Complete UI-free summary of a PSBT for transaction review rendering. */
typedef struct {
  psbt_review_input_t *inputs;
  size_t num_inputs;
  size_t external_inputs;
  psbt_review_output_t *outputs;
  size_t num_outputs;
  uint64_t total_input;
  uint64_t total_output;
  uint64_t fee;
  uint32_t locktime;
  bool signals_rbf;
  size_t dust_count;
  size_t first_dust;
  uint64_t first_dust_value;
  psbt_amount_audit_t amount_audit;
  bool fee_trusted;
} psbt_review_t;

/* Classify every input and output of `psbt`. On success caller must release
 * with psbt_review_free_owners(). */
KERN_WARN_UNUSED_RESULT bool
psbt_review_classify_owners(const struct wally_psbt *psbt, bool is_testnet,
                            psbt_owners_t *out);

void psbt_review_free_owners(psbt_owners_t *owners);

/* Format a human-readable wallet label for an OWNED_SAFE claim. */
void psbt_review_format_claim_policy(const claim_t *claim, char *out,
                                     size_t out_size);

/* Classify a single output as change, self-transfer, owned-unsafe,
 * expected-owned, or spend. Change requires an OWNED_SAFE output on its
 * wallet's change chain whose wallet policy matches at least one OWNED_SAFE
 * input; all other OWNED_SAFE outputs are classified as self-transfer. */
void psbt_review_classify_output(const psbt_review_input_t *inputs,
                                 size_t num_inputs,
                                 output_ownership_t ownership,
                                 psbt_review_output_t *out);

/* Collect all transaction details needed by the review screen into `out`.
 * On success caller must release with psbt_review_free(). */
KERN_WARN_UNUSED_RESULT bool psbt_review_collect(const struct wally_psbt *psbt,
                                                 bool is_testnet,
                                                 const psbt_owners_t *owners,
                                                 psbt_review_t *out);

void psbt_review_free(psbt_review_t *data);

#endif // PSBT_REVIEW_H
