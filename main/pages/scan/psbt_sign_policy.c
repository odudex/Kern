#include "psbt_sign_policy.h"

#include "../../core/psbt.h"
#include "../../core/settings.h"

#include <stdio.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_transaction.h>

#define EXTERNAL_INPUT_LIST_CAP 4

typedef struct {
  bool any_signable;
  bool any_input_external;
  bool signs_taproot;
  bool need_permissive;
  bool need_expected_owned;
  bool flagged_is_input;
  size_t flagged_index;
  char flagged_path[80];
  size_t external_inputs[EXTERNAL_INPUT_LIST_CAP];
  size_t external_count;
} sign_policy_review_t;

static void remember_flagged_path(sign_policy_review_t *review,
                                  psbt_ownership_t ownership, size_t index,
                                  bool is_input,
                                  const unsigned char *raw_keypath,
                                  size_t raw_keypath_len) {
  if (ownership == PSBT_OWNERSHIP_OWNED_UNSAFE &&
      (review->need_permissive || review->need_expected_owned))
    return;
  if (ownership == PSBT_OWNERSHIP_EXPECTED_OWNED && review->need_expected_owned)
    return;

  review->flagged_index = index;
  review->flagged_is_input = is_input;
  if (!psbt_format_keypath(raw_keypath, raw_keypath_len, review->flagged_path,
                           sizeof(review->flagged_path)))
    review->flagged_path[0] = '\0'; // the review renders without a path
}

static void scan_inputs(struct wally_psbt *psbt, bool is_testnet,
                        sign_policy_review_t *review) {
  size_t num_inputs = 0;
  if (wally_psbt_get_num_inputs(psbt, &num_inputs) != WALLY_OK)
    return;

  for (size_t i = 0; i < num_inputs; i++) {
    input_ownership_t own = psbt_classify_input(psbt, i, is_testnet);
    if (own.ownership != PSBT_OWNERSHIP_EXTERNAL &&
        psbt_input_is_taproot(psbt, i))
      review->signs_taproot = true;
    switch (own.ownership) {
    case PSBT_OWNERSHIP_OWNED_SAFE:
      review->any_signable = true;
      break;
    case PSBT_OWNERSHIP_OWNED_UNSAFE:
      review->any_signable = true;
      remember_flagged_path(review, own.ownership, i, true, own.raw_keypath,
                            own.raw_keypath_len);
      review->need_permissive = true;
      break;
    case PSBT_OWNERSHIP_EXPECTED_OWNED:
      review->any_signable = true;
      remember_flagged_path(review, own.ownership, i, true, own.raw_keypath,
                            own.raw_keypath_len);
      review->need_expected_owned = true;
      break;
    case PSBT_OWNERSHIP_EXTERNAL:
      review->any_input_external = true;
      if (review->external_count < EXTERNAL_INPUT_LIST_CAP)
        review->external_inputs[review->external_count] = i;
      review->external_count++;
      break;
    }
  }
}

static void scan_outputs(struct wally_psbt *psbt, bool is_testnet,
                         sign_policy_review_t *review) {
  size_t num_outputs = 0;
  if (wally_psbt_get_num_outputs(psbt, &num_outputs) != WALLY_OK)
    return;

  for (size_t i = 0; i < num_outputs; i++) {
    output_ownership_t own = psbt_classify_output(psbt, i, is_testnet);
    switch (own.ownership) {
    case PSBT_OWNERSHIP_OWNED_UNSAFE:
      remember_flagged_path(review, own.ownership, i, false, own.raw_keypath,
                            own.raw_keypath_len);
      review->need_permissive = true;
      break;
    case PSBT_OWNERSHIP_EXPECTED_OWNED:
      remember_flagged_path(review, own.ownership, i, false, own.raw_keypath,
                            own.raw_keypath_len);
      review->need_expected_owned = true;
      break;
    case PSBT_OWNERSHIP_OWNED_SAFE:
    case PSBT_OWNERSHIP_EXTERNAL:
      break;
    }
  }
}

static void show_cannot_sign(const char *message,
                             dialog_callback_t dismissed_cb) {
  dialog_show_info("Cannot sign PSBT", message, dismissed_cb, NULL,
                   DIALOG_STYLE_FULLSCREEN);
}

static char pending_reject_body[384];
static dialog_callback_t pending_dismissed_cb;
static void (*pending_load_cb)(void);

static void offer_descriptor_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed && pending_load_cb) {
    pending_load_cb();
    return;
  }
  show_cannot_sign(pending_reject_body, pending_dismissed_cb);
}

static bool reject_expected_owned(const sign_policy_review_t *review,
                                  dialog_callback_t dismissed_cb,
                                  void (*load_descriptor_cb)(void)) {
  if (!review->need_expected_owned || settings_get_expected_owned_signing())
    return false;

  snprintf(pending_reject_body, sizeof(pending_reject_body),
           "%s %zu's path %s matches this wallet's fingerprint but the script "
           "cannot be re-derived from it -- wallet bug or attacker-crafted "
           "input.\n"
           "To sign anyway: Enable 'Expected-owned signing' in Settings > "
           "Wallet. The device will then trust the PSBT's keypath without "
           "verification.",
           review->flagged_is_input ? "Input" : "Output", review->flagged_index,
           review->flagged_path[0] ? review->flagged_path : "(unknown)");

  if (!load_descriptor_cb) {
    show_cannot_sign(pending_reject_body, dismissed_cb);
    return true;
  }

  pending_dismissed_cb = dismissed_cb;
  pending_load_cb = load_descriptor_cb;

  char prompt[384];
  snprintf(prompt, sizeof(prompt),
           "%s %zu's path %s matches this wallet's fingerprint, but its "
           "script can't be rebuilt from a single key.\n"
           "Multisig and miniscript scripts can only be verified with the "
           "wallet descriptor.\n\n"
           "Load a descriptor now?",
           review->flagged_is_input ? "Input" : "Output", review->flagged_index,
           review->flagged_path[0] ? review->flagged_path : "(unknown)");
  dialog_show_confirm(prompt, offer_descriptor_cb, NULL,
                      DIALOG_STYLE_FULLSCREEN);
  return true;
}

static bool reject_permissive(const sign_policy_review_t *review,
                              dialog_callback_t dismissed_cb) {
  if (!review->need_permissive || settings_get_permissive_signing())
    return false;

  char body[384];
  snprintf(body, sizeof(body),
           "%s %zu's path %s is on a non-standard derivation. "
           "Enable 'Permissive signing' in Settings > Wallet to proceed.",
           review->flagged_is_input ? "Input" : "Output", review->flagged_index,
           review->flagged_path[0] ? review->flagged_path : "(unknown)");
  show_cannot_sign(body, dismissed_cb);
  return true;
}

/* Under NONE, SINGLE or ANYONECANPAY the signature keeps its validity while
 * the parts of the transaction it does not cover are rewritten, so the outputs
 * and fee the user is about to approve are not what gets mined. Nothing on the
 * review screen can be presented honestly, hence a refusal rather than a
 * warning. */
static bool reject_unsupported_sighash(const psbt_sighash_audit_t *audit,
                                       dialog_callback_t dismissed_cb) {
  if (!audit->unsupported)
    return false;

  char body[384];
  snprintf(body, sizeof(body),
           "Input %zu asks to be signed with SIGHASH_%s.\n\n"
           "Only ALL is supported: any other flag leaves part of the "
           "transaction free to change after signing, so the amounts and fee "
           "shown here would not be what gets broadcast.",
           audit->first_unsupported, psbt_sighash_name(audit->first_sighash));
  show_cannot_sign(body, dismissed_cb);
  return true;
}

/* An input whose utxo data contradicts the prevout it spends is not a missing
 * proof, it is a broken one: the previous transaction supplied does not hash
 * to the outpoint, or it disagrees with the witness_utxo beside it. No fee can
 * be computed from that, and libwally refuses an ECDSA or taproot key-path
 * signature over a previous transaction whose txid does not match anyway, so
 * stop before the review screen shows a fabricated number. */
static bool reject_invalid_amount(const psbt_amount_audit_t *audit,
                                  dialog_callback_t dismissed_cb) {
  if (!audit->invalid)
    return false;

  char body[384];
  snprintf(body, sizeof(body),
           "Input %zu's amount contradicts the transaction it spends: the "
           "previous transaction supplied does not match the outpoint, or the "
           "two copies of the amount disagree.\n\n"
           "The fee cannot be computed and this PSBT should not be signed.",
           audit->first_invalid);
  show_cannot_sign(body, dismissed_cb);
  return true;
}

/* Everything the review screen shows about outputs comes from the transaction
 * the PSBT describes, extracted from v0's global transaction or rebuilt from
 * v2's per-input and per-output fields. Either fails when the result is not a
 * valid transaction -- outputs past the supply, say. Refuse here rather than
 * let the review screen come up empty and report it as unparseable data. */
static bool reject_unbuildable_tx(struct wally_psbt *psbt,
                                  dialog_callback_t dismissed_cb) {
  struct wally_tx *tx = psbt_tx_alloc(psbt);
  if (tx) {
    wally_tx_free(tx);
    return false;
  }

  show_cannot_sign("The transaction this PSBT describes cannot be "
                   "reconstructed.\n\n"
                   "An amount or output in it is out of range, so there is "
                   "nothing here that can be reviewed.",
                   dismissed_cb);
  return true;
}

/* A taproot signature commits to every input's amount, so with any amount
 * missing libwally cannot compute it and signing would fail only after the
 * user approved the transaction. */
static bool reject_taproot_missing_amount(const sign_policy_review_t *review,
                                          const psbt_amount_audit_t *audit,
                                          dialog_callback_t dismissed_cb) {
  if (!review->signs_taproot || !audit->missing)
    return false;

  char body[320];
  snprintf(body, sizeof(body),
           "Input %zu supplies no amount.\n\n"
           "A taproot signature commits to the amount of every input, so "
           "this PSBT cannot be signed until the coordinator includes them "
           "all.",
           audit->first_missing);
  show_cannot_sign(body, dismissed_cb);
  return true;
}

/* An output with no address form is shown as its script's hex, which only
 * reviews it while the whole script fits on the screen. */
static bool reject_unshowable_output(struct wally_psbt *psbt,
                                     dialog_callback_t dismissed_cb) {
  struct wally_tx *tx = psbt_tx_alloc(psbt);
  if (!tx)
    return false;
  size_t index = tx->num_outputs, script_len = 0;
  for (size_t i = 0; i < tx->num_outputs && index == tx->num_outputs; i++) {
    const struct wally_tx_output *out = &tx->outputs[i];
    if (out->script_len <= PSBT_MAX_SHOWN_SCRIPT_LEN)
      continue;
    char *dest =
        psbt_scriptpubkey_to_address(out->script, out->script_len, false);
    if (dest)
      wally_free_string(dest);
    else {
      index = i;
      script_len = out->script_len;
    }
  }
  size_t num_outputs = tx->num_outputs;
  wally_tx_free(tx);
  if (index == num_outputs)
    return false;

  char body[256];
  snprintf(body, sizeof(body),
           "Output %zu pays a %zu-byte script that has no address.\n\n"
           "It is too long to show in full, so what it pays cannot be "
           "reviewed.",
           index, script_len);
  show_cannot_sign(body, dismissed_cb);
  return true;
}

/* sum(outputs) > sum(inputs) cannot happen on chain: the difference is the
 * fee and it is never negative. Either an input amount is understated or an
 * output amount is inflated, and both make every number on the review screen
 * a lie. Only decidable when each input actually supplied an amount -- a
 * MISSING one contributes 0, which produces the same shape honestly. When the
 * outputs cannot even be summed nothing about the fee is knowable, so that is
 * refused too. */
static bool reject_impossible_fee(struct wally_psbt *psbt,
                                  const psbt_amount_audit_t *audit,
                                  dialog_callback_t dismissed_cb) {
  if (audit->missing)
    return false;
  uint64_t total_output = 0;
  if (!psbt_total_output_value(psbt, &total_output)) {
    show_cannot_sign("The outputs of this PSBT cannot be added up: an amount "
                     "is out of range.\n\n"
                     "The fee cannot be computed, so nothing it claims can be "
                     "reviewed honestly.",
                     dismissed_cb);
    return true;
  }
  if (total_output <= audit->total)
    return false;

  char body[384];
  snprintf(body, sizeof(body),
           "The outputs add up to more than the inputs, which cannot happen: "
           "the difference between them is the fee and it is never "
           "negative.\n\n"
           "Inputs total %llu sats, outputs total %llu sats. An amount in this "
           "PSBT is wrong, so nothing it claims can be reviewed honestly.",
           (unsigned long long)audit->total, (unsigned long long)total_output);
  show_cannot_sign(body, dismissed_cb);
  return true;
}

static bool reject_partial(const sign_policy_review_t *review,
                           dialog_callback_t dismissed_cb) {
  if (!review->any_input_external || settings_get_partial_signing())
    return false;

  char body[384];
  char idx_list[96];
  size_t idx_pos = 0;
  idx_list[0] = '\0';
  size_t shown = review->external_count < EXTERNAL_INPUT_LIST_CAP
                     ? review->external_count
                     : EXTERNAL_INPUT_LIST_CAP;
  for (size_t k = 0; k < shown; k++) {
    int written =
        snprintf(idx_list + idx_pos, sizeof(idx_list) - idx_pos, "%s%zu",
                 k == 0 ? "" : ", ", review->external_inputs[k]);
    if (written < 0 || (size_t)written >= sizeof(idx_list) - idx_pos)
      break;
    idx_pos += (size_t)written;
  }
  if (review->external_count > EXTERNAL_INPUT_LIST_CAP) {
    snprintf(idx_list + idx_pos, sizeof(idx_list) - idx_pos, ", ...");
  }

  snprintf(body, sizeof(body),
           "Input%s %s %s not from this wallet. Enable 'Partial signing' "
           "in Settings > Wallet to proceed.",
           review->external_count == 1 ? "" : "s", idx_list,
           review->external_count == 1 ? "is" : "are");
  show_cannot_sign(body, dismissed_cb);
  return true;
}

bool psbt_sign_policy_allows_review(struct wally_psbt *psbt, bool is_testnet,
                                    dialog_callback_t dismissed_cb,
                                    void (*load_descriptor_cb)(void)) {
  if (!psbt)
    return false;

  sign_policy_review_t review = {0};
  scan_inputs(psbt, is_testnet, &review);
  scan_outputs(psbt, is_testnet, &review);

  psbt_amount_audit_t audit;
  psbt_audit_input_amounts(psbt, &audit);

  psbt_sighash_audit_t sighash_audit;
  psbt_audit_sighash(psbt, &sighash_audit);

  if (!review.any_signable) {
    show_cannot_sign("No inputs match this wallet's signing policy.",
                     dismissed_cb);
    return false;
  }
  if (reject_unbuildable_tx(psbt, dismissed_cb))
    return false;
  if (reject_unshowable_output(psbt, dismissed_cb))
    return false;
  if (reject_unsupported_sighash(&sighash_audit, dismissed_cb))
    return false;
  if (reject_invalid_amount(&audit, dismissed_cb))
    return false;
  if (reject_impossible_fee(psbt, &audit, dismissed_cb))
    return false;
  if (reject_taproot_missing_amount(&review, &audit, dismissed_cb))
    return false;
  if (reject_expected_owned(&review, dismissed_cb, load_descriptor_cb))
    return false;
  if (reject_permissive(&review, dismissed_cb))
    return false;
  if (reject_partial(&review, dismissed_cb))
    return false;

  return true;
}
