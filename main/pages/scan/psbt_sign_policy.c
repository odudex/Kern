#include "psbt_sign_policy.h"

#include "../../core/psbt.h"
#include "../../core/settings.h"

#include <stdio.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>

#define EXTERNAL_INPUT_LIST_CAP 4

typedef struct {
  bool any_signable;
  bool any_input_external;
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
  psbt_format_keypath(raw_keypath, raw_keypath_len, review->flagged_path,
                      sizeof(review->flagged_path));
}

static void scan_inputs(struct wally_psbt *psbt, bool is_testnet,
                        sign_policy_review_t *review) {
  size_t num_inputs = 0;
  if (wally_psbt_get_num_inputs(psbt, &num_inputs) != WALLY_OK)
    return;

  for (size_t i = 0; i < num_inputs; i++) {
    input_ownership_t own = psbt_classify_input(psbt, i, is_testnet);
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

static bool reject_expected_owned(const sign_policy_review_t *review,
                                  dialog_callback_t dismissed_cb) {
  if (!review->need_expected_owned || settings_get_expected_owned_signing())
    return false;

  char body[384];
  snprintf(body, sizeof(body),
           "%s %zu's path %s matches our fingerprint but the script "
           "cannot be re-derived from it -- wallet bug or attacker-crafted "
           "input.\n"
           "If multisig: Load the wallet descriptor.\n"
           "To sign anyway: Enable 'Expected-owned signing' in Wallet "
           "settings. The device will then trust the PSBT's keypath without "
           "verification.",
           review->flagged_is_input ? "Input" : "Output", review->flagged_index,
           review->flagged_path[0] ? review->flagged_path : "(unknown)");
  show_cannot_sign(body, dismissed_cb);
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
                                    dialog_callback_t dismissed_cb) {
  if (!psbt)
    return false;

  sign_policy_review_t review = {0};
  scan_inputs(psbt, is_testnet, &review);
  scan_outputs(psbt, is_testnet, &review);

  if (!review.any_signable) {
    show_cannot_sign("No inputs match this wallet's signing policy.",
                     dismissed_cb);
    return false;
  }
  if (reject_expected_owned(&review, dismissed_cb))
    return false;
  if (reject_permissive(&review, dismissed_cb))
    return false;
  if (reject_partial(&review, dismissed_cb))
    return false;

  return true;
}
