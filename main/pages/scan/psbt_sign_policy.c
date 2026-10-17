#include "psbt_sign_policy.h"

#include "../../core/psbt_gate.h"
#include "../../core/settings.h"

#include <stdio.h>

static void show_cannot_sign(const char *message,
                             dialog_callback_t dismissed_cb) {
  dialog_show_info("Cannot sign PSBT", message, dismissed_cb, NULL,
                   DIALOG_STYLE_FULLSCREEN);
}

static const char *flagged_kind(const psbt_gate_report_t *report) {
  return report->flagged_is_input ? "Input" : "Output";
}

static const char *flagged_path(const psbt_gate_report_t *report) {
  return report->flagged_path[0] ? report->flagged_path : "(unknown)";
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

static void reject_expected_owned(const psbt_gate_report_t *report,
                                  dialog_callback_t dismissed_cb,
                                  void (*load_descriptor_cb)(void)) {
  snprintf(pending_reject_body, sizeof(pending_reject_body),
           "%s %zu's path %s matches this wallet's fingerprint but the script "
           "cannot be re-derived from it -- wallet bug or attacker-crafted "
           "input.\n"
           "To sign anyway: Enable 'Expected-owned signing' in Settings > "
           "Wallet. The device will then trust the PSBT's keypath without "
           "verification.",
           flagged_kind(report), report->flagged_index, flagged_path(report));

  if (!load_descriptor_cb) {
    show_cannot_sign(pending_reject_body, dismissed_cb);
    return;
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
           flagged_kind(report), report->flagged_index, flagged_path(report));
  dialog_show_confirm(prompt, offer_descriptor_cb, NULL,
                      DIALOG_STYLE_FULLSCREEN);
}

static void format_external_inputs(const psbt_gate_report_t *report, char *body,
                                   size_t body_len) {
  char idx_list[96];
  size_t idx_pos = 0;
  idx_list[0] = '\0';
  size_t shown = report->external_count < PSBT_GATE_EXTERNAL_LIST_CAP
                     ? report->external_count
                     : PSBT_GATE_EXTERNAL_LIST_CAP;
  for (size_t k = 0; k < shown; k++) {
    int written =
        snprintf(idx_list + idx_pos, sizeof(idx_list) - idx_pos, "%s%zu",
                 k == 0 ? "" : ", ", report->external_inputs[k]);
    if (written < 0 || (size_t)written >= sizeof(idx_list) - idx_pos)
      break;
    idx_pos += (size_t)written;
  }
  if (report->external_count > PSBT_GATE_EXTERNAL_LIST_CAP) {
    snprintf(idx_list + idx_pos, sizeof(idx_list) - idx_pos, ", ...");
  }

  snprintf(body, body_len,
           "Input%s %s %s not from this wallet. Enable 'Partial signing' "
           "in Settings > Wallet to proceed.",
           report->external_count == 1 ? "" : "s", idx_list,
           report->external_count == 1 ? "is" : "are");
}

bool psbt_sign_policy_allows_review(struct wally_psbt *psbt,
                                    const input_ownership_t *inputs,
                                    const output_ownership_t *outputs,
                                    dialog_callback_t dismissed_cb,
                                    void (*load_descriptor_cb)(void)) {
  psbt_gate_settings_t settings = {
      .expected_owned = settings_get_expected_owned_signing(),
      .permissive = settings_get_permissive_signing(),
      .partial = settings_get_partial_signing(),
  };
  psbt_gate_report_t report;
  psbt_gate_t gate = psbt_gate_check(psbt, inputs, outputs, &settings, &report);

  char body[384];
  switch (gate) {
  case PSBT_GATE_ALLOW:
    return true;
  case PSBT_GATE_NOTHING_SIGNABLE:
    show_cannot_sign("No inputs match this wallet's signing policy.",
                     dismissed_cb);
    break;
  case PSBT_GATE_UNBUILDABLE_TX:
    show_cannot_sign("The transaction this PSBT describes cannot be "
                     "reconstructed.\n\n"
                     "An amount or output in it is out of range, so there is "
                     "nothing here that can be reviewed.",
                     dismissed_cb);
    break;
  case PSBT_GATE_UNSHOWABLE_OUTPUT:
    snprintf(body, sizeof(body),
             "Output %zu pays a %zu-byte script that has no address.\n\n"
             "It is too long to show in full, so what it pays cannot be "
             "reviewed.",
             report.unshowable_index, report.unshowable_script_len);
    show_cannot_sign(body, dismissed_cb);
    break;
  case PSBT_GATE_UNSUPPORTED_SIGHASH:
    snprintf(body, sizeof(body),
             "Input %zu asks to be signed with SIGHASH_%s.\n\n"
             "Only ALL is supported: any other flag leaves part of the "
             "transaction free to change after signing, so the amounts and "
             "fee shown here would not be what gets broadcast.",
             report.sighash.first_unsupported,
             psbt_sighash_name(report.sighash.first_sighash));
    show_cannot_sign(body, dismissed_cb);
    break;
  case PSBT_GATE_INVALID_AMOUNT:
    snprintf(body, sizeof(body),
             "Input %zu's amount contradicts the transaction it spends: the "
             "previous transaction supplied does not match the outpoint, or "
             "the two copies of the amount disagree.\n\n"
             "The fee cannot be computed and this PSBT should not be signed.",
             report.amounts.first_invalid);
    show_cannot_sign(body, dismissed_cb);
    break;
  case PSBT_GATE_UNSUMMABLE_OUTPUTS:
    show_cannot_sign("The outputs of this PSBT cannot be added up: an amount "
                     "is out of range.\n\n"
                     "The fee cannot be computed, so nothing it claims can be "
                     "reviewed honestly.",
                     dismissed_cb);
    break;
  case PSBT_GATE_IMPOSSIBLE_FEE:
    snprintf(body, sizeof(body),
             "The outputs add up to more than the inputs, which cannot "
             "happen: the difference between them is the fee and it is never "
             "negative.\n\n"
             "Inputs total %llu sats, outputs total %llu sats. An amount in "
             "this PSBT is wrong, so nothing it claims can be reviewed "
             "honestly.",
             (unsigned long long)report.amounts.total,
             (unsigned long long)report.total_output);
    show_cannot_sign(body, dismissed_cb);
    break;
  case PSBT_GATE_TAPROOT_MISSING_AMOUNT:
    snprintf(body, sizeof(body),
             "Input %zu supplies no amount.\n\n"
             "A taproot signature commits to the amount of every input, so "
             "this PSBT cannot be signed until the coordinator includes them "
             "all.",
             report.amounts.first_missing);
    show_cannot_sign(body, dismissed_cb);
    break;
  case PSBT_GATE_EXPECTED_OWNED:
    reject_expected_owned(&report, dismissed_cb, load_descriptor_cb);
    break;
  case PSBT_GATE_PERMISSIVE:
    snprintf(body, sizeof(body),
             "%s %zu's path %s is on a non-standard derivation. "
             "Enable 'Permissive signing' in Settings > Wallet to proceed.",
             flagged_kind(&report), report.flagged_index,
             flagged_path(&report));
    show_cannot_sign(body, dismissed_cb);
    break;
  case PSBT_GATE_PARTIAL:
    format_external_inputs(&report, body, sizeof(body));
    show_cannot_sign(body, dismissed_cb);
    break;
  }
  return false;
}
