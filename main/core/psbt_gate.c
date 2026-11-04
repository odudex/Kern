#include "psbt_gate.h"

#include <string.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_transaction.h>

typedef struct {
  bool any_signable;
  bool signs_taproot;
  bool need_permissive;
  bool need_expected_owned;
} gate_scan_t;

/* EXPECTED_OWNED outranks OWNED_UNSAFE, so the flagged entry is the first of
 * the highest-ranked kind. */
static void remember_flagged(const gate_scan_t *scan,
                             psbt_gate_report_t *report,
                             psbt_ownership_t ownership, size_t index,
                             bool is_input, const unsigned char *raw_keypath,
                             size_t raw_keypath_len) {
  if (ownership == PSBT_OWNERSHIP_OWNED_UNSAFE &&
      (scan->need_permissive || scan->need_expected_owned))
    return;
  if (ownership == PSBT_OWNERSHIP_EXPECTED_OWNED && scan->need_expected_owned)
    return;

  report->flagged_index = index;
  report->flagged_is_input = is_input;
  if (!psbt_format_keypath(raw_keypath, raw_keypath_len, report->flagged_path,
                           sizeof(report->flagged_path)))
    report->flagged_path[0] = '\0';
}

static void scan_inputs(struct wally_psbt *psbt,
                        const input_ownership_t *inputs, gate_scan_t *scan,
                        psbt_gate_report_t *report) {
  size_t num_inputs = 0;
  if (wally_psbt_get_num_inputs(psbt, &num_inputs) != WALLY_OK)
    return;

  for (size_t i = 0; i < num_inputs; i++) {
    const input_ownership_t *own = &inputs[i];
    if (own->ownership != PSBT_OWNERSHIP_EXTERNAL &&
        psbt_input_is_taproot(psbt, i))
      scan->signs_taproot = true;
    switch (own->ownership) {
    case PSBT_OWNERSHIP_OWNED_SAFE:
      scan->any_signable = true;
      break;
    case PSBT_OWNERSHIP_OWNED_UNSAFE:
      scan->any_signable = true;
      remember_flagged(scan, report, own->ownership, i, true, own->raw_keypath,
                       own->raw_keypath_len);
      scan->need_permissive = true;
      break;
    case PSBT_OWNERSHIP_EXPECTED_OWNED:
      scan->any_signable = true;
      remember_flagged(scan, report, own->ownership, i, true, own->raw_keypath,
                       own->raw_keypath_len);
      scan->need_expected_owned = true;
      break;
    case PSBT_OWNERSHIP_EXTERNAL:
      if (report->external_count < PSBT_GATE_EXTERNAL_LIST_CAP)
        report->external_inputs[report->external_count] = i;
      report->external_count++;
      break;
    }
  }
}

static void scan_outputs(struct wally_psbt *psbt,
                         const output_ownership_t *outputs, gate_scan_t *scan,
                         psbt_gate_report_t *report) {
  size_t num_outputs = 0;
  if (wally_psbt_get_num_outputs(psbt, &num_outputs) != WALLY_OK)
    return;

  for (size_t i = 0; i < num_outputs; i++) {
    const output_ownership_t *own = &outputs[i];
    switch (own->ownership) {
    case PSBT_OWNERSHIP_OWNED_UNSAFE:
      remember_flagged(scan, report, own->ownership, i, false, own->raw_keypath,
                       own->raw_keypath_len);
      scan->need_permissive = true;
      break;
    case PSBT_OWNERSHIP_EXPECTED_OWNED:
      remember_flagged(scan, report, own->ownership, i, false, own->raw_keypath,
                       own->raw_keypath_len);
      scan->need_expected_owned = true;
      break;
    case PSBT_OWNERSHIP_OWNED_SAFE:
    case PSBT_OWNERSHIP_EXTERNAL:
      break;
    }
  }
}

/* Everything the review screen shows about outputs comes from the transaction
 * the PSBT describes, extracted from v0's global transaction or rebuilt from
 * v2's per-input and per-output fields. Either fails when the result is not a
 * valid transaction -- outputs past the supply, say. */
static bool tx_is_buildable(struct wally_psbt *psbt) {
  struct wally_tx *tx = psbt_tx_alloc(psbt);
  if (!tx)
    return false;
  wally_tx_free(tx);
  return true;
}

/* An output with no address form is shown as its script's hex, which only
 * reviews it while the whole script fits on the screen. */
static bool find_unshowable_output(struct wally_psbt *psbt,
                                   psbt_gate_report_t *report) {
  struct wally_tx *tx = psbt_tx_alloc(psbt);
  if (!tx)
    return false;
  bool found = false;
  for (size_t i = 0; i < tx->num_outputs && !found; i++) {
    const struct wally_tx_output *out = &tx->outputs[i];
    if (out->script_len <= PSBT_MAX_SHOWN_SCRIPT_LEN)
      continue;
    char *dest =
        psbt_scriptpubkey_to_address(out->script, out->script_len, false);
    if (dest) {
      wally_free_string(dest);
      continue;
    }
    found = true;
    report->unshowable_index = i;
    report->unshowable_script_len = out->script_len;
  }
  wally_tx_free(tx);
  return found;
}

psbt_gate_t psbt_gate_check(struct wally_psbt *psbt,
                            const input_ownership_t *inputs,
                            const output_ownership_t *outputs,
                            const psbt_gate_settings_t *settings,
                            psbt_gate_report_t *report) {
  memset(report, 0, sizeof(*report));
  if (!psbt || !inputs || !outputs || !settings)
    return PSBT_GATE_NOTHING_SIGNABLE;

  gate_scan_t scan = {0};
  scan_inputs(psbt, inputs, &scan, report);
  scan_outputs(psbt, outputs, &scan, report);
  psbt_audit_input_amounts(psbt, &report->amounts);
  psbt_audit_sighash(psbt, &report->sighash);
  const psbt_amount_audit_t *amounts = &report->amounts;

  if (!scan.any_signable)
    return PSBT_GATE_NOTHING_SIGNABLE;
  if (!tx_is_buildable(psbt))
    return PSBT_GATE_UNBUILDABLE_TX;
  if (find_unshowable_output(psbt, report))
    return PSBT_GATE_UNSHOWABLE_OUTPUT;
  /* Under NONE, SINGLE or ANYONECANPAY the parts of the transaction the
   * signature does not cover can be rewritten after it, so the review would
   * not show what gets mined. */
  if (report->sighash.unsupported)
    return PSBT_GATE_UNSUPPORTED_SIGHASH;
  /* Contradictory utxo data is not a missing proof but a broken one: no fee
   * can be computed from it. */
  if (amounts->invalid)
    return PSBT_GATE_INVALID_AMOUNT;
  /* Outputs above inputs cannot happen on chain. Only decidable when every
   * input supplied an amount: a missing one counts as 0. */
  if (!amounts->missing) {
    if (!psbt_total_output_value(psbt, &report->total_output))
      return PSBT_GATE_UNSUMMABLE_OUTPUTS;
    if (report->total_output > amounts->total)
      return PSBT_GATE_IMPOSSIBLE_FEE;
  }
  /* A taproot signature commits to every input's amount, so signing would
   * fail only after the user approved the transaction. */
  if (scan.signs_taproot && amounts->missing)
    return PSBT_GATE_TAPROOT_MISSING_AMOUNT;
  if (scan.need_expected_owned && !settings->expected_owned)
    return PSBT_GATE_EXPECTED_OWNED;
  if (scan.need_permissive && !settings->permissive)
    return PSBT_GATE_PERMISSIVE;
  if (report->external_count > 0 && !settings->partial)
    return PSBT_GATE_PARTIAL;
  return PSBT_GATE_ALLOW;
}
