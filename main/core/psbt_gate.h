#ifndef PSBT_GATE_H
#define PSBT_GATE_H

#include "psbt.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The checks a PSBT passes before its review screen, in the order they run:
 * the first that fires is the one reported. */
typedef enum {
  PSBT_GATE_ALLOW = 0,
  PSBT_GATE_NOTHING_SIGNABLE,
  PSBT_GATE_UNBUILDABLE_TX,
  PSBT_GATE_UNSHOWABLE_OUTPUT,
  PSBT_GATE_UNSUPPORTED_SIGHASH,
  PSBT_GATE_INVALID_AMOUNT,
  PSBT_GATE_UNSUMMABLE_OUTPUTS,
  PSBT_GATE_IMPOSSIBLE_FEE,
  PSBT_GATE_TAPROOT_MISSING_AMOUNT,
  PSBT_GATE_EXPECTED_OWNED,
  PSBT_GATE_PERMISSIVE,
  PSBT_GATE_PARTIAL,
} psbt_gate_t;

/* Settings > Wallet toggles that lift a gate. */
typedef struct {
  bool expected_owned;
  bool permissive;
  bool partial;
} psbt_gate_settings_t;

#define PSBT_GATE_EXTERNAL_LIST_CAP 4

/* What the dialog for the gate that fired names. */
typedef struct {
  psbt_amount_audit_t amounts;
  psbt_sighash_audit_t sighash;
  uint64_t total_output;
  size_t unshowable_index;
  size_t unshowable_script_len;
  /* The input or output behind EXPECTED_OWNED or PERMISSIVE; an empty path
   * when its keypath cannot be formatted. */
  bool flagged_is_input;
  size_t flagged_index;
  char flagged_path[80];
  /* Inputs behind PARTIAL: the first PSBT_GATE_EXTERNAL_LIST_CAP of
   * external_count. */
  size_t external_inputs[PSBT_GATE_EXTERNAL_LIST_CAP];
  size_t external_count;
} psbt_gate_report_t;

/* `inputs` and `outputs` hold the PSBT's classification, one entry per input
 * and per output. */
psbt_gate_t psbt_gate_check(struct wally_psbt *psbt,
                            const input_ownership_t *inputs,
                            const output_ownership_t *outputs,
                            const psbt_gate_settings_t *settings,
                            psbt_gate_report_t *report);

#endif
