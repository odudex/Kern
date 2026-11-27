/*
 * PSBT review data assembly and output-role classification (UI-free).
 */

#include "psbt_review.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_transaction.h>

static const char *ss_script_label(ss_script_type_t script) {
  switch (script) {
  case SS_SCRIPT_P2PKH:
    return "Legacy";
  case SS_SCRIPT_P2SH_P2WPKH:
    return "Nested SegWit";
  case SS_SCRIPT_P2WPKH:
    return "Native SegWit";
  case SS_SCRIPT_P2TR:
    return "Taproot";
  default:
    return "Single-sig";
  }
}

void psbt_review_format_claim_policy(const claim_t *claim, char *out,
                                     size_t out_size) {
  if (!out || out_size == 0)
    return;
  out[0] = '\0';
  if (!claim)
    return;

  if (claim->kind == CLAIM_WHITELIST) {
    snprintf(out, out_size, "%s @ account %u",
             ss_script_label(claim->whitelist.script),
             (unsigned)claim->whitelist.account);
  } else if (claim->kind == CLAIM_REGISTRY && claim->registry.entry) {
    const registry_entry_t *entry = claim->registry.entry;
    snprintf(out, out_size, "%s", entry->label[0] ? entry->label : entry->id);
  }
}

static bool output_shares_input_policy(const psbt_review_input_t *inputs,
                                       size_t num_inputs,
                                       const claim_t *source) {
  for (size_t i = 0; i < num_inputs; i++)
    if (inputs[i].ownership == PSBT_OWNERSHIP_OWNED_SAFE &&
        psbt_claims_share_policy(&inputs[i].claim, source))
      return true;
  return false;
}

void psbt_review_classify_output(const psbt_review_input_t *inputs,
                                 size_t num_inputs,
                                 output_ownership_t ownership,
                                 psbt_review_output_t *out) {
  switch (ownership.ownership) {
  case PSBT_OWNERSHIP_OWNED_SAFE:
    if (ownership.source.kind == CLAIM_WHITELIST) {
      out->change_chain = (ownership.source.whitelist.chain == 1);
      out->address_index = ownership.source.whitelist.index;
    } else {
      out->change_chain = (ownership.source.registry.multi_index == 1);
      out->address_index = ownership.source.registry.child_num;
    }
    psbt_review_format_claim_policy(&ownership.source, out->policy,
                                    sizeof(out->policy));
    out->type = out->change_chain && output_shares_input_policy(
                                         inputs, num_inputs, &ownership.source)
                    ? PSBT_OUTPUT_CHANGE
                    : PSBT_OUTPUT_SELF_TRANSFER;
    return;

  case PSBT_OWNERSHIP_OWNED_UNSAFE:
  case PSBT_OWNERSHIP_EXPECTED_OWNED:
    if (!psbt_format_keypath(ownership.raw_keypath, ownership.raw_keypath_len,
                             out->path, sizeof(out->path)))
      out->path[0] = '\0';
    out->type = ownership.ownership == PSBT_OWNERSHIP_OWNED_UNSAFE
                    ? PSBT_OUTPUT_OWNED_UNSAFE
                    : PSBT_OUTPUT_EXPECTED_OWNED;
    return;

  case PSBT_OWNERSHIP_EXTERNAL:
  default:
    out->type = PSBT_OUTPUT_SPEND;
    return;
  }
}

void psbt_review_free_owners(psbt_owners_t *owners) {
  if (!owners)
    return;
  free(owners->inputs);
  free(owners->outputs);
  memset(owners, 0, sizeof(*owners));
}

bool psbt_review_classify_owners(const struct wally_psbt *psbt, bool is_testnet,
                                 psbt_owners_t *out) {
  if (!out)
    return false;
  memset(out, 0, sizeof(*out));
  if (!psbt || wally_psbt_get_num_inputs(psbt, &out->num_inputs) != WALLY_OK ||
      wally_psbt_get_num_outputs(psbt, &out->num_outputs) != WALLY_OK ||
      !out->num_inputs || !out->num_outputs)
    return false;

  out->inputs = calloc(out->num_inputs, sizeof(*out->inputs));
  out->outputs = calloc(out->num_outputs, sizeof(*out->outputs));
  if (!out->inputs || !out->outputs) {
    psbt_review_free_owners(out);
    return false;
  }

  for (size_t i = 0; i < out->num_inputs; i++)
    out->inputs[i] = psbt_classify_input(psbt, i, is_testnet);
  for (size_t i = 0; i < out->num_outputs; i++)
    out->outputs[i] = psbt_classify_output(psbt, i, is_testnet);
  return true;
}

void psbt_review_free(psbt_review_t *data) {
  if (!data)
    return;
  if (data->inputs)
    for (size_t i = 0; i < data->num_inputs; i++)
      wally_free_string(data->inputs[i].address);
  free(data->inputs);
  if (data->outputs)
    for (size_t i = 0; i < data->num_outputs; i++)
      wally_free_string(data->outputs[i].address);
  free(data->outputs);
  memset(data, 0, sizeof(*data));
}

bool psbt_review_collect(const struct wally_psbt *psbt, bool is_testnet,
                         const psbt_owners_t *owners, psbt_review_t *out) {
  if (!psbt || !owners || !out)
    return false;
  memset(out, 0, sizeof(*out));
  out->num_inputs = owners->num_inputs;
  out->num_outputs = owners->num_outputs;
  if (out->num_inputs == 0 || out->num_outputs == 0)
    return false;

  out->inputs = calloc(out->num_inputs, sizeof(*out->inputs));
  out->outputs = calloc(out->num_outputs, sizeof(*out->outputs));
  if (!out->inputs || !out->outputs)
    goto fail;

  uint64_t *values = calloc(out->num_inputs, sizeof(*values));
  if (!values)
    goto fail;
  psbt_audit_input_values(psbt, &out->amount_audit, values);

  for (size_t i = 0; i < out->num_inputs; i++) {
    psbt_review_input_t *in = &out->inputs[i];
    in->index = i;
    in->value = values[i];
    out->total_input += in->value;

    const input_ownership_t own = owners->inputs[i];
    in->ownership = own.ownership;
    if (own.ownership == PSBT_OWNERSHIP_OWNED_SAFE) {
      in->claim = own.claim;
      psbt_review_format_claim_policy(&own.claim, in->policy,
                                      sizeof(in->policy));
    }
    if ((own.ownership == PSBT_OWNERSHIP_OWNED_UNSAFE ||
         own.ownership == PSBT_OWNERSHIP_EXPECTED_OWNED) &&
        !psbt_format_keypath(own.raw_keypath, own.raw_keypath_len, in->path,
                             sizeof(in->path)))
      in->path[0] = '\0';

    /* Only external inputs show their address, in the co-signing warning. */
    if (own.ownership == PSBT_OWNERSHIP_EXTERNAL) {
      out->external_inputs++;
      unsigned char spk[PSBT_MAX_SHOWN_SCRIPT_LEN];
      size_t spk_len = 0;
      if (psbt_input_utxo_script(psbt, i, spk, sizeof(spk), &spk_len)) {
        in->address =
            psbt_output_destination(spk, spk_len, is_testnet, &in->dest_kind);
        in->script_len = spk_len;
      }
    }
  }

  free(values);

  bool *signing = calloc(out->num_inputs, sizeof(*signing));
  if (!signing)
    goto fail;
  for (size_t i = 0; i < out->num_inputs; i++)
    signing[i] = out->inputs[i].ownership != PSBT_OWNERSHIP_EXTERNAL;
  out->fee_trusted =
      psbt_fee_is_trusted_for_signing(psbt, &out->amount_audit, signing);
  free(signing);

  struct wally_tx *tx = psbt_tx_alloc(psbt);
  if (!tx)
    goto fail;

  /* BIP-125 opts a transaction into replaceability when any input's sequence
   * is below 0xfffffffe. */
  out->locktime = tx->locktime;
  for (size_t i = 0; i < tx->num_inputs; i++)
    if (tx->inputs[i].sequence < 0xfffffffeu)
      out->signals_rbf = true;

  for (size_t i = 0; i < out->num_outputs; i++) {
    psbt_review_output_t *o = &out->outputs[i];
    const struct wally_tx_output *txo = &tx->outputs[i];
    o->index = i;
    o->value = txo->satoshi;
    out->total_output += o->value;
    o->address = psbt_output_destination(txo->script, txo->script_len,
                                         is_testnet, &o->dest_kind);
    o->script_len = txo->script_len;
    psbt_review_classify_output(out->inputs, out->num_inputs,
                                owners->outputs[i], o);
    o->is_dust =
        o->value < psbt_output_dust_threshold(txo->script, txo->script_len);
    if (o->is_dust) {
      if (!out->dust_count) {
        out->first_dust = i;
        out->first_dust_value = o->value;
      }
      out->dust_count++;
    }
  }
  wally_tx_free(tx);

  out->fee = out->total_input > out->total_output
                 ? out->total_input - out->total_output
                 : 0;
  return true;

fail:
  psbt_review_free(out);
  return false;
}
