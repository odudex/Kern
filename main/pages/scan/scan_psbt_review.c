/*
 * PSBT review: parse, network check, input/output classification, the review
 * screen, and the on-the-fly descriptor load offered by the sign-policy gate.
 */

#include "../../core/psbt.h"
#include "../../core/registry.h"
#include "../../core/wallet.h"
#include "../../qr/parser.h"
#include "../../qr/scanner.h"
#include "../../ui/dialog.h"
#include "../../ui/sankey.h"
#include "../../ui/theme_widgets.h"
#include "../load_descriptor_storage.h"
#include "../shared/descriptor_loader.h"
#include "psbt_sign_policy.h"
#include "scan_internal.h"
#include <inttypes.h>
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_transaction.h>

static void psbt_offer_descriptor_cb(void);
static void psbt_desc_menu_back_cb(void);
static void psbt_desc_qr_cb(void);
static void psbt_desc_flash_cb(void);
static void psbt_desc_sd_cb(void);
static bool create_psbt_info_display(void);

// Fee share of the inputs at which the review screen stops calling it normal.
#define HIGH_FEE_PERCENT 10u
// Past these counts a section collapses to a single totals row.
#define NONSTANDARD_INPUT_INLINE_THRESHOLD 4
#define SELF_TRANSFER_INLINE_THRESHOLD 4

typedef enum {
  OUTPUT_TYPE_SELF_TRANSFER,
  OUTPUT_TYPE_CHANGE,
  /* fp + derive verifies the spk on a non-standard path — factually ours */
  OUTPUT_TYPE_OWNED_UNSAFE,
  /* fp matches but derive doesn't reach the spk — harness state, not
   * provably ours */
  OUTPUT_TYPE_EXPECTED_OWNED,
  OUTPUT_TYPE_SPEND,
} output_type_t;

typedef struct {
  size_t index;
  output_type_t type;
  uint64_t value;
  char *address;
  uint32_t address_index;
  bool is_dust;  /* below the relay dust threshold for its script type */
  char path[80]; /* populated for OWNED_UNSAFE / EXPECTED_OWNED */
} classified_output_t;

/* Input classification for the review screen. We only need a subset of
 * the policy-gate state here — enough to render an "External inputs"
 * warning section when the PSBT has any non-owned inputs and the user
 * has Partial signing enabled. */
typedef struct {
  size_t index;
  psbt_ownership_t ownership;
  uint64_t value;
  char *address; /* heap-allocated, may be NULL if spk can't be decoded */
  /* Human-readable policy this input is signed under, e.g. "BIP84 (Native
   * SegWit) acct 0" for whitelisted singlesig or the registered
   * descriptor's id ("ms_2of2") for registry matches. Empty for inputs
   * that aren't OWNED_SAFE — UNSAFE / EXPECTED_OWNED inputs surface the
   * raw path in their own warning sections. */
  char policy[64];
  char path[80]; /* populated for OWNED_UNSAFE / EXPECTED_OWNED */
} classified_input_t;

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

static void format_input_policy(const input_ownership_t *own, char *out,
                                size_t out_size) {
  out[0] = '\0';
  if (own->ownership != PSBT_OWNERSHIP_OWNED_SAFE)
    return;
  if (own->claim.kind == CLAIM_WHITELIST) {
    snprintf(out, out_size, "%s @ account %u",
             ss_script_label(own->claim.whitelist.script),
             (unsigned)own->claim.whitelist.account);
  } else if (own->claim.kind == CLAIM_REGISTRY && own->claim.registry.entry) {
    const registry_entry_t *entry = own->claim.registry.entry;
    snprintf(out, out_size, "%s", entry->label[0] ? entry->label : entry->id);
  }
}

// Classify output as self-transfer, change, owned-unsafe, expected-owned,
// or spend. For owned-unsafe and expected-owned, the path string is written
// to path_out (truncated to path_out_size).
static output_type_t classify_output(size_t output_index,
                                     uint32_t *address_index_out,
                                     char *path_out, size_t path_out_size) {
  bool is_change = false;
  uint32_t address_index = 0;

  output_ownership_t ownership =
      psbt_classify_output(scan_ctx.psbt, output_index, scan_ctx.is_testnet);

  switch (ownership.ownership) {
  case PSBT_OWNERSHIP_OWNED_SAFE:
    if (ownership.source.kind == CLAIM_WHITELIST) {
      is_change = (ownership.source.whitelist.chain == 1);
      address_index = ownership.source.whitelist.index;
    } else {
      is_change = (ownership.source.registry.multi_index == 1);
      address_index = ownership.source.registry.child_num;
    }
    *address_index_out = address_index;
    return is_change ? OUTPUT_TYPE_CHANGE : OUTPUT_TYPE_SELF_TRANSFER;

  case PSBT_OWNERSHIP_OWNED_UNSAFE:
  case PSBT_OWNERSHIP_EXPECTED_OWNED:
    if (path_out && path_out_size > 0 &&
        !psbt_format_keypath(ownership.raw_keypath, ownership.raw_keypath_len,
                             path_out, path_out_size))
      path_out[0] = '\0'; // renders no path line
    return ownership.ownership == PSBT_OWNERSHIP_OWNED_UNSAFE
               ? OUTPUT_TYPE_OWNED_UNSAFE
               : OUTPUT_TYPE_EXPECTED_OWNED;

  case PSBT_OWNERSHIP_EXTERNAL:
  default:
    return OUTPUT_TYPE_SPEND;
  }
}

static void policy_reject_dismissed_cb(void *user_data) {
  (void)user_data;
  if (scan_ctx.return_cb)
    scan_ctx.return_cb();
}

// Re-runs the policy gate against the retained PSBT. With offer_descriptor the
// expected-owned rejection becomes an offer to load a descriptor; without it
// the gate falls back to the plain rejection dialog.
void scan_psbt_resume_review(bool offer_descriptor) {
  if (!psbt_sign_policy_allows_review(
          scan_ctx.psbt, scan_ctx.is_testnet, policy_reject_dismissed_cb,
          offer_descriptor ? psbt_offer_descriptor_cb : NULL))
    return;
  if (!create_psbt_info_display())
    dialog_show_error_timeout("Invalid PSBT data", scan_ctx.return_cb, 0);
}

static void psbt_offer_descriptor_cb(void) {
  descriptor_loader_show_source_menu(scan_ctx.screen, psbt_desc_qr_cb,
                                     psbt_desc_flash_cb, psbt_desc_sd_cb,
                                     psbt_desc_menu_back_cb);
}

static void psbt_desc_menu_back_cb(void) {
  descriptor_loader_destroy_source_menu();
  scan_psbt_resume_review(false);
}

static void psbt_descriptor_validation_cb(descriptor_validation_result_t result,
                                          void *user_data) {
  (void)user_data;
  if (result != VALIDATION_SUCCESS)
    descriptor_loader_show_error(result);
  scan_psbt_resume_review(true);
}

static void return_from_descriptor_scanner_cb(void) {
  if (!qr_scanner_has_completed_result()) {
    qr_scanner_page_hide();
    qr_scanner_page_destroy();
    scan_psbt_resume_review(false);
    return;
  }
  descriptor_loader_process_scanner(psbt_descriptor_validation_cb, NULL, NULL);
}

static void psbt_desc_qr_cb(void) {
  descriptor_loader_destroy_source_menu();
  qr_scanner_page_create(NULL, return_from_descriptor_scanner_cb);
  qr_scanner_page_show();
}

static void psbt_desc_storage_return_cb(void) {
  load_descriptor_storage_page_destroy();
  scan_psbt_resume_review(false);
}

static void psbt_desc_storage_success_cb(void) {
  load_descriptor_storage_page_destroy();
  scan_psbt_resume_review(true);
}

static void psbt_desc_flash_cb(void) {
  descriptor_loader_destroy_source_menu();
  load_descriptor_storage_page_create(
      lv_screen_active(), psbt_desc_storage_return_cb,
      psbt_desc_storage_success_cb, STORAGE_FLASH);
  load_descriptor_storage_page_show();
}

static void psbt_desc_sd_cb(void) {
  descriptor_loader_destroy_source_menu();
  load_descriptor_storage_page_create(lv_screen_active(),
                                      psbt_desc_storage_return_cb,
                                      psbt_desc_storage_success_cb, STORAGE_SD);
  load_descriptor_storage_page_show();
}

bool scan_psbt_parse_base64(const char *base64_data) {
  if (!base64_data) {
    return false;
  }

  scan_psbt_cleanup();

  scan_ctx.psbt_base64 = strdup(base64_data);
  if (!scan_ctx.psbt_base64) {
    return false;
  }

  int ret = wally_psbt_from_base64(base64_data, 0, &scan_ctx.psbt);
  if (ret != WALLY_OK) {
    scan_psbt_cleanup();
    return false;
  }

  scan_ctx.source_base64 = true;
  return true;
}

static void mismatch_dialog_cb(void *user_data) {
  scan_psbt_cleanup();
  if (scan_ctx.return_cb) {
    scan_ctx.return_cb();
  }
}

bool scan_psbt_check_mismatch(void) {
  if (!scan_ctx.psbt) {
    return false;
  }

  scan_ctx.is_testnet = psbt_detect_network(scan_ctx.psbt);

  wallet_network_t wallet_net = wallet_get_network();
  bool wallet_is_testnet = (wallet_net == WALLET_NETWORK_TESTNET);

  bool network_mismatch = (scan_ctx.is_testnet != wallet_is_testnet);

  if (!network_mismatch) {
    return false;
  }

  char message[256];
  int offset = 0;
  offset += snprintf(
      message + offset, sizeof(message) - offset,
      "PSBT requires different settings for proper change detection:\n\n");

  offset += snprintf(message + offset, sizeof(message) - offset,
                     "  Network:  %s -> %s\n",
                     wallet_is_testnet ? "Testnet" : "Mainnet",
                     scan_ctx.is_testnet ? "Testnet" : "Mainnet");

  snprintf(message + offset, sizeof(message) - offset,
           "\nGo to Settings " LV_SYMBOL_SETTINGS
           " to update\nconfiguration before signing.");

  dialog_show_info("Configuration Mismatch", message, mismatch_dialog_cb, NULL,
                   DIALOG_STYLE_FULLSCREEN);

  return true;
}

/* Everything the review screen shows, gathered before any widget is created
 * so the render helpers below never touch the PSBT or wally. */
typedef struct {
  classified_input_t *inputs;
  size_t num_inputs;
  size_t external_inputs;
  classified_output_t *outputs;
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
} review_data_t;

/* psbt_scriptpubkey_to_address returns a wally string, except the literal
 * OP_RETURN marker which is plain malloc. */
static void free_address(char *address) {
  if (!address)
    return;
  if (strcmp(address, "OP_RETURN") == 0)
    free(address);
  else
    wally_free_string(address);
}

static void review_data_free(review_data_t *d) {
  if (d->inputs)
    for (size_t i = 0; i < d->num_inputs; i++)
      free_address(d->inputs[i].address);
  free(d->inputs);
  if (d->outputs)
    for (size_t i = 0; i < d->num_outputs; i++)
      free_address(d->outputs[i].address);
  free(d->outputs);
  memset(d, 0, sizeof(*d));
}

static bool review_data_collect(review_data_t *d) {
  memset(d, 0, sizeof(*d));
  if (wally_psbt_get_num_inputs(scan_ctx.psbt, &d->num_inputs) != WALLY_OK ||
      wally_psbt_get_num_outputs(scan_ctx.psbt, &d->num_outputs) != WALLY_OK ||
      d->num_inputs == 0 || d->num_outputs == 0)
    return false;

  d->inputs = calloc(d->num_inputs, sizeof(*d->inputs));
  d->outputs = calloc(d->num_outputs, sizeof(*d->outputs));
  if (!d->inputs || !d->outputs)
    goto fail;

  psbt_audit_input_amounts(scan_ctx.psbt, &d->amount_audit);

  for (size_t i = 0; i < d->num_inputs; i++) {
    classified_input_t *in = &d->inputs[i];
    in->index = i;
    in->value = psbt_get_input_value(scan_ctx.psbt, i);
    d->total_input += in->value;

    input_ownership_t own =
        psbt_classify_input(scan_ctx.psbt, i, scan_ctx.is_testnet);
    in->ownership = own.ownership;
    format_input_policy(&own, in->policy, sizeof(in->policy));
    if ((own.ownership == PSBT_OWNERSHIP_OWNED_UNSAFE ||
         own.ownership == PSBT_OWNERSHIP_EXPECTED_OWNED) &&
        !psbt_format_keypath(own.raw_keypath, own.raw_keypath_len, in->path,
                             sizeof(in->path)))
      in->path[0] = '\0'; // renders no path line

    /* Only external inputs show their address, in the co-signing warning. */
    if (own.ownership == PSBT_OWNERSHIP_EXTERNAL) {
      d->external_inputs++;
      unsigned char spk[34];
      size_t spk_len = 0;
      if (psbt_input_utxo_script(scan_ctx.psbt, i, spk, sizeof(spk), &spk_len))
        in->address =
            psbt_scriptpubkey_to_address(spk, spk_len, scan_ctx.is_testnet);
    }
  }

  struct wally_tx *tx = psbt_tx_alloc(scan_ctx.psbt);
  if (!tx)
    goto fail;

  /* BIP-125 opts a transaction into replaceability when any input's sequence
   * is below 0xfffffffe. */
  d->locktime = tx->locktime;
  for (size_t i = 0; i < tx->num_inputs; i++)
    if (tx->inputs[i].sequence < 0xfffffffeu)
      d->signals_rbf = true;

  for (size_t i = 0; i < d->num_outputs; i++) {
    classified_output_t *out = &d->outputs[i];
    const struct wally_tx_output *txo = &tx->outputs[i];
    out->index = i;
    out->value = txo->satoshi;
    d->total_output += out->value;
    out->address = psbt_scriptpubkey_to_address(txo->script, txo->script_len,
                                                scan_ctx.is_testnet);
    out->type =
        classify_output(i, &out->address_index, out->path, sizeof(out->path));
    out->is_dust =
        out->value < psbt_output_dust_threshold(txo->script, txo->script_len);
    if (out->is_dust) {
      if (!d->dust_count) {
        d->first_dust = i;
        d->first_dust_value = out->value;
      }
      d->dust_count++;
    }
  }
  wally_tx_free(tx);

  d->fee =
      d->total_input > d->total_output ? d->total_input - d->total_output : 0;
  return true;

fail:
  review_data_free(d);
  return false;
}

/* ---------- widgets shared by the sections ---------- */

static lv_obj_t *section_title(lv_obj_t *parent, const char *text,
                               lv_color_t color, bool spaced) {
  lv_obj_t *title = theme_create_label(parent, text, false);
  theme_apply_label(title, true);
  lv_obj_set_style_text_color(title, color, 0);
  if (spaced)
    lv_obj_set_style_margin_top(title, 15, 0);
  lv_obj_set_width(title, LV_PCT(100));
  return title;
}

static void indented_amount_row(lv_obj_t *parent, const char *prefix,
                                uint64_t sats) {
  lv_obj_t *row =
      scan_create_btc_value_row(parent, prefix, sats, primary_color());
  lv_obj_set_width(row, LV_PCT(100));
  lv_obj_set_style_pad_left(row, 20, 0);
}

static lv_color_t output_type_color(output_type_t type) {
  switch (type) {
  case OUTPUT_TYPE_CHANGE:
    return good_color();
  case OUTPUT_TYPE_EXPECTED_OWNED:
    return error_color();
  case OUTPUT_TYPE_SPEND:
    return highlight_color();
  case OUTPUT_TYPE_SELF_TRANSFER:
  case OUTPUT_TYPE_OWNED_UNSAFE:
  default:
    return accent_color();
  }
}

/* ---------- diagram ---------- */

static bool render_diagram(lv_obj_t *parent, const review_data_t *d) {
  size_t diagram_outputs = d->num_outputs + (d->fee > 0 ? 1 : 0);
  uint64_t *in_amounts = malloc(d->num_inputs * sizeof(uint64_t));
  lv_color_t *in_colors = malloc(d->num_inputs * sizeof(lv_color_t));
  uint64_t *out_amounts = malloc(diagram_outputs * sizeof(uint64_t));
  lv_color_t *out_colors = malloc(diagram_outputs * sizeof(lv_color_t));
  if (!in_amounts || !in_colors || !out_amounts || !out_colors) {
    free(in_amounts);
    free(in_colors);
    free(out_amounts);
    free(out_colors);
    return false;
  }

  for (size_t i = 0; i < d->num_inputs; i++) {
    in_amounts[i] = d->inputs[i].value;
    in_colors[i] = d->inputs[i].ownership == PSBT_OWNERSHIP_EXTERNAL
                       ? error_color()
                       : primary_color();
  }

  /* Outputs are grouped by kind in the order the sections below use. */
  static const output_type_t order[] = {
      OUTPUT_TYPE_SELF_TRANSFER, OUTPUT_TYPE_CHANGE, OUTPUT_TYPE_OWNED_UNSAFE,
      OUTPUT_TYPE_EXPECTED_OWNED, OUTPUT_TYPE_SPEND};
  size_t idx = 0;
  for (size_t t = 0; t < sizeof(order) / sizeof(order[0]); t++) {
    for (size_t i = 0; i < d->num_outputs; i++) {
      if (d->outputs[i].type != order[t])
        continue;
      out_amounts[idx] = d->outputs[i].value;
      out_colors[idx] = output_type_color(order[t]);
      idx++;
    }
  }
  if (d->fee > 0) {
    out_amounts[idx] = d->fee;
    out_colors[idx] = error_color();
  }

  lv_obj_update_layout(parent);
  int32_t diagram_width = lv_obj_get_width(scan_ctx.screen) - 20;
  int32_t diagram_height = lv_obj_get_height(scan_ctx.screen) / 4;
  scan_ctx.tx_diagram =
      sankey_diagram_create(parent, diagram_width, diagram_height);
  if (scan_ctx.tx_diagram) {
    sankey_diagram_set_inputs(scan_ctx.tx_diagram, in_amounts, d->num_inputs,
                              in_colors);
    sankey_diagram_set_outputs(scan_ctx.tx_diagram, out_amounts,
                               diagram_outputs, out_colors);
    sankey_diagram_render(scan_ctx.tx_diagram);
  }
  free(in_amounts);
  free(in_colors);
  free(out_amounts);
  free(out_colors);

  size_t input_overflow =
      sankey_diagram_get_input_overflow(scan_ctx.tx_diagram);
  size_t output_overflow =
      sankey_diagram_get_output_overflow(scan_ctx.tx_diagram);
  if (input_overflow == 0 && output_overflow == 0)
    return true;

  lv_obj_t *overflow_row = lv_obj_create(parent);
  lv_obj_set_size(overflow_row, LV_PCT(100), LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(overflow_row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(overflow_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(overflow_row, 0, 0);
  lv_obj_set_style_bg_opa(overflow_row, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(overflow_row, 0, 0);

  if (input_overflow > 0) {
    char overflow_text[32];
    snprintf(overflow_text, sizeof(overflow_text), "+%zu more", input_overflow);
    lv_obj_t *label = theme_create_label(overflow_row, overflow_text, false);
    lv_obj_set_style_text_color(label, secondary_color(), 0);
  } else {
    lv_obj_t *spacer = lv_obj_create(overflow_row);
    lv_obj_set_size(spacer, 1, 1);
    lv_obj_set_style_bg_opa(spacer, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(spacer, 0, 0);
  }

  if (output_overflow > 0) {
    char overflow_text[32];
    snprintf(overflow_text, sizeof(overflow_text), "+%zu more",
             output_overflow);
    lv_obj_t *label = theme_create_label(overflow_row, overflow_text, false);
    lv_obj_set_style_text_color(label, secondary_color(), 0);
  }
  return true;
}

/* ---------- input sections ---------- */

/* One "Inputs(N): <amount> from <policy>" row per distinct signing policy of
 * the owned-safe inputs. The other ownership classes get their own warning
 * sections below, which already carry count, amount and path or address. */
static void render_input_policy_rows(lv_obj_t *parent, const review_data_t *d) {
  for (size_t i = 0; i < d->num_inputs; i++) {
    const char *policy = d->inputs[i].policy;
    if (policy[0] == '\0')
      continue;

    bool already = false;
    for (size_t j = 0; j < i; j++) {
      if (strcmp(d->inputs[j].policy, policy) == 0) {
        already = true;
        break;
      }
    }
    if (already)
      continue;

    size_t count = 0;
    uint64_t total = 0;
    for (size_t k = i; k < d->num_inputs; k++) {
      if (strcmp(d->inputs[k].policy, policy) == 0) {
        count++;
        total += d->inputs[k].value;
      }
    }

    char prefix[32];
    snprintf(prefix, sizeof(prefix), "Inputs(%zu): ", count);
    lv_obj_t *row =
        scan_create_btc_value_row(parent, prefix, total, primary_color());
    lv_obj_set_width(row, LV_PCT(100));
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW_WRAP);

    lv_obj_t *src = lv_label_create(row);
    lv_label_set_text_fmt(src, " from %s", policy);
    lv_obj_set_style_text_font(src, theme_font_small(), 0);
    lv_obj_set_style_text_color(src, secondary_color(), 0);
    lv_label_set_long_mode(src, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_max_width(src, LV_PCT(100), 0);
  }
}

/* Owned inputs on a non-standard path collapse to a totals row when listing
 * them all would scroll-fatigue the review screen. */
static void render_nonstandard_inputs(lv_obj_t *parent,
                                      const review_data_t *d) {
  size_t count = 0;
  uint64_t total = 0;
  for (size_t i = 0; i < d->num_inputs; i++) {
    if (d->inputs[i].ownership == PSBT_OWNERSHIP_OWNED_UNSAFE) {
      count++;
      total += d->inputs[i].value;
    }
  }
  if (count == 0)
    return;

  if (count > NONSTANDARD_INPUT_INLINE_THRESHOLD) {
    char title[64];
    snprintf(title, sizeof(title),
             "Owned inputs, non-standard path (%zu): ", count);
    section_title(parent, title, accent_color(), true);
    indented_amount_row(parent, "Total: ", total);
    return;
  }

  section_title(parent, "Owned inputs (non-standard path): ", accent_color(),
                true);
  for (size_t i = 0; i < d->num_inputs; i++) {
    const classified_input_t *in = &d->inputs[i];
    if (in->ownership != PSBT_OWNERSHIP_OWNED_UNSAFE)
      continue;
    char text[128];
    snprintf(text, sizeof(text), "Input %zu (%s): ", in->index,
             in->path[0] ? in->path : "?");
    indented_amount_row(parent, text, in->value);
  }
}

static void render_expected_inputs(lv_obj_t *parent, const review_data_t *d) {
  bool titled = false;
  for (size_t i = 0; i < d->num_inputs; i++) {
    const classified_input_t *in = &d->inputs[i];
    if (in->ownership != PSBT_OWNERSHIP_EXPECTED_OWNED)
      continue;
    if (!titled) {
      section_title(parent,
                    "Expected ownership inputs (UNVERIFIED): ", error_color(),
                    true);
      titled = true;
    }
    char text[128];
    snprintf(text, sizeof(text), "Input %zu (%s): ", in->index,
             in->path[0] ? in->path : "?");
    indented_amount_row(parent, text, in->value);
  }
}

/* The Partial-signing gate has already passed, but the user must still see
 * what they are co-signing: we sign our inputs only and leave externals to
 * whoever holds those keys. Each external input's amount and address is
 * shown so a forgery (an attacker slipping their own address in) stands out. */
static void render_external_inputs(lv_obj_t *parent, const review_data_t *d) {
  if (d->external_inputs == 0)
    return;

  lv_obj_t *title = section_title(
      parent,
      "External inputs (NOT YOURS) -- you are co-signing:", error_color(),
      true);
  lv_label_set_long_mode(title, LV_LABEL_LONG_WRAP);

  for (size_t i = 0; i < d->num_inputs; i++) {
    const classified_input_t *in = &d->inputs[i];
    if (in->ownership != PSBT_OWNERSHIP_EXTERNAL)
      continue;
    char text[64];
    snprintf(text, sizeof(text), "Input %zu: ", in->index);
    indented_amount_row(parent, text, in->value);
    if (in->address)
      scan_create_address_label(parent, in->address, error_color(),
                                ADDRESS_INDENT_PX);
  }
}

/* ---------- output sections ---------- */

/* Self-transfers collapse to a totals row past the inline threshold. */
static void render_self_transfers(lv_obj_t *parent, const review_data_t *d) {
  size_t count = 0;
  uint64_t total = 0;
  for (size_t i = 0; i < d->num_outputs; i++) {
    if (d->outputs[i].type == OUTPUT_TYPE_SELF_TRANSFER) {
      count++;
      total += d->outputs[i].value;
    }
  }
  if (count == 0)
    return;

  if (count > SELF_TRANSFER_INLINE_THRESHOLD) {
    char title[48];
    snprintf(title, sizeof(title), "Self-Transfer (%zu): ", count);
    section_title(parent, title, accent_color(), false);
    indented_amount_row(parent, "Total: ", total);
    return;
  }

  section_title(parent, "Self-Transfer: ", accent_color(), false);
  for (size_t i = 0; i < d->num_outputs; i++) {
    const classified_output_t *out = &d->outputs[i];
    if (out->type != OUTPUT_TYPE_SELF_TRANSFER)
      continue;
    char text[64];
    snprintf(text, sizeof(text), "Receive #%u: ", out->address_index);
    indented_amount_row(parent, text, out->value);
    if (out->address)
      scan_create_address_label(parent, out->address, accent_color(),
                                ADDRESS_INDENT_PX);
  }
}

/* Change is verified-owned (derive reproduces the spk on chain=1), so the
 * addresses need no review and a single total keeps the screen focused on
 * outgoing spends. Outputs that cannot be verified classify as EXPECTED_OWNED
 * and render in their own warning section. */
static void render_change(lv_obj_t *parent, const review_data_t *d) {
  uint64_t total = 0;
  size_t count = 0;
  for (size_t i = 0; i < d->num_outputs; i++) {
    if (d->outputs[i].type == OUTPUT_TYPE_CHANGE) {
      total += d->outputs[i].value;
      count++;
    }
  }
  if (count == 0)
    return;
  lv_obj_t *row =
      scan_create_btc_value_row(parent, "Change: ", total, good_color());
  lv_obj_set_width(row, LV_PCT(100));
  lv_obj_set_style_margin_top(row, 15, 0);
}

/* A titled list of every output of one kind: amount row plus address, with
 * the derivation path in the row label when the kind carries one. */
static void render_output_group(lv_obj_t *parent, const review_data_t *d,
                                output_type_t type, const char *title,
                                bool with_path) {
  lv_color_t color = output_type_color(type);
  bool titled = false;
  for (size_t i = 0; i < d->num_outputs; i++) {
    const classified_output_t *out = &d->outputs[i];
    if (out->type != type)
      continue;
    if (!titled) {
      section_title(parent, title, color, true);
      titled = true;
    }
    char text[128];
    if (with_path)
      snprintf(text, sizeof(text), "Output %zu (%s): ", out->index,
               out->path[0] ? out->path : "?");
    else
      snprintf(text, sizeof(text), "Output %zu: ", out->index);
    indented_amount_row(parent, text, out->value);
    if (out->address)
      scan_create_address_label(parent, out->address, color, ADDRESS_INDENT_PX);
  }
}

/* ---------- fee and notes ---------- */

static void render_fee_and_notes(lv_obj_t *parent, const review_data_t *d) {
  uint32_t fee_percent = psbt_fee_percent(d->fee, d->total_input);

  if (d->fee > 0) {
    theme_create_separator(parent, primary_color());

    lv_obj_t *fee_row =
        scan_create_btc_value_row(parent, "Fee: ", d->fee, error_color());
    lv_obj_set_width(fee_row, LV_PCT(100));
    lv_obj_set_flex_flow(fee_row, LV_FLEX_FLOW_ROW_WRAP);

    lv_obj_t *pct = lv_label_create(fee_row);
    lv_label_set_text_fmt(pct, "(%" PRIu32 "%% of inputs)", fee_percent);
    lv_obj_set_style_text_font(pct, theme_font_small(), 0);
    lv_obj_set_style_text_color(
        pct,
        fee_percent >= HIGH_FEE_PERCENT ? error_color() : secondary_color(), 0);

    /* A fee this large relative to what is being spent is nearly always a
     * mistake or an attack, and it is the one number a compromised coordinator
     * most wants slipped past the review. */
    if (fee_percent >= HIGH_FEE_PERCENT) {
      char note[128];
      snprintf(note, sizeof(note),
               LV_SYMBOL_WARNING " High fee: %" PRIu32
                                 "%% of the inputs is going to miners.",
               fee_percent);
      scan_create_review_note(parent, note, error_color());
    }
  }

  /* The fee is inputs minus outputs, and the outputs are committed to by the
   * sighash. The inputs are only as good as their proof, so say so here rather
   * than let the number read as verified. */
  if (!psbt_amounts_are_proven(&d->amount_audit)) {
    char note[160];
    snprintf(note, sizeof(note),
             LV_SYMBOL_WARNING " Unproven fee: %zu of %zu input amounts are "
                               "not backed by their previous transaction.",
             d->amount_audit.num_inputs - d->amount_audit.proven,
             d->amount_audit.num_inputs);
    scan_create_review_note(parent, note, highlight_color());
  }

  /* The gate refuses a PSBT whose outputs exceed the inputs, so reaching here
   * that way means an input never supplied an amount and was counted as zero.
   * The unproven-fee note above already says the numbers are not backed; name
   * the missing fee too, because no fee row at all otherwise reads as "no
   * fee". */
  if (d->total_output > d->total_input) {
    scan_create_review_note(parent,
                            LV_SYMBOL_WARNING
                            " Fee unknown: the outputs exceed the input "
                            "amounts this PSBT supplied.",
                            error_color());
  }

  /* Below the relay dust threshold an output costs more to spend than it
   * holds, so the transaction is unlikely to propagate at all. */
  if (d->dust_count) {
    char note[192];
    if (d->dust_count == 1)
      snprintf(note, sizeof(note),
               LV_SYMBOL_WARNING " Dust: output %zu holds only %llu sats, "
                                 "below the amount needed to relay.",
               d->first_dust, (unsigned long long)d->first_dust_value);
    else
      snprintf(note, sizeof(note),
               LV_SYMBOL_WARNING " Dust: %zu outputs are below the amount "
                                 "needed to relay.",
               d->dust_count);
    scan_create_review_note(parent, note, highlight_color());
  }

  /* Neither is visible anywhere else on this screen, and both change what
   * signing actually commits to: a future locktime is not broadcastable yet,
   * and an RBF-signalling transaction can be replaced before it confirms. */
  if (d->locktime) {
    char note[160];
    if (d->locktime < 500000000u)
      snprintf(note, sizeof(note),
               LV_SYMBOL_WARNING " Locked until block %" PRIu32
                                 ": not broadcastable before then.",
               d->locktime);
    else
      snprintf(note, sizeof(note),
               LV_SYMBOL_WARNING " Locked until unix time %" PRIu32
                                 ": not broadcastable before then.",
               d->locktime);
    scan_create_review_note(parent, note, highlight_color());
  }

  if (d->signals_rbf) {
    scan_create_review_note(parent,
                            LV_SYMBOL_WARNING
                            " Replaceable (RBF): this transaction can be "
                            "replaced by a different one before it confirms.",
                            secondary_color());
  }
}

static bool create_psbt_info_display(void) {
  if (!scan_ctx.screen || !scan_ctx.psbt || !wallet_is_initialized())
    return false;
  if (scan_psbt_check_mismatch())
    return true;

  review_data_t data;
  if (!review_data_collect(&data))
    return false;

  scan_ctx.info_container = theme_create_scroll_column(scan_ctx.screen, 10, 10);
  lv_obj_t *c = scan_ctx.info_container;

  if (!render_diagram(c, &data)) {
    review_data_free(&data);
    return false;
  }

  render_input_policy_rows(c, &data);
  render_nonstandard_inputs(c, &data);
  render_expected_inputs(c, &data);
  render_external_inputs(c, &data);

  lv_obj_t *separator = theme_create_separator(c, primary_color());
  lv_obj_set_style_margin_top(separator, 15, 0);

  render_self_transfers(c, &data);
  render_change(c, &data);
  render_output_group(c, &data, OUTPUT_TYPE_OWNED_UNSAFE,
                      "Owned (non-standard path): ", true);
  render_output_group(c, &data, OUTPUT_TYPE_EXPECTED_OWNED,
                      "Expected ownership (UNVERIFIED): ", true);
  render_output_group(c, &data, OUTPUT_TYPE_SPEND, "Spending: ", false);

  render_fee_and_notes(c, &data);
  review_data_free(&data);

  scan_create_sign_action_row(c, scan_psbt_sign_button_cb);
  return true;
}

void scan_psbt_cleanup(void) {
  if (scan_ctx.psbt) {
    wally_psbt_free(scan_ctx.psbt);
    scan_ctx.psbt = NULL;
  }

  if (scan_ctx.psbt_base64) {
    free(scan_ctx.psbt_base64);
    scan_ctx.psbt_base64 = NULL;
  }

  if (scan_ctx.signed_psbt_base64) {
    wally_free_string(scan_ctx.signed_psbt_base64);
    scan_ctx.signed_psbt_base64 = NULL;
  }

  message_sign_free_parsed(&scan_ctx.message);
  scan_ctx.is_message_sign = false;

  bip322_request_free(&scan_ctx.bip322);
  scan_ctx.is_bip322 = false;

  scan_ctx.is_testnet = false;
  scan_ctx.qr_format = FORMAT_NONE;
}
