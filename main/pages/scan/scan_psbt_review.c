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

static bool create_psbt_info_display(void) {
  if (!scan_ctx.screen || !scan_ctx.psbt || !wallet_is_initialized()) {
    return false;
  }

  if (scan_psbt_check_mismatch()) {
    return true;
  }

  size_t num_inputs = 0;
  size_t num_outputs = 0;

  if (wally_psbt_get_num_inputs(scan_ctx.psbt, &num_inputs) != WALLY_OK ||
      wally_psbt_get_num_outputs(scan_ctx.psbt, &num_outputs) != WALLY_OK) {
    return false;
  }

  if (num_inputs == 0 || num_outputs == 0) {
    return false;
  }

  uint64_t *input_amounts = malloc(num_inputs * sizeof(uint64_t));
  if (!input_amounts) {
    return false;
  }
  lv_color_t *input_colors = malloc(num_inputs * sizeof(lv_color_t));
  if (!input_colors) {
    free(input_amounts);
    return false;
  }
  classified_input_t *classified_inputs =
      calloc(num_inputs, sizeof(classified_input_t));
  if (!classified_inputs) {
    free(input_colors);
    free(input_amounts);
    return false;
  }
  psbt_amount_audit_t amount_audit;
  psbt_audit_input_amounts(scan_ctx.psbt, &amount_audit);

  uint64_t total_input_value = 0;
  size_t external_input_count = 0;
  for (size_t i = 0; i < num_inputs; i++) {
    input_amounts[i] = psbt_get_input_value(scan_ctx.psbt, i);
    total_input_value += input_amounts[i];

    input_ownership_t own =
        psbt_classify_input(scan_ctx.psbt, i, scan_ctx.is_testnet);
    classified_inputs[i].index = i;
    classified_inputs[i].ownership = own.ownership;
    classified_inputs[i].value = input_amounts[i];
    input_colors[i] = (own.ownership == PSBT_OWNERSHIP_EXTERNAL)
                          ? error_color()
                          : primary_color();
    format_input_policy(&own, classified_inputs[i].policy,
                        sizeof(classified_inputs[i].policy));
    classified_inputs[i].path[0] = '\0';
    if ((own.ownership == PSBT_OWNERSHIP_OWNED_UNSAFE ||
         own.ownership == PSBT_OWNERSHIP_EXPECTED_OWNED) &&
        !psbt_format_keypath(own.raw_keypath, own.raw_keypath_len,
                             classified_inputs[i].path,
                             sizeof(classified_inputs[i].path)))
      classified_inputs[i].path[0] = '\0'; // renders no path line

    /* External inputs need their address rendered in the warning section.
     * Skip address decoding for owned inputs — they're not displayed. */
    if (own.ownership == PSBT_OWNERSHIP_EXTERNAL) {
      external_input_count++;
      unsigned char spk[34];
      size_t spk_len = 0;
      if (psbt_input_utxo_script(scan_ctx.psbt, i, spk, sizeof(spk),
                                 &spk_len)) {
        classified_inputs[i].address =
            psbt_scriptpubkey_to_address(spk, spk_len, scan_ctx.is_testnet);
      }
    }
  }

  struct wally_tx *global_tx = psbt_tx_alloc(scan_ctx.psbt);
  if (!global_tx) {
    for (size_t i = 0; i < num_inputs; i++)
      free(classified_inputs[i].address);
    free(classified_inputs);
    free(input_colors);
    free(input_amounts);
    return false;
  }

  classified_output_t *classified_outputs =
      calloc(num_outputs, sizeof(classified_output_t));
  if (!classified_outputs) {
    for (size_t i = 0; i < num_inputs; i++)
      free(classified_inputs[i].address);
    free(classified_inputs);
    free(input_colors);
    free(input_amounts);
    wally_tx_free(global_tx);
    return false;
  }

  uint64_t total_output_value = 0;
  for (size_t i = 0; i < num_outputs; i++) {
    total_output_value += global_tx->outputs[i].satoshi;
  }

  /* Both are read off the global tx, which is freed before the notes are
   * rendered. BIP-125 opts a transaction into replaceability when any input's
   * sequence is below 0xfffffffe. */
  uint32_t locktime = global_tx->locktime;
  bool signals_rbf = false;
  for (size_t i = 0; i < global_tx->num_inputs; i++) {
    if (global_tx->inputs[i].sequence < 0xfffffffeu)
      signals_rbf = true;
  }
  uint64_t fee = (total_input_value > total_output_value)
                     ? (total_input_value - total_output_value)
                     : 0;

  size_t diagram_output_count = num_outputs + (fee > 0 ? 1 : 0);
  uint64_t *output_amounts = malloc(diagram_output_count * sizeof(uint64_t));
  lv_color_t *output_colors = malloc(diagram_output_count * sizeof(lv_color_t));
  if (!output_amounts || !output_colors) {
    for (size_t i = 0; i < num_inputs; i++)
      free(classified_inputs[i].address);
    free(classified_inputs);
    free(input_colors);
    free(input_amounts);
    free(output_amounts);
    free(output_colors);
    free(classified_outputs);
    wally_tx_free(global_tx);
    return false;
  }

  for (size_t i = 0; i < num_outputs; i++) {
    classified_outputs[i].index = i;
    classified_outputs[i].value = global_tx->outputs[i].satoshi;
    classified_outputs[i].address = psbt_scriptpubkey_to_address(
        global_tx->outputs[i].script, global_tx->outputs[i].script_len,
        scan_ctx.is_testnet);
    classified_outputs[i].path[0] = '\0';
    classified_outputs[i].type = classify_output(
        i, &classified_outputs[i].address_index, classified_outputs[i].path,
        sizeof(classified_outputs[i].path));
    classified_outputs[i].is_dust =
        classified_outputs[i].value <
        psbt_output_dust_threshold(global_tx->outputs[i].script,
                                   global_tx->outputs[i].script_len);
  }

  size_t diagram_idx = 0;

  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_SELF_TRANSFER) {
      output_amounts[diagram_idx] = classified_outputs[i].value;
      output_colors[diagram_idx] = accent_color();
      diagram_idx++;
    }
  }

  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_CHANGE) {
      output_amounts[diagram_idx] = classified_outputs[i].value;
      output_colors[diagram_idx] = good_color();
      diagram_idx++;
    }
  }

  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_OWNED_UNSAFE) {
      output_amounts[diagram_idx] = classified_outputs[i].value;
      output_colors[diagram_idx] = accent_color();
      diagram_idx++;
    }
  }

  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_EXPECTED_OWNED) {
      output_amounts[diagram_idx] = classified_outputs[i].value;
      output_colors[diagram_idx] = error_color();
      diagram_idx++;
    }
  }

  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_SPEND) {
      output_amounts[diagram_idx] = classified_outputs[i].value;
      output_colors[diagram_idx] = highlight_color();
      diagram_idx++;
    }
  }

  if (fee > 0) {
    output_amounts[diagram_idx] = fee;
    output_colors[diagram_idx] = error_color();
  }

  scan_ctx.info_container = theme_create_scroll_column(scan_ctx.screen, 10, 10);

  lv_obj_update_layout(scan_ctx.info_container);
  int32_t diagram_width = lv_obj_get_width(scan_ctx.screen) - 20;
  int32_t diagram_height = lv_obj_get_height(scan_ctx.screen) / 4;
  scan_ctx.tx_diagram = sankey_diagram_create(scan_ctx.info_container,
                                              diagram_width, diagram_height);
  if (scan_ctx.tx_diagram) {
    sankey_diagram_set_inputs(scan_ctx.tx_diagram, input_amounts, num_inputs,
                              input_colors);
    sankey_diagram_set_outputs(scan_ctx.tx_diagram, output_amounts,
                               diagram_output_count, output_colors);
    sankey_diagram_render(scan_ctx.tx_diagram);
  }

  size_t input_overflow =
      sankey_diagram_get_input_overflow(scan_ctx.tx_diagram);
  size_t output_overflow =
      sankey_diagram_get_output_overflow(scan_ctx.tx_diagram);

  if (input_overflow > 0 || output_overflow > 0) {
    lv_obj_t *overflow_row = lv_obj_create(scan_ctx.info_container);
    lv_obj_set_size(overflow_row, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(overflow_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(overflow_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(overflow_row, 0, 0);
    lv_obj_set_style_bg_opa(overflow_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(overflow_row, 0, 0);

    if (input_overflow > 0) {
      char overflow_text[32];
      snprintf(overflow_text, sizeof(overflow_text), "+%zu more",
               input_overflow);
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
  }

  free(input_amounts);
  free(input_colors);
  free(output_amounts);
  free(output_colors);

  /* Group owned-safe inputs by their signing policy and render one
   * "Inputs(N): <amount> from <policy>" row per distinct source.
   * UNSAFE / EXPECTED / External inputs keep their dedicated warning
   * sections below — those carry the count + amount + path/address
   * inline so they don't need a top-level breakdown. */
  for (size_t i = 0; i < num_inputs; i++) {
    const char *policy = classified_inputs[i].policy;
    if (policy[0] == '\0')
      continue;

    bool already = false;
    for (size_t j = 0; j < i; j++) {
      if (strcmp(classified_inputs[j].policy, policy) == 0) {
        already = true;
        break;
      }
    }
    if (already)
      continue;

    size_t count = 0;
    uint64_t total = 0;
    for (size_t k = i; k < num_inputs; k++) {
      if (strcmp(classified_inputs[k].policy, policy) == 0) {
        count++;
        total += classified_inputs[k].value;
      }
    }

    char prefix[32];
    snprintf(prefix, sizeof(prefix), "Inputs(%zu): ", count);
    lv_obj_t *row = scan_create_btc_value_row(scan_ctx.info_container, prefix,
                                              total, primary_color());
    lv_obj_set_width(row, LV_PCT(100));
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW_WRAP);

    lv_obj_t *src = lv_label_create(row);
    lv_label_set_text_fmt(src, " from %s", policy);
    lv_obj_set_style_text_font(src, theme_font_small(), 0);
    lv_obj_set_style_text_color(src, secondary_color(), 0);
    lv_label_set_long_mode(src, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_max_width(src, LV_PCT(100), 0);
  }
  (void)total_input_value; /* now distributed across per-policy rows */

  /* Count non-standard owned inputs up-front so we can collapse to a
   * totals row when the list would scroll-fatigue the review screen. */
#define NONSTANDARD_INPUT_INLINE_THRESHOLD 4
  size_t unsafe_input_count = 0;
  uint64_t total_unsafe_input = 0;
  for (size_t i = 0; i < num_inputs; i++) {
    if (classified_inputs[i].ownership == PSBT_OWNERSHIP_OWNED_UNSAFE) {
      unsafe_input_count++;
      total_unsafe_input += classified_inputs[i].value;
    }
  }

  if (unsafe_input_count > NONSTANDARD_INPUT_INLINE_THRESHOLD) {
    char title_text[64];
    snprintf(title_text, sizeof(title_text),
             "Owned inputs, non-standard path (%zu): ", unsafe_input_count);
    lv_obj_t *title =
        theme_create_label(scan_ctx.info_container, title_text, false);
    theme_apply_label(title, true);
    lv_obj_set_style_text_color(title, accent_color(), 0);
    lv_obj_set_style_margin_top(title, 15, 0);
    lv_obj_set_width(title, LV_PCT(100));

    lv_obj_t *row = scan_create_btc_value_row(scan_ctx.info_container,
                                              "Total: ", total_unsafe_input,
                                              primary_color());
    lv_obj_set_width(row, LV_PCT(100));
    lv_obj_set_style_pad_left(row, 20, 0);
  } else if (unsafe_input_count > 0) {
    lv_obj_t *title = theme_create_label(
        scan_ctx.info_container, "Owned inputs (non-standard path): ", false);
    theme_apply_label(title, true);
    lv_obj_set_style_text_color(title, accent_color(), 0);
    lv_obj_set_style_margin_top(title, 15, 0);
    lv_obj_set_width(title, LV_PCT(100));

    for (size_t i = 0; i < num_inputs; i++) {
      if (classified_inputs[i].ownership != PSBT_OWNERSHIP_OWNED_UNSAFE)
        continue;
      char text[128];
      snprintf(text, sizeof(text),
               "Input %zu (%s): ", classified_inputs[i].index,
               classified_inputs[i].path[0] ? classified_inputs[i].path : "?");
      lv_obj_t *row = scan_create_btc_value_row(scan_ctx.info_container, text,
                                                classified_inputs[i].value,
                                                primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);
    }
  }

  bool has_expected_inputs = false;
  for (size_t i = 0; i < num_inputs; i++) {
    if (classified_inputs[i].ownership != PSBT_OWNERSHIP_EXPECTED_OWNED)
      continue;
    if (!has_expected_inputs) {
      lv_obj_t *title =
          theme_create_label(scan_ctx.info_container,
                             "Expected ownership inputs (UNVERIFIED): ", false);
      theme_apply_label(title, true);
      lv_obj_set_style_text_color(title, error_color(), 0);
      lv_obj_set_style_margin_top(title, 15, 0);
      lv_obj_set_width(title, LV_PCT(100));
      has_expected_inputs = true;
    }

    char text[128];
    snprintf(text, sizeof(text), "Input %zu (%s): ", classified_inputs[i].index,
             classified_inputs[i].path[0] ? classified_inputs[i].path : "?");
    lv_obj_t *row =
        scan_create_btc_value_row(scan_ctx.info_container, text,
                                  classified_inputs[i].value, primary_color());
    lv_obj_set_width(row, LV_PCT(100));
    lv_obj_set_style_pad_left(row, 20, 0);
  }

  /* External inputs warning section. The Partial-signing gate has already
   * passed (otherwise we wouldn't reach the review screen with externals
   * present), but the user must still see what they're co-signing — we
   * sign our inputs only, leaving externals to whoever holds those keys.
   * Render each external input's amount + address so the user can spot a
   * forgery (an attacker tricking us into co-signing their address). */
  if (external_input_count > 0) {
    lv_obj_t *warn_title = theme_create_label(
        scan_ctx.info_container,
        "External inputs (NOT YOURS) -- you are co-signing:", false);
    theme_apply_label(warn_title, true);
    lv_obj_set_style_text_color(warn_title, error_color(), 0);
    lv_obj_set_style_margin_top(warn_title, 15, 0);
    lv_obj_set_width(warn_title, LV_PCT(100));
    lv_label_set_long_mode(warn_title, LV_LABEL_LONG_WRAP);

    for (size_t i = 0; i < num_inputs; i++) {
      if (classified_inputs[i].ownership != PSBT_OWNERSHIP_EXTERNAL)
        continue;
      char text[64];
      snprintf(text, sizeof(text), "Input %zu: ", classified_inputs[i].index);
      lv_obj_t *row = scan_create_btc_value_row(scan_ctx.info_container, text,
                                                classified_inputs[i].value,
                                                primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_inputs[i].address) {
        scan_create_address_label(scan_ctx.info_container,
                                  classified_inputs[i].address, error_color(),
                                  ADDRESS_INDENT_PX);
      }
    }
  }

  lv_obj_t *separator1 =
      theme_create_separator(scan_ctx.info_container, primary_color());
  lv_obj_set_style_margin_top(separator1, 15, 0);

  /* Count self-transfers up-front so we can collapse to a totals row when
   * the list would otherwise scroll-fatigue the review screen. */
#define SELF_TRANSFER_INLINE_THRESHOLD 4
  size_t self_transfer_count = 0;
  uint64_t total_self_transfer = 0;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_SELF_TRANSFER) {
      self_transfer_count++;
      total_self_transfer += classified_outputs[i].value;
    }
  }

  if (self_transfer_count > SELF_TRANSFER_INLINE_THRESHOLD) {
    char title_text[48];
    snprintf(title_text, sizeof(title_text),
             "Self-Transfer (%zu): ", self_transfer_count);
    lv_obj_t *title =
        theme_create_label(scan_ctx.info_container, title_text, false);
    theme_apply_label(title, true);
    lv_obj_set_style_text_color(title, accent_color(), 0);
    lv_obj_set_width(title, LV_PCT(100));

    lv_obj_t *row = scan_create_btc_value_row(scan_ctx.info_container,
                                              "Total: ", total_self_transfer,
                                              primary_color());
    lv_obj_set_width(row, LV_PCT(100));
    lv_obj_set_style_pad_left(row, 20, 0);
  } else if (self_transfer_count > 0) {
    lv_obj_t *title =
        theme_create_label(scan_ctx.info_container, "Self-Transfer: ", false);
    theme_apply_label(title, true);
    lv_obj_set_style_text_color(title, accent_color(), 0);
    lv_obj_set_width(title, LV_PCT(100));

    for (size_t i = 0; i < num_outputs; i++) {
      if (classified_outputs[i].type != OUTPUT_TYPE_SELF_TRANSFER)
        continue;

      char text[64];
      snprintf(text, sizeof(text),
               "Receive #%u: ", classified_outputs[i].address_index);
      lv_obj_t *row = scan_create_btc_value_row(scan_ctx.info_container, text,
                                                classified_outputs[i].value,
                                                primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        scan_create_address_label(scan_ctx.info_container,
                                  classified_outputs[i].address, accent_color(),
                                  ADDRESS_INDENT_PX);
      }
    }
  }

  /* Change is verified-owned (derive reproduces the spk on chain=1); the
   * specific addresses don't need user review. Collapse to a single total
   * row so the review screen stays focused on outgoing spends. Outputs we
   * can't verify (fp matches but derive fails) classify as
   * EXPECTED_OWNED, not CHANGE, and render in their own warning section. */
  uint64_t total_change = 0;
  size_t change_count = 0;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_CHANGE) {
      total_change += classified_outputs[i].value;
      change_count++;
    }
  }
  if (change_count > 0) {
    lv_obj_t *row = scan_create_btc_value_row(
        scan_ctx.info_container, "Change: ", total_change, good_color());
    lv_obj_set_width(row, LV_PCT(100));
    lv_obj_set_style_margin_top(row, 15, 0);
  }

  bool has_owned_unsafe = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_OWNED_UNSAFE) {
      if (!has_owned_unsafe) {
        lv_obj_t *title = theme_create_label(
            scan_ctx.info_container, "Owned (non-standard path): ", false);
        theme_apply_label(title, true);
        lv_obj_set_style_text_color(title, accent_color(), 0);
        lv_obj_set_style_margin_top(title, 15, 0);
        lv_obj_set_width(title, LV_PCT(100));
        has_owned_unsafe = true;
      }

      char text[128];
      snprintf(
          text, sizeof(text), "Output %zu (%s): ", classified_outputs[i].index,
          classified_outputs[i].path[0] ? classified_outputs[i].path : "?");
      lv_obj_t *row = scan_create_btc_value_row(scan_ctx.info_container, text,
                                                classified_outputs[i].value,
                                                primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        scan_create_address_label(scan_ctx.info_container,
                                  classified_outputs[i].address, accent_color(),
                                  ADDRESS_INDENT_PX);
      }
    }
  }

  bool has_expected = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_EXPECTED_OWNED) {
      if (!has_expected) {
        lv_obj_t *title =
            theme_create_label(scan_ctx.info_container,
                               "Expected ownership (UNVERIFIED): ", false);
        theme_apply_label(title, true);
        lv_obj_set_style_text_color(title, error_color(), 0);
        lv_obj_set_style_margin_top(title, 15, 0);
        lv_obj_set_width(title, LV_PCT(100));
        has_expected = true;
      }

      char text[128];
      snprintf(
          text, sizeof(text), "Output %zu (%s): ", classified_outputs[i].index,
          classified_outputs[i].path[0] ? classified_outputs[i].path : "?");
      lv_obj_t *row = scan_create_btc_value_row(scan_ctx.info_container, text,
                                                classified_outputs[i].value,
                                                primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        scan_create_address_label(scan_ctx.info_container,
                                  classified_outputs[i].address, error_color(),
                                  ADDRESS_INDENT_PX);
      }
    }
  }

  bool has_spends = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_SPEND) {
      if (!has_spends) {
        lv_obj_t *title =
            theme_create_label(scan_ctx.info_container, "Spending: ", false);
        theme_apply_label(title, true);
        lv_obj_set_style_text_color(title, highlight_color(), 0);
        lv_obj_set_style_margin_top(title, 15, 0);
        lv_obj_set_width(title, LV_PCT(100));
        has_spends = true;
      }

      char text[64];
      snprintf(text, sizeof(text), "Output %zu: ", classified_outputs[i].index);
      lv_obj_t *row = scan_create_btc_value_row(scan_ctx.info_container, text,
                                                classified_outputs[i].value,
                                                primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        scan_create_address_label(scan_ctx.info_container,
                                  classified_outputs[i].address,
                                  highlight_color(), ADDRESS_INDENT_PX);
      }
    }
  }

  size_t dust_count = 0;
  size_t first_dust = 0;
  uint64_t first_dust_value = 0;
  for (size_t i = 0; i < num_outputs; i++) {
    if (!classified_outputs[i].is_dust)
      continue;
    if (!dust_count) {
      first_dust = classified_outputs[i].index;
      first_dust_value = classified_outputs[i].value;
    }
    dust_count++;
  }

  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].address) {
      if (strcmp(classified_outputs[i].address, "OP_RETURN") == 0) {
        free(classified_outputs[i].address);
      } else {
        wally_free_string(classified_outputs[i].address);
      }
    }
  }
  free(classified_outputs);

  for (size_t i = 0; i < num_inputs; i++) {
    if (classified_inputs[i].address) {
      if (strcmp(classified_inputs[i].address, "OP_RETURN") == 0)
        free(classified_inputs[i].address);
      else
        wally_free_string(classified_inputs[i].address);
    }
  }
  free(classified_inputs);

  if (global_tx) {
    wally_tx_free(global_tx);
    global_tx = NULL;
  }

  uint32_t fee_percent = psbt_fee_percent(fee, total_input_value);

  if (fee > 0) {
    theme_create_separator(scan_ctx.info_container, primary_color());

    lv_obj_t *fee_row = scan_create_btc_value_row(scan_ctx.info_container,
                                                  "Fee: ", fee, error_color());
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
      scan_create_review_note(scan_ctx.info_container, note, error_color());
    }
  }

  /* The fee is inputs minus outputs, and the outputs are committed to by the
   * sighash. The inputs are only as good as their proof, so say so here rather
   * than let the number read as verified. */
  if (!psbt_amounts_are_proven(&amount_audit)) {
    char note[160];
    snprintf(note, sizeof(note),
             LV_SYMBOL_WARNING " Unproven fee: %zu of %zu input amounts are "
                               "not backed by their previous transaction.",
             amount_audit.num_inputs - amount_audit.proven,
             amount_audit.num_inputs);
    scan_create_review_note(scan_ctx.info_container, note, highlight_color());
  }

  /* The gate refuses a PSBT whose outputs exceed the inputs, so reaching here
   * that way means an input never supplied an amount and was counted as zero.
   * The unproven-fee note above already says the numbers are not backed; name
   * the missing fee too, because no fee row at all otherwise reads as "no
   * fee". */
  if (total_output_value > total_input_value) {
    scan_create_review_note(
        scan_ctx.info_container,
        LV_SYMBOL_WARNING " Fee unknown: the outputs exceed the input amounts "
                          "this PSBT supplied.",
        error_color());
  }

  /* Below the relay dust threshold an output costs more to spend than it
   * holds, so the transaction is unlikely to propagate at all. */
  if (dust_count) {
    char note[192];
    if (dust_count == 1)
      snprintf(note, sizeof(note),
               LV_SYMBOL_WARNING " Dust: output %zu holds only %llu sats, "
                                 "below the amount needed to relay.",
               first_dust, (unsigned long long)first_dust_value);
    else
      snprintf(note, sizeof(note),
               LV_SYMBOL_WARNING " Dust: %zu outputs are below the amount "
                                 "needed to relay.",
               dust_count);
    scan_create_review_note(scan_ctx.info_container, note, highlight_color());
  }

  /* Neither is visible anywhere else on this screen, and both change what
   * signing actually commits to: a future locktime is not broadcastable yet,
   * and an RBF-signalling transaction can be replaced before it confirms. */
  if (locktime) {
    char note[160];
    if (locktime < 500000000u)
      snprintf(note, sizeof(note),
               LV_SYMBOL_WARNING " Locked until block %" PRIu32
                                 ": not broadcastable before then.",
               locktime);
    else
      snprintf(note, sizeof(note),
               LV_SYMBOL_WARNING " Locked until unix time %" PRIu32
                                 ": not broadcastable before then.",
               locktime);
    scan_create_review_note(scan_ctx.info_container, note, highlight_color());
  }

  if (signals_rbf) {
    scan_create_review_note(
        scan_ctx.info_container,
        LV_SYMBOL_WARNING
        " Replaceable (RBF): this transaction can be replaced "
        "by a different one before it confirms.",
        secondary_color());
  }

  scan_create_sign_action_row(scan_ctx.info_container,
                              scan_psbt_sign_button_cb);

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
