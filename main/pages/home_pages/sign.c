/*
 * Sign Page
 * Handles PSBT transaction signing
 */

#include "sign.h"
#include "../../../components/cUR/src/types/psbt.h"
#include "../../key/key.h"
#include "../../psbt/psbt.h"
#include "../../ui_components/flash_error.h"
#include "../../ui_components/info_dialog.h"
#include "../../ui_components/qr_viewer.h"
#include "../../ui_components/theme.h"
#include "../../utils/qr_codes.h"
#include "../../wallet/wallet.h"
#include "../qr_scanner.h"
#include <esp_log.h>
#include <lvgl.h>
#include <stdio.h>
#include <string.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

typedef enum {
  OUTPUT_TYPE_SELF_TRANSFER,
  OUTPUT_TYPE_CHANGE,
  OUTPUT_TYPE_SPEND,
} output_type_t;

typedef struct {
  size_t index;
  output_type_t type;
  uint64_t value;
  char *address;
  uint32_t address_index;
} classified_output_t;

// UI components
static lv_obj_t *sign_screen = NULL;
static lv_obj_t *psbt_info_container = NULL;
static void (*return_callback)(void) = NULL;
static void (*saved_return_callback)(void) = NULL;

// PSBT data
static struct wally_psbt *current_psbt = NULL;
static char *psbt_base64 = NULL;
static char *signed_psbt_base64 = NULL;
static bool is_testnet = false;
static int scanned_qr_format = FORMAT_NONE;

// Forward declarations
static void back_button_cb(lv_event_t *e);
static void return_from_qr_scanner_cb(void);
static bool parse_and_display_psbt(const char *base64_data);
static void cleanup_psbt_data(void);
static bool create_psbt_info_display(void);
static output_type_t classify_output(size_t output_index,
                                     const struct wally_tx_output *tx_output,
                                     uint32_t *address_index_out);
static void sign_button_cb(lv_event_t *e);
static void return_from_qr_viewer_cb(void);
static bool check_psbt_mismatch(void);
static void mismatch_dialog_cb(void *user_data);

// Classify output as self-transfer, change, or spend
static output_type_t classify_output(size_t output_index,
                                     const struct wally_tx_output *tx_output,
                                     uint32_t *address_index_out) {
  bool is_change = false;
  uint32_t address_index = 0;

  // Check if output has verified derivation path for our wallet
  if (!psbt_get_output_derivation(current_psbt, output_index, is_testnet,
                                  &is_change, &address_index)) {
    return OUTPUT_TYPE_SPEND;
  }

  // Verify scriptPubKey matches derived address
  unsigned char expected_script[WALLY_WITNESSSCRIPT_MAX_LEN];
  size_t expected_script_len;

  if (!wallet_get_scriptpubkey(is_change, address_index, expected_script,
                               &expected_script_len) ||
      tx_output->script_len != expected_script_len ||
      memcmp(tx_output->script, expected_script, expected_script_len) != 0) {
    return OUTPUT_TYPE_SPEND;
  }

  *address_index_out = address_index;
  return is_change ? OUTPUT_TYPE_CHANGE : OUTPUT_TYPE_SELF_TRANSFER;
}

static void back_button_cb(lv_event_t *e) {
  if (return_callback) {
    return_callback();
  }
}

static void return_from_qr_scanner_cb(void) {
  // Get the format first (before destroying scanner)
  int detected_format = qr_scanner_get_format();

  char *qr_content = NULL;
  size_t qr_content_len = 0;
  bool parse_success = false;

  if (detected_format == FORMAT_UR) {
    const char *ur_type = NULL;
    const uint8_t *cbor_data = NULL;
    size_t cbor_len = 0;

    if (qr_scanner_get_ur_result(&ur_type, &cbor_data, &cbor_len)) {
      // Decode PSBT from UR CBOR
      psbt_data_t *psbt_data = psbt_from_cbor(cbor_data, cbor_len);
      if (psbt_data) {
        // Get raw PSBT bytes and parse directly without base64 conversion
        size_t psbt_len;
        const uint8_t *psbt_bytes = psbt_get_data(psbt_data, &psbt_len);

        if (psbt_bytes) {
          cleanup_psbt_data();
          parse_success = (wally_psbt_from_bytes(psbt_bytes, psbt_len, 0,
                                                 &current_psbt) == WALLY_OK);
        }
        psbt_free(psbt_data);
      }
    }
  } else if (detected_format == FORMAT_BBQR) {
    // BBQr returns raw binary PSBT data - parse directly without base64
    // conversion
    qr_content = qr_scanner_get_completed_content_with_len(&qr_content_len);
    if (qr_content && qr_content_len > 0) {
      cleanup_psbt_data();
      parse_success =
          (wally_psbt_from_bytes((const uint8_t *)qr_content, qr_content_len, 0,
                                 &current_psbt) == WALLY_OK);
      free(qr_content);
    }
  } else {
    // Other formats (PMOFN, NONE) return base64 encoded data
    qr_content = qr_scanner_get_completed_content();
    if (qr_content) {
      parse_success = parse_and_display_psbt(qr_content);
      free(qr_content);
    }
  }

  qr_scanner_page_hide();
  qr_scanner_page_destroy();

  if (parse_success) {
    scanned_qr_format = detected_format;
    if (!create_psbt_info_display()) {
      show_flash_error("Invalid PSBT data", return_callback, 0);
    }
  } else {
    show_flash_error("Invalid PSBT format", return_callback, 0);
  }
}

static bool parse_and_display_psbt(const char *base64_data) {
  if (!base64_data) {
    return false;
  }

  cleanup_psbt_data();

  psbt_base64 = strdup(base64_data);
  if (!psbt_base64) {
    return false;
  }

  int ret = wally_psbt_from_base64(base64_data, 0, &current_psbt);
  if (ret != WALLY_OK) {
    cleanup_psbt_data();
    return false;
  }

  return true;
}

static void mismatch_dialog_cb(void *user_data) {
  cleanup_psbt_data();
  if (return_callback) {
    return_callback();
  }
}

// Check for mismatches between PSBT requirements and wallet configuration
// Returns true if there is a mismatch (and shows dialog), false if OK to proceed
static bool check_psbt_mismatch(void) {
  if (!current_psbt) {
    return false;
  }

  // Detect PSBT requirements (also sets global is_testnet for later use)
  is_testnet = psbt_detect_network(current_psbt);
  int32_t psbt_account = psbt_detect_account(current_psbt);

  // Get wallet configuration
  wallet_network_t wallet_net = wallet_get_network();
  bool wallet_is_testnet = (wallet_net == WALLET_NETWORK_TESTNET);
  uint32_t wallet_account = wallet_get_account();

  // Check for mismatches
  bool network_mismatch = (is_testnet != wallet_is_testnet);
  bool account_mismatch =
      (psbt_account >= 0 && (uint32_t)psbt_account != wallet_account);

  if (!network_mismatch && !account_mismatch) {
    return false; // No mismatch, proceed
  }

  // Build mismatch message
  char message[256];
  int offset = 0;
  offset += snprintf(message + offset, sizeof(message) - offset,
                     "PSBT requires different settings for proper change detection:\n\n");

  if (network_mismatch) {
    offset +=
        snprintf(message + offset, sizeof(message) - offset,
                 "  Network:  %s -> %s\n", wallet_is_testnet ? "Testnet" : "Mainnet",
                 is_testnet ? "Testnet" : "Mainnet");
  }

  if (account_mismatch) {
    offset += snprintf(message + offset, sizeof(message) - offset,
                       "  Account:  %u -> %d\n", wallet_account, psbt_account);
  }

  snprintf(message + offset, sizeof(message) - offset,
           "\nGo to Settings " LV_SYMBOL_SETTINGS " to update\nconfiguration before signing.");

  // Show mismatch dialog
  show_info_dialog("Configuration Mismatch", message, mismatch_dialog_cb, NULL);

  return true;
}

static bool create_psbt_info_display(void) {
  if (!sign_screen || !current_psbt || !wallet_is_initialized()) {
    return false;
  }

  // Check for configuration mismatches before displaying (also sets is_testnet)
  if (check_psbt_mismatch()) {
    return true; // Mismatch dialog shown, don't proceed with display
  }

  size_t num_inputs = 0;
  size_t num_outputs = 0;

  if (wally_psbt_get_num_inputs(current_psbt, &num_inputs) != WALLY_OK ||
      wally_psbt_get_num_outputs(current_psbt, &num_outputs) != WALLY_OK) {
    return false;
  }

  if (num_inputs == 0 || num_outputs == 0) {
    return false;
  }

  uint64_t total_input_value = 0;
  for (size_t i = 0; i < num_inputs; i++) {
    total_input_value += psbt_get_input_value(current_psbt, i);
  }
  psbt_info_container = lv_obj_create(sign_screen);
  lv_obj_set_size(psbt_info_container, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_flow(psbt_info_container, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(psbt_info_container, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(psbt_info_container, 10, 0);
  lv_obj_set_style_pad_gap(psbt_info_container, 10, 0);
  theme_apply_screen(psbt_info_container);
  lv_obj_add_flag(psbt_info_container, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *title =
      theme_create_label(psbt_info_container, "PSBT Transaction", false);
  theme_apply_label(title, true);
  lv_obj_set_width(title, LV_PCT(100));
  lv_obj_set_style_text_align(title, LV_TEXT_ALIGN_CENTER, 0);

  char inputs_text[64];
  snprintf(inputs_text, sizeof(inputs_text), "Inputs: %zu", num_inputs);
  lv_obj_t *inputs_label =
      theme_create_label(psbt_info_container, inputs_text, false);
  lv_obj_set_width(inputs_label, LV_PCT(100));

  char total_input_text[128];
  snprintf(total_input_text, sizeof(total_input_text), "Total Input: %llu sats",
           total_input_value);
  lv_obj_t *total_input_label =
      theme_create_label(psbt_info_container, total_input_text, false);
  lv_obj_set_width(total_input_label, LV_PCT(100));

  lv_obj_t *separator1 = lv_obj_create(psbt_info_container);
  lv_obj_set_size(separator1, LV_PCT(100), 2);
  lv_obj_set_style_bg_color(separator1, main_color(), 0);
  lv_obj_set_style_bg_opa(separator1, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(separator1, 0, 0);

  struct wally_tx *global_tx = NULL;
  int tx_ret = wally_psbt_get_global_tx_alloc(current_psbt, &global_tx);

  if (tx_ret != WALLY_OK || !global_tx) {
    return false;
  }

  classified_output_t *classified_outputs =
      calloc(num_outputs, sizeof(classified_output_t));
  if (!classified_outputs) {
    wally_tx_free(global_tx);
    return false;
  }
  for (size_t i = 0; i < num_outputs; i++) {
    classified_outputs[i].index = i;
    classified_outputs[i].value = global_tx->outputs[i].satoshi;
    classified_outputs[i].address = psbt_scriptpubkey_to_address(
        global_tx->outputs[i].script, global_tx->outputs[i].script_len,
        is_testnet);
    classified_outputs[i].type = classify_output(
        i, &global_tx->outputs[i], &classified_outputs[i].address_index);
  }

  bool has_self_transfers = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_SELF_TRANSFER) {
      if (!has_self_transfers) {
        lv_obj_t *title =
            theme_create_label(psbt_info_container, "Self-Transfer:", false);
        theme_apply_label(title, true);
        lv_obj_set_width(title, LV_PCT(100));
        has_self_transfers = true;
      }

      char text[128];
      snprintf(text, sizeof(text), "Receive #%u: %llu sats",
               classified_outputs[i].address_index,
               classified_outputs[i].value);
      lv_obj_t *label = theme_create_label(psbt_info_container, text, false);
      lv_obj_set_width(label, LV_PCT(100));
      lv_obj_set_style_pad_left(label, 20, 0);

      if (classified_outputs[i].address) {
        lv_obj_t *addr = theme_create_label(
            psbt_info_container, classified_outputs[i].address, false);
        lv_obj_set_width(addr, LV_PCT(100));
        lv_label_set_long_mode(addr, LV_LABEL_LONG_WRAP);
        lv_obj_set_style_text_color(addr, lv_color_hex(0xAAAAAA), 0);
        lv_obj_set_style_pad_left(addr, 20, 0);
      }
    }
  }
  if (has_self_transfers) {
    lv_obj_t *newline = theme_create_label(psbt_info_container, "\n", false);
    lv_obj_set_width(newline, LV_PCT(100));
  }

  // Display change
  bool has_change = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_CHANGE) {
      if (!has_change) {
        lv_obj_t *title =
            theme_create_label(psbt_info_container, "Change:", false);
        theme_apply_label(title, true);
        lv_obj_set_width(title, LV_PCT(100));
        has_change = true;
      }

      char text[128];
      snprintf(text, sizeof(text), "Change #%u: %llu sats",
               classified_outputs[i].address_index,
               classified_outputs[i].value);
      lv_obj_t *label = theme_create_label(psbt_info_container, text, false);
      lv_obj_set_width(label, LV_PCT(100));
      lv_obj_set_style_pad_left(label, 20, 0);

      if (classified_outputs[i].address) {
        lv_obj_t *addr = theme_create_label(
            psbt_info_container, classified_outputs[i].address, false);
        lv_obj_set_width(addr, LV_PCT(100));
        lv_label_set_long_mode(addr, LV_LABEL_LONG_WRAP);
        lv_obj_set_style_text_color(addr, lv_color_hex(0xAAAAAA), 0);
        lv_obj_set_style_pad_left(addr, 20, 0);
      }
    }
  }
  if (has_change) {
    lv_obj_t *newline = theme_create_label(psbt_info_container, "\n", false);
    lv_obj_set_width(newline, LV_PCT(100));
  }

  // Display spends
  bool has_spends = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_SPEND) {
      if (!has_spends) {
        lv_obj_t *title =
            theme_create_label(psbt_info_container, "Spending:", false);
        theme_apply_label(title, true);
        lv_obj_set_width(title, LV_PCT(100));
        has_spends = true;
      }

      char text[128];
      snprintf(text, sizeof(text), "Output %zu: %llu sats",
               classified_outputs[i].index, classified_outputs[i].value);
      lv_obj_t *label = theme_create_label(psbt_info_container, text, false);
      lv_obj_set_width(label, LV_PCT(100));
      lv_obj_set_style_pad_left(label, 20, 0);

      if (classified_outputs[i].address) {
        lv_obj_t *addr = theme_create_label(
            psbt_info_container, classified_outputs[i].address, false);
        lv_obj_set_width(addr, LV_PCT(100));
        lv_label_set_long_mode(addr, LV_LABEL_LONG_WRAP);
        lv_obj_set_style_text_color(addr, lv_color_hex(0xAAAAAA), 0);
        lv_obj_set_style_pad_left(addr, 20, 0);
      }
    }
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

  uint64_t total_output_value = 0;
  if (tx_ret == WALLY_OK && global_tx) {
    for (size_t i = 0; i < global_tx->num_outputs; i++) {
      total_output_value += global_tx->outputs[i].satoshi;
    }
  }

  if (global_tx) {
    wally_tx_free(global_tx);
    global_tx = NULL;
  }

  if (total_input_value > 0) {
    uint64_t fee = total_input_value - total_output_value;
    lv_obj_t *separator2 = lv_obj_create(psbt_info_container);
    lv_obj_set_size(separator2, LV_PCT(100), 2);
    lv_obj_set_style_bg_color(separator2, main_color(), 0);
    lv_obj_set_style_bg_opa(separator2, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(separator2, 0, 0);

    char fee_text[128];
    snprintf(fee_text, sizeof(fee_text), "Fee: %llu sats", fee);
    lv_obj_t *fee_label =
        theme_create_label(psbt_info_container, fee_text, false);
    lv_obj_set_width(fee_label, LV_PCT(100));
  }

  lv_obj_t *button_container = lv_obj_create(psbt_info_container);
  lv_obj_set_size(button_container, LV_PCT(100), LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(button_container, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(button_container, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(button_container, 0, 0);
  lv_obj_set_style_pad_gap(button_container, 10, 0);
  lv_obj_set_style_bg_opa(button_container, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(button_container, 0, 0);

  lv_obj_t *back_button = lv_btn_create(button_container);
  lv_obj_set_size(back_button, LV_PCT(45), LV_SIZE_CONTENT);
  theme_apply_touch_button(back_button, false);
  lv_obj_add_event_cb(back_button, back_button_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_clear_flag(back_button, LV_OBJ_FLAG_EVENT_BUBBLE);

  lv_obj_t *back_label = lv_label_create(back_button);
  lv_label_set_text(back_label, "Back");
  lv_obj_center(back_label);
  theme_apply_button_label(back_label, false);

  lv_obj_t *sign_button = lv_btn_create(button_container);
  lv_obj_set_size(sign_button, LV_PCT(45), LV_SIZE_CONTENT);
  theme_apply_touch_button(sign_button, false);
  lv_obj_add_event_cb(sign_button, sign_button_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_clear_flag(sign_button, LV_OBJ_FLAG_EVENT_BUBBLE);

  lv_obj_t *sign_label = lv_label_create(sign_button);
  lv_label_set_text(sign_label, "Sign");
  lv_obj_center(sign_label);
  theme_apply_button_label(sign_label, false);

  return true;
}

static void sign_button_cb(lv_event_t *e) {
  if (!current_psbt) {
    show_flash_error("No PSBT loaded", NULL, 2000);
    return;
  }

  size_t signatures_added = psbt_sign(current_psbt, is_testnet);

  if (signatures_added == 0) {
    show_flash_error("Failed to sign PSBT", NULL, 2000);
    return;
  }

  if (signed_psbt_base64) {
    wally_free_string(signed_psbt_base64);
    signed_psbt_base64 = NULL;
  }

  struct wally_psbt *trimmed_psbt = psbt_trim(current_psbt);
  struct wally_psbt *export_psbt = trimmed_psbt ? trimmed_psbt : current_psbt;

  int ret = wally_psbt_to_base64(export_psbt, 0, &signed_psbt_base64);

  if (trimmed_psbt) {
    wally_psbt_free(trimmed_psbt);
  }

  if (ret != WALLY_OK) {
    show_flash_error("Failed to encode PSBT", NULL, 2000);
    return;
  }

  saved_return_callback = return_callback;

  int export_format =
      (scanned_qr_format == -1) ? FORMAT_NONE : scanned_qr_format;

  if (!qr_viewer_page_create_with_format(lv_screen_active(), export_format,
                                         signed_psbt_base64, "Signed PSBT",
                                         return_from_qr_viewer_cb)) {
    show_flash_error("Failed to create QR viewer", return_callback, 2000);
    return;
  }

  sign_page_hide();
  sign_page_destroy();

  qr_viewer_page_show();
}

static void return_from_qr_viewer_cb(void) {
  qr_viewer_page_destroy();
  if (saved_return_callback) {
    void (*callback)(void) = saved_return_callback;
    saved_return_callback = NULL;
    callback();
  }
}

static void cleanup_psbt_data(void) {
  if (current_psbt) {
    wally_psbt_free(current_psbt);
    current_psbt = NULL;
  }

  if (psbt_base64) {
    free(psbt_base64);
    psbt_base64 = NULL;
  }

  if (signed_psbt_base64) {
    wally_free_string(signed_psbt_base64);
    signed_psbt_base64 = NULL;
  }

  is_testnet = false;
  scanned_qr_format = FORMAT_NONE;
}

void sign_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded()) {
    return;
  }

  return_callback = return_cb;

  sign_screen = theme_create_page_container(parent);
  qr_scanner_page_create(NULL, return_from_qr_scanner_cb);
  qr_scanner_page_show();
}

void sign_page_show(void) {
  if (sign_screen) {
    lv_obj_clear_flag(sign_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void sign_page_hide(void) {
  if (sign_screen) {
    lv_obj_add_flag(sign_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void sign_page_destroy(void) {
  qr_scanner_page_destroy();

  cleanup_psbt_data();

  psbt_info_container = NULL;

  if (sign_screen) {
    lv_obj_del(sign_screen);
    sign_screen = NULL;
  }

  return_callback = NULL;
}
