/*
 * Scan Page
 * Universal QR content detection: PSBT, message, descriptor, address, mnemonic
 */

#include "scan.h"
#include "../../../components/cUR/src/types/bytes_type.h"
#include "../../../components/cUR/src/types/psbt.h"
#include "../../core/key.h"
#include "../../core/message_sign.h"
#include "../../core/psbt.h"
#include "../../core/storage.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../qr/parser.h"
#include "../../qr/scanner.h"
#include "../../qr/viewer.h"
#include "../../ui/assets/icons_24.h"
#include "../../ui/dialog.h"
#include "../../ui/menu.h"
#include "../../ui/sankey.h"
#include "../../ui/theme.h"
#include "../../utils/secure_mem.h"
#include "../load_descriptor_storage.h"
#include "../shared/address_checker.h"
#include "../shared/descriptor_loader.h"
#include <esp_log.h>
#include <lvgl.h>
#include <stdio.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

// Address indices above this are considered unusual and warrant a warning.
#define UNUSUAL_DERIVATION_INDEX 10000u

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
static lv_obj_t *scan_screen = NULL;
static lv_obj_t *psbt_info_container = NULL;
static sankey_diagram_t *tx_diagram = NULL;
static ui_menu_t *multisig_menu = NULL;
static void (*return_callback)(void) = NULL;
static void (*saved_return_callback)(void) = NULL;

// PSBT data
static struct wally_psbt *current_psbt = NULL;
static char *psbt_base64 = NULL;
static char *signed_psbt_base64 = NULL;
static bool is_testnet = false;
static int scanned_qr_format = FORMAT_NONE;
static bool skip_verification = false;

// Message signing data
static parsed_sign_message_t current_message = {0};
static bool is_message_sign = false;

// Mnemonic data
static char *scanned_mnemonic = NULL;

// Forward declarations
static void back_button_cb(lv_event_t *e);
static void return_from_qr_scanner_cb(void);
static bool parse_and_display_psbt(const char *base64_data);
static void cleanup_psbt_data(void);
static bool create_psbt_info_display(void);
static output_type_t classify_output(size_t output_index,
                                     const struct wally_tx_output *tx_output,
                                     const struct wally_tx *global_tx,
                                     uint32_t *address_index_out);
static void sign_button_cb(lv_event_t *e);
static void return_from_qr_viewer_cb(void);
static bool check_psbt_mismatch(void);
static void mismatch_dialog_cb(void *user_data);
static void show_multisig_options_menu(void);
static void return_from_descriptor_scanner_cb(void);
static void create_message_sign_display(void);
static void message_sign_button_cb(lv_event_t *e);
static void handle_descriptor_content(const char *descriptor_str);
static void handle_address_content(const char *content);
static void handle_mnemonic_content(const char *data, size_t len);

// Format satoshis as Bitcoin with visual grouping: "1.00 000 000"
static void format_btc(char *buf, size_t buf_size, uint64_t sats) {
  uint64_t whole = sats / 100000000ULL;
  uint64_t frac = sats % 100000000ULL;
  // Split fraction: first 2 digits, then two groups of 3
  uint32_t frac_first = (uint32_t)(frac / 1000000ULL);
  uint32_t frac_second = (uint32_t)((frac / 1000ULL) % 1000ULL);
  uint32_t frac_third = (uint32_t)(frac % 1000ULL);
  snprintf(buf, buf_size, "%llu.%02u %03u %03u", whole, frac_first, frac_second,
           frac_third);
}

// Create address label with first and last 6 chars highlighted in given color
static lv_obj_t *create_address_label(lv_obj_t *parent, const char *address,
                                      lv_color_t highlight) {
  size_t len = strlen(address);
  char *formatted = malloc(len + 32);
  if (!formatted) {
    return theme_create_label(parent, address, false);
  }

  lv_color32_t c32 = lv_color_to_32(highlight, LV_OPA_COVER);
  uint32_t color_hex = (c32.red << 16) | (c32.green << 8) | c32.blue;

  if (len > 12) {
    char first[7], last[7];
    strncpy(first, address, 6);
    first[6] = '\0';
    strncpy(last, address + len - 6, 6);
    last[6] = '\0';

    snprintf(formatted, len + 32, "#%06X %s#%.*s#%06X %s#", (unsigned)color_hex,
             first, (int)(len - 12), address + 6, (unsigned)color_hex, last);
  } else {
    snprintf(formatted, len + 32, "#%06X %s#", (unsigned)color_hex, address);
  }

  lv_obj_t *label = lv_label_create(parent);
  lv_label_set_recolor(label, true);
  lv_label_set_text(label, formatted);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  lv_obj_set_style_text_color(label, lv_color_hex(0xAAAAAA), 0);
  free(formatted);

  return label;
}

// Create a row with: [prefix text] [BTC icon] [formatted value]
static lv_obj_t *create_btc_value_row(lv_obj_t *parent, const char *prefix,
                                      uint64_t sats, lv_color_t color) {
  lv_obj_t *row = theme_create_flex_row(parent);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_START);
  lv_obj_set_style_pad_column(row, 4, 0);

  lv_obj_t *prefix_label = lv_label_create(row);
  lv_label_set_text(prefix_label, prefix);
  lv_obj_set_style_text_font(prefix_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(prefix_label, color, 0);

  lv_obj_t *icon_label = lv_label_create(row);
  lv_label_set_text(icon_label, ICON_BITCOIN);
  lv_obj_set_style_text_font(icon_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(icon_label, color, 0);

  char btc_str[32];
  format_btc(btc_str, sizeof(btc_str), sats);
  lv_obj_t *value_label = lv_label_create(row);
  lv_label_set_text(value_label, btc_str);
  lv_obj_set_style_text_font(value_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(value_label, color, 0);

  return row;
}

// Classify output as self-transfer, change, or spend
static output_type_t classify_output(size_t output_index,
                                     const struct wally_tx_output *tx_output,
                                     const struct wally_tx *global_tx,
                                     uint32_t *address_index_out) {
  bool is_change = false;
  uint32_t address_index = 0;

  if (skip_verification) {
    return OUTPUT_TYPE_SPEND;
  }

  if (psbt_is_multisig(current_psbt) && wallet_has_descriptor()) {
    if (psbt_verify_output_with_descriptor(current_psbt, output_index,
                                           global_tx, &is_change,
                                           &address_index)) {
      *address_index_out = address_index;
      return is_change ? OUTPUT_TYPE_CHANGE : OUTPUT_TYPE_SELF_TRANSFER;
    }
    return OUTPUT_TYPE_SPEND;
  }

  if (!psbt_get_output_derivation(current_psbt, output_index, is_testnet,
                                  &is_change, &address_index)) {
    return OUTPUT_TYPE_SPEND;
  }

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

// --- Content detection ---

static bool is_descriptor_prefix(const char *data) {
  return strncmp(data, "wsh(", 4) == 0 || strncmp(data, "sh(", 3) == 0 ||
         strncmp(data, "wpkh(", 5) == 0 || strncmp(data, "pkh(", 4) == 0 ||
         strncmp(data, "tr(", 3) == 0;
}

static bool is_bluewallet_descriptor(const char *data) {
  return strstr(data, "Policy:") != NULL;
}

static bool is_valid_address(const char *data) {
  const char *addr = data;
  char *stripped = NULL;

  // Strip BIP21 prefix
  if (strncasecmp(data, "bitcoin:", 8) == 0) {
    const char *start = data + 8;
    const char *query = strchr(start, '?');
    size_t addr_len = query ? (size_t)(query - start) : strlen(start);
    stripped = strndup(start, addr_len);
    if (!stripped)
      return false;
    addr = stripped;
  }

  const char *hrp =
      (wallet_get_network() == WALLET_NETWORK_MAINNET) ? "bc" : "tb";
  uint32_t wally_net = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                           ? WALLY_NETWORK_BITCOIN_MAINNET
                           : WALLY_NETWORK_BITCOIN_TESTNET;
  unsigned char script[128];
  size_t written = 0;
  bool valid =
      (wally_addr_segwit_to_bytes(addr, hrp, 0, script, sizeof(script),
                                  &written) == WALLY_OK) ||
      (wally_address_to_scriptpubkey(addr, wally_net, script, sizeof(script),
                                     &written) == WALLY_OK);
  free(stripped);
  return valid;
}

// --- Main scanner callback with two-layer detection ---

static void return_from_qr_scanner_cb(void) {
  int detected_format = qr_scanner_get_format();

  char *qr_content = NULL;
  size_t qr_content_len = 0;
  bool parse_success = false;

  if (detected_format == FORMAT_UR) {
    const char *ur_type = NULL;
    const uint8_t *cbor_data = NULL;
    size_t cbor_len = 0;

    if (qr_scanner_get_ur_result(&ur_type, &cbor_data, &cbor_len)) {
      // Layer 1: UR type hints
      if (ur_type && strcmp(ur_type, "crypto-psbt") == 0) {
        // PSBT via UR
        psbt_data_t *psbt_data = psbt_from_cbor(cbor_data, cbor_len);
        if (psbt_data) {
          size_t psbt_len;
          const uint8_t *psbt_bytes = psbt_get_data(psbt_data, &psbt_len);
          if (psbt_bytes) {
            cleanup_psbt_data();
            parse_success = (wally_psbt_from_bytes(psbt_bytes, psbt_len, 0,
                                                   &current_psbt) == WALLY_OK);
          }
          psbt_free(psbt_data);
        }
      } else if (ur_type && (strcmp(ur_type, "crypto-output") == 0 ||
                             strcmp(ur_type, "crypto-account") == 0)) {
        // Descriptor via UR — extract before destroying scanner
        char *desc = descriptor_extract_from_scanner();
        qr_scanner_page_hide();
        qr_scanner_page_destroy();
        if (desc) {
          handle_descriptor_content(desc);
          free(desc);
        } else {
          dialog_show_error("Failed to parse descriptor", return_callback, 0);
        }
        return;
      } else if (ur_type && strcmp(ur_type, "bytes") == 0) {
        // UR bytes: decode to string, fall through to Layer 2
        bytes_data_t *bytes = bytes_from_cbor(cbor_data, cbor_len);
        if (bytes) {
          size_t len = 0;
          const uint8_t *data = bytes_get_data(bytes, &len);
          if (data && len > 0) {
            qr_content = strndup((const char *)data, len);
            qr_content_len = len;
          }
          bytes_free(bytes);
        }
      }
    }
  } else if (detected_format == FORMAT_BBQR) {
    // BBQr returns raw binary PSBT data
    qr_content = qr_scanner_get_completed_content_with_len(&qr_content_len);
    if (qr_content && qr_content_len > 0) {
      cleanup_psbt_data();
      parse_success =
          (wally_psbt_from_bytes((const uint8_t *)qr_content, qr_content_len, 0,
                                 &current_psbt) == WALLY_OK);
      free(qr_content);
      qr_content = NULL;
    }
  } else {
    // Other formats (PMOFN, NONE) — get content with length for binary formats
    qr_content = qr_scanner_get_completed_content_with_len(&qr_content_len);
  }

  // Layer 2: plaintext/binary heuristics — try each parser in priority order
  if (!parse_success && qr_content) {
    // 1. Message
    if (message_sign_parse(qr_content, &current_message)) {
      is_message_sign = true;
      parse_success = true;
    }

    // 2. PSBT (base64)
    if (!parse_success) {
      parse_success = parse_and_display_psbt(qr_content);
    }

    // 3. Descriptor
    if (!parse_success && (is_descriptor_prefix(qr_content) ||
                           is_bluewallet_descriptor(qr_content))) {
      qr_scanner_page_hide();
      qr_scanner_page_destroy();
      handle_descriptor_content(qr_content);
      free(qr_content);
      return;
    }

    // 4. Address
    if (!parse_success && is_valid_address(qr_content)) {
      qr_scanner_page_hide();
      qr_scanner_page_destroy();
      handle_address_content(qr_content);
      free(qr_content);
      return;
    }

    // 5. Mnemonic
    if (!parse_success) {
      char *mnemonic =
          mnemonic_qr_to_mnemonic(qr_content, qr_content_len, NULL);
      if (mnemonic && bip39_mnemonic_validate(NULL, mnemonic) == WALLY_OK) {
        free(mnemonic);
        qr_scanner_page_hide();
        qr_scanner_page_destroy();
        handle_mnemonic_content(qr_content, qr_content_len);
        free(qr_content);
        return;
      }
      SECURE_FREE_STRING(mnemonic);
    }

    free(qr_content);
    qr_content = NULL;
  }

  qr_scanner_page_hide();
  qr_scanner_page_destroy();

  if (parse_success) {
    if (is_message_sign) {
      create_message_sign_display();
    } else {
      scanned_qr_format = detected_format;

      if (psbt_is_multisig(current_psbt) && !wallet_has_descriptor()) {
        show_multisig_options_menu();
      } else {
        if (!create_psbt_info_display()) {
          dialog_show_error("Invalid PSBT data", return_callback, 0);
        }
      }
    }
  } else {
    dialog_show_error("Unrecognized QR format", return_callback, 0);
  }
}

// --- Descriptor handler ---

static void descriptor_loaded_info_cb(void *user_data) {
  (void)user_data;
  if (return_callback)
    return_callback();
}

static void scan_descriptor_validation_cb(descriptor_validation_result_t result,
                                          void *user_data) {
  (void)user_data;

  if (result == VALIDATION_SUCCESS) {
    dialog_show_info("Descriptor Loaded", "Wallet descriptor updated",
                     descriptor_loaded_info_cb, NULL, DIALOG_STYLE_FULLSCREEN);
    return;
  }

  descriptor_loader_show_error(result);
  if (return_callback)
    return_callback();
}

static void handle_descriptor_content(const char *descriptor_str) {
  descriptor_loader_process_string(descriptor_str,
                                   scan_descriptor_validation_cb, NULL);
}

// --- Address handler ---

static void address_found_cb(void) {
  address_checker_destroy();
  if (return_callback)
    return_callback();
}

static void address_not_found_cb(void) {
  address_checker_destroy();
  if (return_callback)
    return_callback();
}

static void handle_address_content(const char *content) {
  // For multisig without descriptor, we can't verify addresses
  if (wallet_get_policy() == WALLET_POLICY_MULTISIG &&
      !wallet_has_descriptor()) {
    dialog_show_error("Load a descriptor first to verify multisig addresses",
                      return_callback, 0);
    return;
  }

  address_checker_check(content, address_found_cb, address_not_found_cb);
}

// --- Mnemonic handler ---

static void mnemonic_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;

  if (!confirmed || !scanned_mnemonic) {
    SECURE_FREE_STRING(scanned_mnemonic);
    if (return_callback)
      return_callback();
    return;
  }

  wallet_network_t net = wallet_get_network();

  // Unload current state
  wallet_unload();

  // Load new mnemonic (no passphrase, will use current network)
  if (!key_load_from_mnemonic(scanned_mnemonic, NULL,
                              net == WALLET_NETWORK_TESTNET)) {
    SECURE_FREE_STRING(scanned_mnemonic);
    dialog_show_error("Failed to load mnemonic", return_callback, 0);
    return;
  }

  if (!wallet_init(net)) {
    SECURE_FREE_STRING(scanned_mnemonic);
    dialog_show_error("Failed to initialize wallet", return_callback, 0);
    return;
  }

  SECURE_FREE_STRING(scanned_mnemonic);

  // Return to home — it will recreate with new key info
  if (return_callback)
    return_callback();
}

static void handle_mnemonic_content(const char *data, size_t len) {
  char *mnemonic = mnemonic_qr_to_mnemonic(data, len, NULL);
  if (!mnemonic || bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    SECURE_FREE_STRING(mnemonic);
    dialog_show_error("Invalid mnemonic", return_callback, 0);
    return;
  }

  // Get current fingerprint
  char current_fp[9] = "????????";
  key_get_fingerprint_hex(current_fp);

  // Compute new mnemonic's fingerprint without touching the loaded key
  wallet_network_t net = wallet_get_network();
  bool is_test = (net == WALLET_NETWORK_TESTNET);

  char new_fp[9] = "????????";
  {
    unsigned char seed[BIP39_SEED_LEN_512];
    size_t seed_len = 0;
    if (bip39_mnemonic_to_seed(mnemonic, NULL, seed, sizeof(seed), &seed_len) ==
        WALLY_OK) {
      uint32_t ver = is_test ? BIP32_VER_TEST_PRIVATE : BIP32_VER_MAIN_PRIVATE;
      struct ext_key *tmp_key = NULL;
      if (bip32_key_from_seed_alloc(seed, seed_len, ver, 0, &tmp_key) ==
          WALLY_OK) {
        unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
        if (bip32_key_get_fingerprint(tmp_key, fp, BIP32_KEY_FINGERPRINT_LEN) ==
            WALLY_OK) {
          for (int i = 0; i < BIP32_KEY_FINGERPRINT_LEN; i++)
            sprintf(new_fp + (i * 2), "%02x", fp[i]);
          new_fp[BIP32_KEY_FINGERPRINT_LEN * 2] = '\0';
        }
        bip32_key_free(tmp_key);
      }
      secure_memzero(seed, sizeof(seed));
    }
  }

  // Store mnemonic for confirmation callback
  scanned_mnemonic = mnemonic;

  char msg[256];
  snprintf(
      msg, sizeof(msg),
      "Replace current key?\n\n"
      "  %s > #%06X %s#\n\n"
      "Passphrase and descriptor will be discarded.",
      current_fp,
      (unsigned)((lv_color_to_32(highlight_color(), LV_OPA_COVER).red << 16) |
                 (lv_color_to_32(highlight_color(), LV_OPA_COVER).green << 8) |
                 lv_color_to_32(highlight_color(), LV_OPA_COVER).blue),
      new_fp);

  dialog_show_confirm(msg, mnemonic_confirm_cb, NULL, DIALOG_STYLE_FULLSCREEN);
}

// --- PSBT handling (unchanged from sign.c) ---

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

static bool check_psbt_mismatch(void) {
  if (!current_psbt) {
    return false;
  }

  is_testnet = psbt_detect_network(current_psbt);
  int32_t psbt_account = psbt_detect_account(current_psbt);

  wallet_network_t wallet_net = wallet_get_network();
  bool wallet_is_testnet = (wallet_net == WALLET_NETWORK_TESTNET);
  uint32_t wallet_account = wallet_get_account();

  bool network_mismatch = (is_testnet != wallet_is_testnet);
  bool account_mismatch =
      (psbt_account >= 0 && (uint32_t)psbt_account != wallet_account);

  if (!network_mismatch && !account_mismatch) {
    return false;
  }

  char message[256];
  int offset = 0;
  offset += snprintf(
      message + offset, sizeof(message) - offset,
      "PSBT requires different settings for proper change detection:\n\n");

  if (network_mismatch) {
    offset += snprintf(message + offset, sizeof(message) - offset,
                       "  Network:  %s -> %s\n",
                       wallet_is_testnet ? "Testnet" : "Mainnet",
                       is_testnet ? "Testnet" : "Mainnet");
  }

  if (account_mismatch) {
    offset += snprintf(message + offset, sizeof(message) - offset,
                       "  Account:  %u -> %d\n", wallet_account, psbt_account);
  }

  snprintf(message + offset, sizeof(message) - offset,
           "\nGo to Settings " LV_SYMBOL_SETTINGS
           " to update\nconfiguration before signing.");

  dialog_show_info("Configuration Mismatch", message, mismatch_dialog_cb, NULL,
                   DIALOG_STYLE_FULLSCREEN);

  return true;
}

static bool create_psbt_info_display(void) {
  if (!scan_screen || !current_psbt || !wallet_is_initialized()) {
    return false;
  }

  if (check_psbt_mismatch()) {
    return true;
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

  uint64_t *input_amounts = malloc(num_inputs * sizeof(uint64_t));
  if (!input_amounts) {
    return false;
  }
  uint64_t total_input_value = 0;
  for (size_t i = 0; i < num_inputs; i++) {
    input_amounts[i] = psbt_get_input_value(current_psbt, i);
    total_input_value += input_amounts[i];
  }

  struct wally_tx *global_tx = NULL;
  int tx_ret = wally_psbt_get_global_tx_alloc(current_psbt, &global_tx);
  if (tx_ret != WALLY_OK || !global_tx) {
    free(input_amounts);
    return false;
  }

  classified_output_t *classified_outputs =
      calloc(num_outputs, sizeof(classified_output_t));
  if (!classified_outputs) {
    free(input_amounts);
    wally_tx_free(global_tx);
    return false;
  }

  uint64_t total_output_value = 0;
  for (size_t i = 0; i < num_outputs; i++) {
    total_output_value += global_tx->outputs[i].satoshi;
  }
  uint64_t fee = (total_input_value > total_output_value)
                     ? (total_input_value - total_output_value)
                     : 0;

  size_t diagram_output_count = num_outputs + (fee > 0 ? 1 : 0);
  uint64_t *output_amounts = malloc(diagram_output_count * sizeof(uint64_t));
  lv_color_t *output_colors = malloc(diagram_output_count * sizeof(lv_color_t));
  if (!output_amounts || !output_colors) {
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
        is_testnet);
    classified_outputs[i].type =
        classify_output(i, &global_tx->outputs[i], global_tx,
                        &classified_outputs[i].address_index);
  }

  size_t diagram_idx = 0;

  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_SELF_TRANSFER) {
      output_amounts[diagram_idx] = classified_outputs[i].value;
      output_colors[diagram_idx] = cyan_color();
      diagram_idx++;
    }
  }

  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_CHANGE) {
      output_amounts[diagram_idx] = classified_outputs[i].value;
      output_colors[diagram_idx] = yes_color();
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

  psbt_info_container = lv_obj_create(scan_screen);
  lv_obj_set_size(psbt_info_container, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_flow(psbt_info_container, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(psbt_info_container, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(psbt_info_container, 10, 0);
  lv_obj_set_style_pad_gap(psbt_info_container, 10, 0);
  theme_apply_screen(psbt_info_container);
  lv_obj_add_flag(psbt_info_container, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_update_layout(psbt_info_container);
  int32_t diagram_width = lv_obj_get_width(scan_screen) - 20;
  tx_diagram = sankey_diagram_create(psbt_info_container, diagram_width, 160);
  if (tx_diagram) {
    sankey_diagram_set_inputs(tx_diagram, input_amounts, num_inputs);
    sankey_diagram_set_outputs(tx_diagram, output_amounts, diagram_output_count,
                               output_colors);
    sankey_diagram_render(tx_diagram);
  }

  size_t input_overflow = sankey_diagram_get_input_overflow(tx_diagram);
  size_t output_overflow = sankey_diagram_get_output_overflow(tx_diagram);

  if (input_overflow > 0 || output_overflow > 0) {
    lv_obj_t *overflow_row = lv_obj_create(psbt_info_container);
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
  free(output_amounts);
  free(output_colors);

  char prefix_text[64];
  snprintf(prefix_text, sizeof(prefix_text), "Inputs(%zu): ", num_inputs);
  lv_obj_t *inputs_row = create_btc_value_row(psbt_info_container, prefix_text,
                                              total_input_value, main_color());
  lv_obj_set_width(inputs_row, LV_PCT(100));

  lv_obj_t *separator1 = lv_obj_create(psbt_info_container);
  lv_obj_set_size(separator1, LV_PCT(100), 2);
  lv_obj_set_style_bg_color(separator1, main_color(), 0);
  lv_obj_set_style_bg_opa(separator1, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(separator1, 0, 0);

  bool has_self_transfers = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_SELF_TRANSFER) {
      if (!has_self_transfers) {
        lv_obj_t *title =
            theme_create_label(psbt_info_container, "Self-Transfer: ", false);
        theme_apply_label(title, true);
        lv_obj_set_style_text_color(title, cyan_color(), 0);
        lv_obj_set_width(title, LV_PCT(100));
        has_self_transfers = true;
      }

      char text[64];
      snprintf(text, sizeof(text),
               "Receive #%u: ", classified_outputs[i].address_index);
      lv_obj_t *row = create_btc_value_row(
          psbt_info_container, text, classified_outputs[i].value, main_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        lv_obj_t *addr = create_address_label(
            psbt_info_container, classified_outputs[i].address, cyan_color());
        lv_obj_set_width(addr, LV_PCT(100));
        lv_label_set_long_mode(addr, LV_LABEL_LONG_WRAP);
        lv_obj_set_style_pad_left(addr, 20, 0);
      }

      if (classified_outputs[i].address_index >= UNUSUAL_DERIVATION_INDEX) {
        lv_obj_t *warn = theme_create_label(
            psbt_info_container,
            "WARNING: unusual derivation index. May be unrecoverable", false);
        lv_obj_set_style_text_color(warn, error_color(), 0);
        lv_obj_set_width(warn, LV_PCT(100));
        lv_obj_set_style_pad_left(warn, 20, 0);
        lv_label_set_long_mode(warn, LV_LABEL_LONG_WRAP);
      }
    }
  }

  bool has_change = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_CHANGE) {
      if (!has_change) {
        lv_obj_t *title =
            theme_create_label(psbt_info_container, "Change: ", false);
        theme_apply_label(title, true);
        lv_obj_set_style_text_color(title, yes_color(), 0);
        lv_obj_set_style_margin_top(title, 15, 0);
        lv_obj_set_width(title, LV_PCT(100));
        has_change = true;
      }

      char text[64];
      snprintf(text, sizeof(text),
               "Change #%u: ", classified_outputs[i].address_index);
      lv_obj_t *row = create_btc_value_row(
          psbt_info_container, text, classified_outputs[i].value, main_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        lv_obj_t *addr = create_address_label(
            psbt_info_container, classified_outputs[i].address, yes_color());
        lv_obj_set_width(addr, LV_PCT(100));
        lv_label_set_long_mode(addr, LV_LABEL_LONG_WRAP);
        lv_obj_set_style_pad_left(addr, 20, 0);
      }

      if (classified_outputs[i].address_index >= UNUSUAL_DERIVATION_INDEX) {
        lv_obj_t *warn = theme_create_label(
            psbt_info_container,
            "WARNING: unusual derivation index. May be unrecoverable", false);
        lv_obj_set_style_text_color(warn, error_color(), 0);
        lv_obj_set_width(warn, LV_PCT(100));
        lv_obj_set_style_pad_left(warn, 20, 0);
        lv_label_set_long_mode(warn, LV_LABEL_LONG_WRAP);
      }
    }
  }

  bool has_spends = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_SPEND) {
      if (!has_spends) {
        lv_obj_t *title =
            theme_create_label(psbt_info_container, "Spending: ", false);
        theme_apply_label(title, true);
        lv_obj_set_style_text_color(title, highlight_color(), 0);
        lv_obj_set_style_margin_top(title, 15, 0);
        lv_obj_set_width(title, LV_PCT(100));
        has_spends = true;
      }

      char text[64];
      snprintf(text, sizeof(text), "Output %zu: ", classified_outputs[i].index);
      lv_obj_t *row = create_btc_value_row(
          psbt_info_container, text, classified_outputs[i].value, main_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        lv_obj_t *addr = create_address_label(psbt_info_container,
                                              classified_outputs[i].address,
                                              highlight_color());
        lv_obj_set_width(addr, LV_PCT(100));
        lv_label_set_long_mode(addr, LV_LABEL_LONG_WRAP);
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

  if (global_tx) {
    wally_tx_free(global_tx);
    global_tx = NULL;
  }

  if (fee > 0) {
    lv_obj_t *separator2 = lv_obj_create(psbt_info_container);
    lv_obj_set_size(separator2, LV_PCT(100), 2);
    lv_obj_set_style_bg_color(separator2, main_color(), 0);
    lv_obj_set_style_bg_opa(separator2, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(separator2, 0, 0);

    lv_obj_t *fee_row =
        create_btc_value_row(psbt_info_container, "Fee: ", fee, error_color());
    lv_obj_set_width(fee_row, LV_PCT(100));
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

static lv_obj_t *sign_progress_dialog = NULL;

static void dismiss_sign_progress(void) {
  if (sign_progress_dialog) {
    lv_obj_del(sign_progress_dialog);
    sign_progress_dialog = NULL;
  }
}

static void deferred_sign_cb(lv_timer_t *timer) {
  (void)timer;

  if (!current_psbt) {
    dismiss_sign_progress();
    dialog_show_error("No PSBT loaded", NULL, 2000);
    return;
  }

  size_t signatures_added = psbt_sign(current_psbt, is_testnet);

  if (signatures_added == 0) {
    dismiss_sign_progress();
    dialog_show_error("Failed to sign PSBT", NULL, 2000);
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

  dismiss_sign_progress();

  if (ret != WALLY_OK) {
    dialog_show_error("Failed to encode PSBT", NULL, 2000);
    return;
  }

  saved_return_callback = return_callback;

  int export_format =
      (scanned_qr_format == -1) ? FORMAT_NONE : scanned_qr_format;

  if (!qr_viewer_page_create_with_format(lv_screen_active(), export_format,
                                         signed_psbt_base64, "Signed PSBT",
                                         return_from_qr_viewer_cb)) {
    dialog_show_error("Failed to create QR viewer", return_callback, 2000);
    return;
  }

  scan_page_hide();
  scan_page_destroy();

  qr_viewer_page_show();
}

static void sign_button_cb(lv_event_t *e) {
  (void)e;
  if (!current_psbt) {
    dialog_show_error("No PSBT loaded", NULL, 2000);
    return;
  }

  // Signing big PSBTs can take a few seconds — show a progress dialog and
  // defer the work to a one-shot timer so LVGL gets to render it first.
  sign_progress_dialog =
      dialog_show_progress("Sign", "Processing...", DIALOG_STYLE_OVERLAY);
  lv_timer_t *t = lv_timer_create(deferred_sign_cb, 50, NULL);
  lv_timer_set_repeat_count(t, 1);
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

  message_sign_free_parsed(&current_message);
  is_message_sign = false;

  is_testnet = false;
  scanned_qr_format = FORMAT_NONE;
  skip_verification = false;
}

// Multisig menu callbacks
static void multisig_menu_back_cb(void) {
  descriptor_loader_destroy_source_menu();
  if (multisig_menu) {
    ui_menu_destroy(multisig_menu);
    multisig_menu = NULL;
  }
  cleanup_psbt_data();
  if (return_callback) {
    return_callback();
  }
}

static void show_multisig_menu_on_error(void) {
  if (multisig_menu)
    ui_menu_show(multisig_menu);
}

static void descriptor_validation_cb(descriptor_validation_result_t result,
                                     void *user_data) {
  (void)user_data;

  if (result == VALIDATION_SUCCESS) {
    descriptor_loader_destroy_source_menu();
    if (multisig_menu) {
      ui_menu_destroy(multisig_menu);
      multisig_menu = NULL;
    }
    if (!create_psbt_info_display()) {
      dialog_show_error("Invalid PSBT data", return_callback, 0);
    }
    return;
  }

  descriptor_loader_show_error(result);
  show_multisig_menu_on_error();
}

static void return_from_descriptor_scanner_cb(void) {
  descriptor_loader_process_scanner(descriptor_validation_cb, NULL,
                                    show_multisig_menu_on_error);
}

static void return_from_descriptor_storage(void) {
  load_descriptor_storage_page_destroy();
  show_multisig_menu_on_error();
}

static void success_from_descriptor_storage(void) {
  load_descriptor_storage_page_destroy();
  descriptor_loader_destroy_source_menu();
  if (multisig_menu) {
    ui_menu_destroy(multisig_menu);
    multisig_menu = NULL;
  }
  if (!create_psbt_info_display()) {
    dialog_show_error("Invalid PSBT data", return_callback, 0);
  }
}

static void load_desc_from_qr_cb(void) {
  descriptor_loader_destroy_source_menu();
  if (multisig_menu)
    ui_menu_hide(multisig_menu);
  qr_scanner_page_create(NULL, return_from_descriptor_scanner_cb);
  qr_scanner_page_show();
}

static void load_desc_from_flash_cb(void) {
  descriptor_loader_destroy_source_menu();
  if (multisig_menu)
    ui_menu_hide(multisig_menu);
  load_descriptor_storage_page_create(
      lv_screen_active(), return_from_descriptor_storage,
      success_from_descriptor_storage, STORAGE_FLASH);
  load_descriptor_storage_page_show();
}

static void load_desc_from_sd_cb(void) {
  descriptor_loader_destroy_source_menu();
  if (multisig_menu)
    ui_menu_hide(multisig_menu);
  load_descriptor_storage_page_create(
      lv_screen_active(), return_from_descriptor_storage,
      success_from_descriptor_storage, STORAGE_SD);
  load_descriptor_storage_page_show();
}

static void load_desc_source_back_cb(void) {
  descriptor_loader_destroy_source_menu();
}

static void load_descriptor_menu_cb(void) {
  descriptor_loader_show_source_menu(
      scan_screen, load_desc_from_qr_cb, load_desc_from_flash_cb,
      load_desc_from_sd_cb, load_desc_source_back_cb);
}

static void sign_without_verification_cb(void) {
  if (multisig_menu) {
    ui_menu_destroy(multisig_menu);
    multisig_menu = NULL;
  }
  skip_verification = true;
  if (!create_psbt_info_display()) {
    dialog_show_error("Invalid PSBT data", return_callback, 0);
  }
}

static void show_multisig_options_menu(void) {
  if (!scan_screen) {
    return;
  }

  multisig_menu = ui_menu_create(scan_screen, "Multisig PSBT Detected",
                                 multisig_menu_back_cb);
  if (!multisig_menu) {
    dialog_show_error("Failed to create menu", return_callback, 0);
    return;
  }

  ui_menu_add_entry(multisig_menu, "Load Descriptor", load_descriptor_menu_cb);
  ui_menu_add_entry(multisig_menu, "Sign Without Verification",
                    sign_without_verification_cb);
  ui_menu_show(multisig_menu);
}

static void create_message_sign_display(void) {
  if (!scan_screen) {
    return;
  }

  wallet_network_t net = wallet_get_network();
  bool testnet = (net == WALLET_NETWORK_TESTNET);

  char *address = NULL;
  if (!message_sign_get_address(current_message.derivation_path, testnet,
                                &address)) {
    dialog_show_error("Failed to derive address", return_callback, 0);
    return;
  }

  psbt_info_container = lv_obj_create(scan_screen);
  lv_obj_set_size(psbt_info_container, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_flow(psbt_info_container, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(psbt_info_container, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(psbt_info_container, 10, 0);
  lv_obj_set_style_pad_gap(psbt_info_container, 10, 0);
  theme_apply_screen(psbt_info_container);
  lv_obj_add_flag(psbt_info_container, LV_OBJ_FLAG_SCROLLABLE);

  theme_create_page_title(psbt_info_container, "Sign Message");

  lv_obj_t *path_title =
      theme_create_label(psbt_info_container, "Path:", false);
  theme_apply_label(path_title, true);
  lv_obj_set_style_text_color(path_title, secondary_color(), 0);

  lv_obj_t *path_label = theme_create_label(
      psbt_info_container, current_message.derivation_path, false);
  lv_obj_set_width(path_label, LV_PCT(100));

  lv_obj_t *addr_title =
      theme_create_label(psbt_info_container, "Address:", false);
  theme_apply_label(addr_title, true);
  lv_obj_set_style_text_color(addr_title, secondary_color(), 0);

  lv_obj_t *addr_label =
      create_address_label(psbt_info_container, address, highlight_color());
  lv_obj_set_width(addr_label, LV_PCT(100));
  lv_label_set_long_mode(addr_label, LV_LABEL_LONG_WRAP);

  wally_free_string(address);

  lv_obj_t *separator = lv_obj_create(psbt_info_container);
  lv_obj_set_size(separator, LV_PCT(100), 2);
  lv_obj_set_style_bg_color(separator, main_color(), 0);
  lv_obj_set_style_bg_opa(separator, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(separator, 0, 0);

  lv_obj_t *msg_title =
      theme_create_label(psbt_info_container, "Message:", false);
  theme_apply_label(msg_title, true);
  lv_obj_set_style_text_color(msg_title, secondary_color(), 0);

  lv_obj_t *msg_label =
      theme_create_label(psbt_info_container, current_message.message, false);
  lv_obj_set_width(msg_label, LV_PCT(100));
  lv_label_set_long_mode(msg_label, LV_LABEL_LONG_WRAP);

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
  lv_obj_add_event_cb(sign_button, message_sign_button_cb, LV_EVENT_CLICKED,
                      NULL);
  lv_obj_clear_flag(sign_button, LV_OBJ_FLAG_EVENT_BUBBLE);

  lv_obj_t *sign_label = lv_label_create(sign_button);
  lv_label_set_text(sign_label, "Sign");
  lv_obj_center(sign_label);
  theme_apply_button_label(sign_label, false);
}

static void message_sign_button_cb(lv_event_t *e) {
  char *sig_b64 = NULL;
  if (!message_sign_sign(current_message.derivation_path,
                         current_message.message, &sig_b64)) {
    dialog_show_error("Failed to sign message", NULL, 2000);
    return;
  }

  saved_return_callback = return_callback;

  qr_viewer_page_create(lv_screen_active(), sig_b64, "Message Signature",
                        return_from_qr_viewer_cb);
  wally_free_string(sig_b64);

  scan_page_hide();
  scan_page_destroy();

  qr_viewer_page_show();
}

void scan_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded()) {
    return;
  }

  return_callback = return_cb;

  scan_screen = theme_create_page_container(parent);
  qr_scanner_page_create(NULL, return_from_qr_scanner_cb);
  qr_scanner_page_show();
}

void scan_page_show(void) {
  if (scan_screen) {
    lv_obj_clear_flag(scan_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void scan_page_hide(void) {
  if (scan_screen) {
    lv_obj_add_flag(scan_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void scan_page_destroy(void) {
  dismiss_sign_progress();
  qr_scanner_page_destroy();
  load_descriptor_storage_page_destroy();
  descriptor_loader_destroy_source_menu();
  address_checker_destroy();

  cleanup_psbt_data();

  SECURE_FREE_STRING(scanned_mnemonic);

  if (multisig_menu) {
    ui_menu_destroy(multisig_menu);
    multisig_menu = NULL;
  }

  if (tx_diagram) {
    sankey_diagram_destroy(tx_diagram);
    tx_diagram = NULL;
  }

  psbt_info_container = NULL;

  if (scan_screen) {
    lv_obj_del(scan_screen);
    scan_screen = NULL;
  }

  return_callback = NULL;
}
