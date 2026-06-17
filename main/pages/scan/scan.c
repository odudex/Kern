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
#include "../../core/registry.h"
#include "../../core/settings.h"
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
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "../load_descriptor_storage.h"
#include "../shared/address_checker.h"
#include "../shared/descriptor_loader.h"
#include "psbt_sign_policy.h"
#include "sd_card.h"
#include <esp_log.h>
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

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

// UI components
static lv_obj_t *scan_screen = NULL;
static lv_obj_t *psbt_info_container = NULL;
static sankey_diagram_t *tx_diagram = NULL;
static void (*return_callback)(void) = NULL;
// Invoked instead of return_callback when a signing flow runs to completion
// (signed PSBT exported, message signature shown) — lets a file-browser caller
// send back-outs to the browser but completed flows back to home.
static void (*complete_callback)(void) = NULL;
static void (*saved_return_callback)(void) = NULL;

// PSBT data
static struct wally_psbt *current_psbt = NULL;
static char *psbt_base64 = NULL;
static char *signed_psbt_base64 = NULL;
static bool is_testnet = false;
static int scanned_qr_format = FORMAT_NONE;

// Signed-PSBT export context. Set when the source PSBT is parsed and reset at
// the start of each ingest: where a saved file is written (the folder the PSBT
// was loaded from on SD, else the card root) and which encoding to mirror
// (base64 text when the source was base64, otherwise raw binary).
static char psbt_export_dir[512] = SD_CARD_MOUNT_POINT;
static bool psbt_source_base64 = false;
// Original SD file name (no path), used to name the saved file
// "signed-<name>.psbt". Empty for QR sources, which fall back to "signed-N".
static char psbt_source_name[128] = "";
static ui_menu_t *export_menu = NULL;

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
                                     uint32_t *address_index_out,
                                     char *path_out, size_t path_out_size);
static void sign_button_cb(lv_event_t *e);
static void return_from_qr_viewer_cb(void);
static bool check_psbt_mismatch(void);
static void mismatch_dialog_cb(void *user_data);
static void return_from_descriptor_scanner_cb(void);
static void create_message_sign_display(void);
static void message_sign_button_cb(lv_event_t *e);
static void handle_descriptor_content(const char *descriptor_str);
static void handle_address_content(const char *content);
static void handle_mnemonic_content(const char *data, size_t len);
static void descriptor_loaded_info_cb(void *user_data);
static void show_export_choice(void);
static void export_show_qr_cb(void);
static void export_save_sd_cb(void);
static void export_choice_back_cb(void);
static void finish_export(void);

static void create_sign_action_row(lv_obj_t *parent, lv_event_cb_t sign_cb) {
  lv_obj_t *button_container = theme_create_button_row(parent, 10);
  if (!button_container)
    return;

  lv_obj_t *back_button = theme_create_button(button_container, "Back", false);
  lv_obj_set_size(back_button, LV_PCT(45), LV_SIZE_CONTENT);
  lv_obj_add_event_cb(back_button, back_button_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_clear_flag(back_button, LV_OBJ_FLAG_EVENT_BUBBLE);

  lv_obj_t *sign_button = theme_create_button(button_container, "Sign", false);
  lv_obj_set_size(sign_button, LV_PCT(45), LV_SIZE_CONTENT);
  lv_obj_add_event_cb(sign_button, sign_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_clear_flag(sign_button, LV_OBJ_FLAG_EVENT_BUBBLE);
}

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

#define ADDRESS_TIP_CHARS 6
#define ADDRESS_INDENT_PX 20

static void add_address_tip_overlay(lv_obj_t *parent, lv_obj_t *base_label,
                                    const char *address, size_t index,
                                    lv_color_t highlight, int32_t x_offset) {
  char text[2] = {address[index], '\0'};
  lv_point_t pos;
  lv_label_get_letter_pos(base_label, (uint32_t)index, &pos);

  lv_obj_t *tip = lv_label_create(parent);
  lv_label_set_text(tip, text);
  lv_obj_set_style_text_font(tip, theme_font_small(), 0);
  lv_obj_set_style_text_color(tip, highlight, 0);
  lv_obj_set_pos(tip, x_offset + pos.x, pos.y);
}

// Plain wrapped address label plus colored overlays for the tip chars. This
// keeps wrapping in LVGL's label engine and avoids recolor/span edge cases.
static lv_obj_t *create_address_label(lv_obj_t *parent, const char *address,
                                      lv_color_t highlight, int32_t pad_left) {
  size_t len = strlen(address);
  const lv_font_t *font = theme_font_small();
  lv_obj_update_layout(parent);

  lv_obj_t *container = lv_obj_create(parent);
  theme_apply_transparent_container(container);
  lv_obj_clear_flag(container, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_width(container, LV_PCT(100));
  lv_obj_set_height(container, LV_SIZE_CONTENT);

  int32_t label_width = lv_obj_get_content_width(parent) - pad_left;
  if (label_width < 0)
    label_width = 0;

  lv_obj_t *label = lv_label_create(container);
  lv_obj_set_pos(label, pad_left, 0);
  lv_obj_set_width(label, label_width);
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_label_set_text(label, address);
  lv_obj_set_style_text_font(label, font, 0);
  lv_obj_set_style_text_color(label, lv_color_hex(0xAAAAAA), 0);

  lv_obj_update_layout(container);
  lv_obj_update_layout(label);
  lv_obj_set_height(container, lv_obj_get_height(label));

  size_t tip_count = len < ADDRESS_TIP_CHARS ? len : ADDRESS_TIP_CHARS;
  for (size_t i = 0; i < tip_count; i++) {
    add_address_tip_overlay(container, label, address, i, highlight, pad_left);
  }
  if (len > ADDRESS_TIP_CHARS) {
    size_t tail_start = len > ADDRESS_TIP_CHARS * 2 ? len - ADDRESS_TIP_CHARS
                                                    : ADDRESS_TIP_CHARS;
    for (size_t i = tail_start; i < len; i++) {
      add_address_tip_overlay(container, label, address, i, highlight,
                              pad_left);
    }
  }

  return container;
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

// Classify output as self-transfer, change, owned-unsafe, expected-owned,
// or spend. For owned-unsafe and expected-owned, the path string is written
// to path_out (truncated to path_out_size).
static output_type_t classify_output(size_t output_index,
                                     uint32_t *address_index_out,
                                     char *path_out, size_t path_out_size) {
  bool is_change = false;
  uint32_t address_index = 0;

  output_ownership_t ownership =
      psbt_classify_output(current_psbt, output_index, is_testnet);

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
    if (path_out && path_out_size > 0) {
      path_out[0] = '\0';
      psbt_format_keypath(ownership.raw_keypath, ownership.raw_keypath_len,
                          path_out, path_out_size);
    }
    return ownership.ownership == PSBT_OWNERSHIP_OWNED_UNSAFE
               ? OUTPUT_TYPE_OWNED_UNSAFE
               : OUTPUT_TYPE_EXPECTED_OWNED;

  case PSBT_OWNERSHIP_EXTERNAL:
  default:
    return OUTPUT_TYPE_SPEND;
  }
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

typedef enum {
  ADDRESS_NETWORK_NONE,
  ADDRESS_NETWORK_MAINNET,
  ADDRESS_NETWORK_TESTNET,
} address_network_t;

static address_network_t detect_address_network(const char *data) {
  const char *addr = data;
  char *stripped = NULL;

  // Strip BIP21 prefix
  if (strncasecmp(data, "bitcoin:", 8) == 0) {
    const char *start = data + 8;
    const char *query = strchr(start, '?');
    size_t addr_len = query ? (size_t)(query - start) : strlen(start);
    stripped = strndup(start, addr_len);
    if (!stripped)
      return ADDRESS_NETWORK_NONE;
    addr = stripped;
  }

  unsigned char script[128];
  size_t written = 0;
  address_network_t result = ADDRESS_NETWORK_NONE;

  if (wally_addr_segwit_to_bytes(addr, "bc", 0, script, sizeof(script),
                                 &written) == WALLY_OK ||
      wally_address_to_scriptpubkey(addr, WALLY_NETWORK_BITCOIN_MAINNET, script,
                                    sizeof(script), &written) == WALLY_OK) {
    result = ADDRESS_NETWORK_MAINNET;
  } else if (wally_addr_segwit_to_bytes(addr, "tb", 0, script, sizeof(script),
                                        &written) == WALLY_OK ||
             wally_address_to_scriptpubkey(addr, WALLY_NETWORK_BITCOIN_TESTNET,
                                           script, sizeof(script),
                                           &written) == WALLY_OK) {
    result = ADDRESS_NETWORK_TESTNET;
  }

  free(stripped);
  return result;
}

// Classify an already-assembled blob and route it to the matching review
// screen. Shared by the QR scanner and the SD-card loader, so it must not touch
// any qr_scanner_page_* state — the caller tears the scanner down first. Takes
// ownership of qr_content (frees it). When parse_success is already true on
// entry (a binary PSBT decoded by layer 1), qr_content must be NULL.
static void finish_dispatch(char *qr_content, size_t qr_content_len,
                            bool parse_success, int detected_format) {
  is_message_sign = false;

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
      handle_descriptor_content(qr_content);
      SECURE_FREE_STRING(qr_content);
      return;
    }

    // 4. Address
    if (!parse_success) {
      address_network_t addr_net = detect_address_network(qr_content);
      if (addr_net != ADDRESS_NETWORK_NONE) {
        bool addr_is_mainnet = (addr_net == ADDRESS_NETWORK_MAINNET);
        bool wallet_is_mainnet =
            (wallet_get_network() == WALLET_NETWORK_MAINNET);
        if (addr_is_mainnet == wallet_is_mainnet) {
          handle_address_content(qr_content);
        } else {
          dialog_show_error_timeout(
              addr_is_mainnet ? "Address is for Mainnet, wallet is on Testnet"
                              : "Address is for Testnet, wallet is on Mainnet",
              return_callback, 3000);
        }
        SECURE_FREE_STRING(qr_content);
        return;
      }
    }

    // 5. Mnemonic
    if (!parse_success) {
      char *mnemonic =
          mnemonic_qr_to_mnemonic(qr_content, qr_content_len, NULL);
      if (mnemonic && bip39_mnemonic_validate(NULL, mnemonic) == WALLY_OK) {
        SECURE_FREE_STRING(mnemonic);
        handle_mnemonic_content(qr_content, qr_content_len);
        SECURE_FREE_STRING(qr_content);
        return;
      }
      SECURE_FREE_STRING(mnemonic);
    }

    SECURE_FREE_STRING(qr_content);
  }

  if (parse_success) {
    if (is_message_sign) {
      create_message_sign_display();
    } else {
      scanned_qr_format = detected_format;

      if (check_psbt_mismatch()) {
        return;
      }

      if (!psbt_sign_policy_allows_review(current_psbt, is_testnet,
                                          descriptor_loaded_info_cb)) {
        return;
      }

      if (!create_psbt_info_display()) {
        dialog_show_error_timeout("Invalid PSBT data", return_callback, 0);
      }
    }
  } else {
    dialog_show_error_timeout("Unrecognized format", return_callback, 0);
  }
}

// --- Main scanner callback with two-layer detection ---

static void return_from_qr_scanner_cb(void) {
  if (!qr_scanner_has_completed_result()) {
    qr_scanner_page_hide();
    qr_scanner_page_destroy();
    if (return_callback)
      return_callback();
    return;
  }

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
          dialog_show_error_timeout("Failed to parse descriptor",
                                    return_callback, 0);
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
    /* BBQr can carry any payload type — file_type 'P' for raw PSBT
     * bytes, 'U' for UTF-8 text (descriptor / mnemonic / address /
     * signed-message). Try the binary-PSBT path first; on failure,
     * keep qr_content alive so layer 2's text-mode detectors get a
     * shot at it. The decoded payload from qr_parser_result is
     * NUL-terminated (parser.c:301), so it's safe to treat as a C
     * string in the layer-2 detectors. */
    qr_content = qr_scanner_get_completed_content_with_len(&qr_content_len);
    if (qr_content && qr_content_len > 0) {
      cleanup_psbt_data();
      parse_success =
          (wally_psbt_from_bytes((const uint8_t *)qr_content, qr_content_len, 0,
                                 &current_psbt) == WALLY_OK);
      if (parse_success) {
        free(qr_content);
        qr_content = NULL;
      }
    }
  } else {
    // Other formats (PMOFN, NONE) — get content with length for binary formats
    qr_content = qr_scanner_get_completed_content_with_len(&qr_content_len);
  }

  qr_scanner_page_hide();
  qr_scanner_page_destroy();

  finish_dispatch(qr_content, qr_content_len, parse_success, detected_format);
}

// Resets the signed-PSBT export context. A scanned PSBT has no source folder
// or file name — a saved signature lands at the card root in binary, unless
// layer 2 detects base64 text; a file load passes the folder it came from and
// its name.
static void reset_export_context(const char *save_dir,
                                 const char *source_name) {
  psbt_source_base64 = false;
  snprintf(psbt_export_dir, sizeof(psbt_export_dir), "%s",
           save_dir ? save_dir : SD_CARD_MOUNT_POINT);
  snprintf(psbt_source_name, sizeof(psbt_source_name), "%s",
           source_name ? source_name : "");
}

// Normalizes a text file's contents into the single string the layer-2
// detectors expect from a QR: strips a UTF-8 BOM, drops comment and blank
// lines (a comment's first non-whitespace character is '#'; a descriptor's
// "#checksum" suffix is mid-line and so survives), trims each line, then
// rejoins. Editor-wrapped base64 PSBTs and descriptors are joined without a
// separator; anything else (e.g. a word-per-line mnemonic backup) gets a
// single space between lines. BlueWallet "Policy:" files keep their layout —
// that parser reads the lines itself. Returns a heap string, or NULL when no
// content line exists.
static char *normalize_file_text(const uint8_t *data, size_t len) {
  const char *text = (const char *)data;
  if (len >= 3 && memcmp(text, "\xEF\xBB\xBF", 3) == 0) {
    text += 3;
    len -= 3;
  }

  char *out = malloc(len + 1);
  if (!out)
    return NULL;

  size_t n = 0;
  const char *sep = NULL;
  size_t i = 0;
  while (i < len) {
    size_t s = i;
    while (i < len && text[i] != '\n')
      i++;
    size_t e = i;
    if (i < len)
      i++; // step past '\n'

    while (s < e && (text[s] == ' ' || text[s] == '\t' || text[s] == '\r'))
      s++;
    while (e > s &&
           (text[e - 1] == ' ' || text[e - 1] == '\t' || text[e - 1] == '\r'))
      e--;
    if (s == e || text[s] == '#')
      continue; // blank or comment line

    if (!sep) { // first content line decides how the rest are joined
      sep = (e - s >= 6 && (strncmp(text + s, "cHNidP", 6) == 0 ||
                            is_descriptor_prefix(text + s)))
                ? ""
                : " ";
    } else if (*sep) {
      out[n++] = ' ';
    }
    memcpy(out + n, text + s, e - s);
    n += e - s;
  }
  out[n] = '\0';

  if (n == 0 || strstr(out, "Policy:")) {
    // BlueWallet files are re-emitted whole; an all-comment/blank file is
    // reported as having no content.
    SECURE_FREE_BUFFER(out, n);
    if (n == 0)
      return NULL;
    out = malloc(len + 1);
    if (!out)
      return NULL;
    memcpy(out, text, len);
    out[len] = '\0';
  }
  return out;
}

void scan_load_content(lv_obj_t *parent, const uint8_t *data, size_t len,
                       const char *save_dir, const char *source_name,
                       void (*return_cb)(void), void (*complete_cb)(void)) {
  if (!parent || !data || len == 0)
    return;

  reset_export_context(save_dir, source_name);
  return_callback = return_cb;
  complete_callback = complete_cb;
  scan_screen = theme_create_page_container(parent);

  // A file may hold a serialized binary PSBT — try that first (mirroring the
  // BBQr path); otherwise normalize the text for the layer-2 detectors.
  cleanup_psbt_data();
  bool parse_success =
      (wally_psbt_from_bytes(data, len, 0, &current_psbt) == WALLY_OK);

  char *content = NULL;
  if (!parse_success) {
    content = normalize_file_text(data, len);
    if (!content) {
      dialog_show_error_timeout("No loadable content in file", return_callback,
                                0);
      return;
    }
  }

  finish_dispatch(content, content ? strlen(content) : len, parse_success,
                  FORMAT_NONE);
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
    dialog_show_info("Descriptor Loaded", "Wallet descriptor added to session",
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
    dialog_show_error_timeout("Failed to load mnemonic", return_callback, 0);
    return;
  }

  if (!wallet_init(net)) {
    SECURE_FREE_STRING(scanned_mnemonic);
    dialog_show_error_timeout("Failed to initialize wallet", return_callback,
                              0);
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
    dialog_show_error_timeout("Invalid mnemonic", return_callback, 0);
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

  psbt_source_base64 = true;
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

  wallet_network_t wallet_net = wallet_get_network();
  bool wallet_is_testnet = (wallet_net == WALLET_NETWORK_TESTNET);

  bool network_mismatch = (is_testnet != wallet_is_testnet);

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
                     is_testnet ? "Testnet" : "Mainnet");

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
  uint64_t total_input_value = 0;
  size_t external_input_count = 0;
  for (size_t i = 0; i < num_inputs; i++) {
    input_amounts[i] = psbt_get_input_value(current_psbt, i);
    total_input_value += input_amounts[i];

    input_ownership_t own = psbt_classify_input(current_psbt, i, is_testnet);
    classified_inputs[i].index = i;
    classified_inputs[i].ownership = own.ownership;
    classified_inputs[i].value = input_amounts[i];
    input_colors[i] = (own.ownership == PSBT_OWNERSHIP_EXTERNAL)
                          ? error_color()
                          : primary_color();
    format_input_policy(&own, classified_inputs[i].policy,
                        sizeof(classified_inputs[i].policy));

    /* External inputs need their address rendered in the warning section.
     * Skip address decoding for owned inputs — they're not displayed. */
    if (own.ownership == PSBT_OWNERSHIP_EXTERNAL) {
      external_input_count++;
      unsigned char spk[34];
      size_t spk_len = 0;
      if (psbt_input_utxo_script(current_psbt, i, spk, sizeof(spk), &spk_len)) {
        classified_inputs[i].address =
            psbt_scriptpubkey_to_address(spk, spk_len, is_testnet);
      }
    }
  }

  struct wally_tx *global_tx = NULL;
  int tx_ret = wally_psbt_get_global_tx_alloc(current_psbt, &global_tx);
  if (tx_ret != WALLY_OK || !global_tx) {
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
        is_testnet);
    classified_outputs[i].path[0] = '\0';
    classified_outputs[i].type = classify_output(
        i, &classified_outputs[i].address_index, classified_outputs[i].path,
        sizeof(classified_outputs[i].path));
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

  psbt_info_container = theme_create_scroll_column(scan_screen, 10, 10);

  lv_obj_update_layout(psbt_info_container);
  int32_t diagram_width = lv_obj_get_width(scan_screen) - 20;
  int32_t diagram_height = lv_obj_get_height(scan_screen) / 4;
  tx_diagram =
      sankey_diagram_create(psbt_info_container, diagram_width, diagram_height);
  if (tx_diagram) {
    sankey_diagram_set_inputs(tx_diagram, input_amounts, num_inputs,
                              input_colors);
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
    lv_obj_t *row = create_btc_value_row(psbt_info_container, prefix, total,
                                         primary_color());
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

  /* External inputs warning section. The Partial-signing gate has already
   * passed (otherwise we wouldn't reach the review screen with externals
   * present), but the user must still see what they're co-signing — we
   * sign our inputs only, leaving externals to whoever holds those keys.
   * Render each external input's amount + address so the user can spot a
   * forgery (an attacker tricking us into co-signing their address). */
  if (external_input_count > 0) {
    lv_obj_t *warn_title = theme_create_label(
        psbt_info_container,
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
      lv_obj_t *row =
          create_btc_value_row(psbt_info_container, text,
                               classified_inputs[i].value, primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_inputs[i].address) {
        create_address_label(psbt_info_container, classified_inputs[i].address,
                             error_color(), ADDRESS_INDENT_PX);
      }
    }
  }

  lv_obj_t *separator1 =
      theme_create_separator(psbt_info_container, primary_color());
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
        theme_create_label(psbt_info_container, title_text, false);
    theme_apply_label(title, true);
    lv_obj_set_style_text_color(title, accent_color(), 0);
    lv_obj_set_width(title, LV_PCT(100));

    lv_obj_t *row = create_btc_value_row(
        psbt_info_container, "Total: ", total_self_transfer, primary_color());
    lv_obj_set_width(row, LV_PCT(100));
    lv_obj_set_style_pad_left(row, 20, 0);
  } else if (self_transfer_count > 0) {
    lv_obj_t *title =
        theme_create_label(psbt_info_container, "Self-Transfer: ", false);
    theme_apply_label(title, true);
    lv_obj_set_style_text_color(title, accent_color(), 0);
    lv_obj_set_width(title, LV_PCT(100));

    for (size_t i = 0; i < num_outputs; i++) {
      if (classified_outputs[i].type != OUTPUT_TYPE_SELF_TRANSFER)
        continue;

      char text[64];
      snprintf(text, sizeof(text),
               "Receive #%u: ", classified_outputs[i].address_index);
      lv_obj_t *row =
          create_btc_value_row(psbt_info_container, text,
                               classified_outputs[i].value, primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        create_address_label(psbt_info_container, classified_outputs[i].address,
                             accent_color(), ADDRESS_INDENT_PX);
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
    lv_obj_t *row = create_btc_value_row(
        psbt_info_container, "Change: ", total_change, good_color());
    lv_obj_set_width(row, LV_PCT(100));
    lv_obj_set_style_margin_top(row, 15, 0);
  }

  bool has_owned_unsafe = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_OWNED_UNSAFE) {
      if (!has_owned_unsafe) {
        lv_obj_t *title = theme_create_label(
            psbt_info_container, "Owned (non-standard path): ", false);
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
      lv_obj_t *row =
          create_btc_value_row(psbt_info_container, text,
                               classified_outputs[i].value, primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        create_address_label(psbt_info_container, classified_outputs[i].address,
                             accent_color(), ADDRESS_INDENT_PX);
      }
    }
  }

  bool has_expected = false;
  for (size_t i = 0; i < num_outputs; i++) {
    if (classified_outputs[i].type == OUTPUT_TYPE_EXPECTED_OWNED) {
      if (!has_expected) {
        lv_obj_t *title = theme_create_label(
            psbt_info_container, "Expected ownership (UNVERIFIED): ", false);
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
      lv_obj_t *row =
          create_btc_value_row(psbt_info_container, text,
                               classified_outputs[i].value, primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        create_address_label(psbt_info_container, classified_outputs[i].address,
                             error_color(), ADDRESS_INDENT_PX);
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
      lv_obj_t *row =
          create_btc_value_row(psbt_info_container, text,
                               classified_outputs[i].value, primary_color());
      lv_obj_set_width(row, LV_PCT(100));
      lv_obj_set_style_pad_left(row, 20, 0);

      if (classified_outputs[i].address) {
        create_address_label(psbt_info_container, classified_outputs[i].address,
                             highlight_color(), ADDRESS_INDENT_PX);
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

  if (fee > 0) {
    theme_create_separator(psbt_info_container, primary_color());

    lv_obj_t *fee_row =
        create_btc_value_row(psbt_info_container, "Fee: ", fee, error_color());
    lv_obj_set_width(fee_row, LV_PCT(100));
  }

  create_sign_action_row(psbt_info_container, sign_button_cb);

  return true;
}

static lv_obj_t *progress_dialog = NULL;

static void dismiss_progress(void) {
  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }
}

static void destroy_export_menu(void) {
  if (export_menu) {
    ui_menu_destroy(export_menu);
    export_menu = NULL;
  }
}

static void deferred_sign_cb(lv_timer_t *timer) {
  (void)timer;

  if (!current_psbt) {
    dismiss_progress();
    dialog_show_error_timeout("No PSBT loaded", NULL, 2000);
    return;
  }

  psbt_sign_policy_t sign_policy = {
      .allow_unsafe = settings_get_permissive_signing(),
      .allow_expected_owned = settings_get_expected_owned_signing(),
  };
  size_t signatures_added = psbt_sign(current_psbt, is_testnet, sign_policy);

  if (signatures_added == 0) {
    dismiss_progress();
    dialog_show_error_timeout("Failed to sign PSBT", NULL, 2000);
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

  dismiss_progress();

  if (ret != WALLY_OK) {
    dialog_show_error_timeout("Failed to encode PSBT", NULL, 2000);
    return;
  }

  saved_return_callback =
      complete_callback ? complete_callback : return_callback;
  show_export_choice();
}

// Tears down the chooser, then returns to the caller that opened the
// scan/sign flow — the return callback owns scan_page_destroy(). Used once a
// signed PSBT has been exported (QR or SD) or the user backs out of the
// export choice.
static void finish_export(void) {
  destroy_export_menu();
  if (saved_return_callback) {
    void (*cb)(void) = saved_return_callback;
    saved_return_callback = NULL;
    cb();
  }
}

static void export_choice_back_cb(void) { finish_export(); }

static void export_show_qr_cb(void) {
  destroy_export_menu();

  int export_format =
      (scanned_qr_format == -1) ? FORMAT_NONE : scanned_qr_format;

  // File-loaded PSBTs carry no source QR format — default to UR so the
  // export animates instead of cramming one dense raw QR.
  if (export_format == FORMAT_NONE && psbt_source_name[0])
    export_format = FORMAT_UR;

  if (!qr_viewer_page_create_with_format(lv_screen_active(), export_format,
                                         signed_psbt_base64, "Signed PSBT",
                                         return_from_qr_viewer_cb)) {
    dialog_show_error_timeout("Failed to create QR viewer", return_callback,
                              2000);
    return;
  }

  // Free the review screen early — the viewer return callback's own destroy
  // then finds nothing left to do (scan_page_destroy is idempotent).
  scan_page_destroy();

  qr_viewer_page_show();
}

static void export_saved_dialog_cb(void *user_data) {
  (void)user_data;
  finish_export();
}

// Writes the signed PSBT to psbt_export_dir under an auto-generated,
// non-clobbering name, mirroring the source encoding — base64 text saves as
// .txt, binary as .psbt. Unlike QR export there is no payload-size pressure,
// so the full PSBT is serialized rather than the trimmed copy.
static void deferred_export_save_cb(lv_timer_t *timer) {
  (void)timer;

  if (!current_psbt) {
    dismiss_progress();
    dialog_show_error_timeout("No PSBT loaded", NULL, 2000);
    return;
  }

  // Ensure the SD card is mounted — the card may have been swapped (no card-
  // detect line), but if it was already mounted (e.g. loaded from SD) the
  // init is a no-op. If the card was removed, the subsequent write will fail.
  esp_err_t mret = sd_card_init();
  dismiss_progress();
  if (mret != ESP_OK) {
    dialog_show_error_timeout("No SD card", show_export_choice, 0);
    return;
  }

  // Derive a stem from the original file name (extension stripped); when there
  // is none (QR source) the file is numbered instead.
  char base[96];
  base[0] = '\0';
  if (psbt_source_name[0]) {
    size_t blen = strlen(psbt_source_name);
    const char *dot = strrchr(psbt_source_name, '.');
    if (dot && dot != psbt_source_name)
      blen = (size_t)(dot - psbt_source_name);
    if (blen >= sizeof(base))
      blen = sizeof(base) - 1;
    memcpy(base, psbt_source_name, blen);
    base[blen] = '\0';
  }

  const char *ext = psbt_source_base64 ? "txt" : "psbt";
  char path[700];
  bool found = false;
  for (int n = 1; n <= 1000; n++) {
    if (base[0]) {
      if (n == 1)
        snprintf(path, sizeof(path), "%s/signed-%s.%s", psbt_export_dir, base,
                 ext);
      else
        snprintf(path, sizeof(path), "%s/signed-%s-%d.%s", psbt_export_dir,
                 base, n, ext);
    } else {
      snprintf(path, sizeof(path), "%s/signed-%d.%s", psbt_export_dir, n, ext);
    }
    bool exists = false;
    if (sd_card_file_exists(path, &exists) != ESP_OK)
      break;
    if (!exists) {
      found = true;
      break;
    }
  }
  if (!found) {
    dialog_show_error_timeout("Could not create file", show_export_choice, 0);
    return;
  }

  esp_err_t wret;
  if (psbt_source_base64) {
    char *full_b64 = NULL;
    if (wally_psbt_to_base64(current_psbt, 0, &full_b64) != WALLY_OK) {
      dialog_show_error_timeout("Failed to encode PSBT", show_export_choice, 0);
      return;
    }
    wret =
        sd_card_write_file(path, (const uint8_t *)full_b64, strlen(full_b64));
    wally_free_string(full_b64);
  } else {
    size_t bin_len = 0;
    if (wally_psbt_get_length(current_psbt, 0, &bin_len) != WALLY_OK) {
      dialog_show_error_timeout("Failed to encode PSBT", show_export_choice, 0);
      return;
    }
    uint8_t *bin = malloc(bin_len);
    if (!bin) {
      dialog_show_error_timeout("Out of memory", show_export_choice, 0);
      return;
    }
    size_t written = 0;
    if (wally_psbt_to_bytes(current_psbt, 0, bin, bin_len, &written) !=
        WALLY_OK) {
      free(bin);
      dialog_show_error_timeout("Failed to encode PSBT", show_export_choice, 0);
      return;
    }
    wret = sd_card_write_file(path, bin, written);
    free(bin);
  }

  if (wret != ESP_OK) {
    dialog_show_error_timeout("Failed to save", show_export_choice, 0);
    return;
  }

  char msg[768];
  snprintf(msg, sizeof(msg), "Saved to:\n%s", path);
  dialog_show_info("Saved", msg, export_saved_dialog_cb, NULL,
                   DIALOG_STYLE_OVERLAY);
}

static void export_save_sd_cb(void) {
  destroy_export_menu();

  // Remounting probes the card and can take a while — show progress and defer
  // the work so LVGL gets to render it first.
  progress_dialog =
      dialog_show_progress("Save", "Saving...", DIALOG_STYLE_OVERLAY);
  lv_timer_t *t = lv_timer_create(deferred_export_save_cb, 50, NULL);
  lv_timer_set_repeat_count(t, 1);
}

// Offers the signed PSBT as a QR code or an SD-card file. Shown over the
// (hidden) review screen so a back-out can still return cleanly.
static void show_export_choice(void) {
  scan_page_hide();

  export_menu = ui_menu_create(lv_screen_active(), "Export Signed PSBT",
                               export_choice_back_cb);
  if (!export_menu) {
    export_show_qr_cb(); // fall back to the QR viewer if the menu can't build
    return;
  }
  ui_menu_add_entry(export_menu, "Show QR code", export_show_qr_cb);
  ui_menu_add_entry(export_menu, "Save to SD card", export_save_sd_cb);
  ui_menu_show(export_menu);
}

static void sign_button_cb(lv_event_t *e) {
  (void)e;
  if (!current_psbt) {
    dialog_show_error_timeout("No PSBT loaded", NULL, 2000);
    return;
  }

  // Signing big PSBTs can take a few seconds — show a progress dialog and
  // defer the work to a one-shot timer so LVGL gets to render it first.
  progress_dialog =
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
    dialog_show_error_timeout("Failed to derive address", return_callback, 0);
    return;
  }

  psbt_info_container = theme_create_scroll_column(scan_screen, 10, 10);

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

  create_address_label(psbt_info_container, address, highlight_color(), 0);

  wally_free_string(address);

  theme_create_separator(psbt_info_container, primary_color());

  lv_obj_t *msg_title =
      theme_create_label(psbt_info_container, "Message:", false);
  theme_apply_label(msg_title, true);
  lv_obj_set_style_text_color(msg_title, secondary_color(), 0);

  lv_obj_t *msg_label =
      theme_create_label(psbt_info_container, current_message.message, false);
  lv_obj_set_width(msg_label, LV_PCT(100));
  lv_label_set_long_mode(msg_label, LV_LABEL_LONG_WRAP);

  create_sign_action_row(psbt_info_container, message_sign_button_cb);
}

static void message_sign_button_cb(lv_event_t *e) {
  char *sig_b64 = NULL;
  if (!message_sign_sign(current_message.derivation_path,
                         current_message.message, &sig_b64)) {
    dialog_show_error_timeout("Failed to sign message", NULL, 2000);
    return;
  }

  saved_return_callback =
      complete_callback ? complete_callback : return_callback;

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
  complete_callback = NULL;
  reset_export_context(NULL, NULL);

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
  dismiss_progress();
  destroy_export_menu();
  qr_scanner_page_destroy();
  load_descriptor_storage_page_destroy();
  descriptor_loader_destroy_source_menu();
  address_checker_destroy();

  cleanup_psbt_data();

  SECURE_FREE_STRING(scanned_mnemonic);

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
  complete_callback = NULL;
}
