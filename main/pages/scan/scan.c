/*
 * Scan Page
 * Universal QR content detection: PSBT, message, descriptor, address, mnemonic.
 * This file owns the page lifecycle, the shared flow context, and the
 * two-layer content dispatch; the review and signing screens live in the
 * scan_*.c siblings.
 */

#include "scan.h"
#include "../../../components/cUR/src/types/bytes_type.h"
#include "../../../components/cUR/src/types/psbt.h"
#include "../../core/bip322.h"
#include "../../core/kef.h"
#include "../../core/key.h"
#include "../../core/message_sign.h"
#include "../../core/psbt.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../qr/parser.h"
#include "../../qr/scanner.h"
#include "../../ui/dialog.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "../load_descriptor_storage.h"
#include "../shared/address_checker.h"
#include "../shared/descriptor_loader.h"
#include "../shared/kef_decrypt_page.h"
#include "scan_internal.h"
#include "sd_card.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wally_address.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_psbt.h>

scan_ctx_t scan_ctx = {
    .export_dir = SD_CARD_MOUNT_POINT,
    .qr_format = FORMAT_NONE,
};

// Shows a progress dialog and runs cb from a one-shot timer so LVGL renders
// the dialog before the slow work starts.
void scan_defer_with_progress(const char *title, const char *text,
                              lv_timer_cb_t cb) {
  scan_ctx.progress_dialog =
      dialog_show_progress(title, text, DIALOG_STYLE_OVERLAY);
  lv_timer_t *t = lv_timer_create(cb, 50, NULL);
  lv_timer_set_repeat_count(t, 1);
}

static void scan_kef_return_cb(void);
static void scan_kef_success_cb(const uint8_t *data, size_t len);

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

void scan_dismiss_progress(void) {
  if (scan_ctx.progress_dialog) {
    lv_obj_del(scan_ctx.progress_dialog);
    scan_ctx.progress_dialog = NULL;
  }
}

// Classify an already-assembled blob and route it to the matching review
// screen. Shared by the QR scanner and the SD-card loader, so it must not touch
// any qr_scanner_page_* state — the caller tears the scanner down first. Takes
// ownership of qr_content (frees it). When parse_success is already true on
// entry (a binary PSBT decoded by layer 1), qr_content must be NULL.
static void finish_dispatch(char *qr_content, size_t qr_content_len,
                            bool parse_success, int detected_format) {
  scan_ctx.is_message_sign = false;

  // Layer 2: plaintext/binary heuristics — try each parser in priority order
  if (!parse_success && qr_content) {
    // 1. Message
    if (message_sign_parse(qr_content, &scan_ctx.message)) {
      scan_ctx.is_message_sign = true;
      parse_success = true;
    }

    // 2. PSBT (base64)
    if (!parse_success) {
      parse_success = scan_psbt_parse_base64(qr_content);
    }

    // 3. Descriptor
    if (!parse_success && (is_descriptor_prefix(qr_content) ||
                           is_bluewallet_descriptor(qr_content))) {
      scan_handle_descriptor(qr_content);
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
          scan_handle_address(qr_content);
        } else {
          dialog_show_error_timeout(
              addr_is_mainnet ? "Address is for Mainnet, wallet is on Testnet"
                              : "Address is for Testnet, wallet is on Mainnet",
              scan_ctx.return_cb, 3000);
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
        scan_handle_mnemonic(qr_content, qr_content_len);
        SECURE_FREE_STRING(qr_content);
        return;
      }
      SECURE_FREE_STRING(mnemonic);
    }

    // 6. Encrypted (KEF) envelope — e.g. a base64-armored descriptor or
    // mnemonic backup. Tried last so a base64 PSBT is recognized as a PSBT
    // first. On success the decrypted payload is re-dispatched.
    if (!parse_success) {
      size_t env_len = 0;
      uint8_t *envelope = kef_envelope_from_bytes((const uint8_t *)qr_content,
                                                  qr_content_len, &env_len);
      if (envelope) {
        SECURE_FREE_STRING(qr_content);
        kef_decrypt_page_create(lv_screen_active(), scan_kef_return_cb,
                                scan_kef_success_cb, envelope, env_len);
        kef_decrypt_page_show();
        free(envelope);
        return;
      }
    }

    SECURE_FREE_STRING(qr_content);
  }

  if (parse_success) {
    if (scan_ctx.is_message_sign) {
      scan_message_create_display();
    } else {
      scan_ctx.qr_format = detected_format;

      if (scan_psbt_check_mismatch()) {
        return;
      }

      if (bip322_detect(scan_ctx.psbt)) {
        if (!bip322_parse(scan_ctx.psbt, scan_ctx.is_testnet,
                          &scan_ctx.bip322)) {
          dialog_show_error_timeout("Invalid BIP322 message request",
                                    scan_ctx.return_cb, 0);
          return;
        }
        scan_ctx.is_bip322 = true;
        scan_bip322_create_display();
        return;
      }

      scan_psbt_resume_review(true);
    }
  } else {
    dialog_show_error_timeout("Unrecognized format", scan_ctx.return_cb, 0);
  }
}

// Camera teardown plus payload parsing — for large PSBTs this can take over a
// second, so it runs behind the progress dialog from a one-shot timer.
static void process_scan_result(void) {
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
            scan_psbt_cleanup();
            parse_success =
                psbt_parse_payload(psbt_bytes, psbt_len, &scan_ctx.psbt);
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
          scan_handle_descriptor(desc);
          free(desc);
        } else {
          dialog_show_error_timeout("Failed to parse descriptor",
                                    scan_ctx.return_cb, 0);
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
    char bbqr_file_type = qr_scanner_get_bbqr_file_type();
    qr_content = qr_scanner_get_completed_content_with_len(&qr_content_len);
    if (qr_content && qr_content_len > 0) {
      scan_psbt_cleanup();
      parse_success = psbt_parse_payload((const uint8_t *)qr_content,
                                         qr_content_len, &scan_ctx.psbt);
      if (parse_success) {
        free(qr_content);
        qr_content = NULL;
      } else if (bbqr_file_type == 'P') {
        /* Header explicitly says PSBT — don't let the text detectors (or
         * the KEF prompt) misclassify raw PSBT bytes. */
        free(qr_content);
        qr_scanner_page_hide();
        qr_scanner_page_destroy();
        dialog_show_error_timeout("Invalid PSBT data", scan_ctx.return_cb, 0);
        return;
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

static void deferred_scan_process_cb(lv_timer_t *timer) {
  (void)timer;
  process_scan_result();
  scan_dismiss_progress();
}

static void return_from_qr_scanner_cb(void) {
  if (!qr_scanner_has_completed_result()) {
    qr_scanner_page_hide();
    qr_scanner_page_destroy();
    if (scan_ctx.return_cb)
      scan_ctx.return_cb();
    return;
  }

  // Parsing large PSBTs can take over a second — show a progress dialog and
  // defer the work to a one-shot timer so LVGL gets to render it first.
  scan_defer_with_progress("Scan", "Processing...", deferred_scan_process_cb);
}

// Resets the signed-PSBT export context. A scanned PSBT has no source folder
// or file name — a saved signature lands at the card root in binary, unless
// layer 2 detects base64 text; a file load passes the folder it came from and
// its name.
static void reset_export_context(const char *save_dir,
                                 const char *source_name) {
  scan_ctx.source_base64 = false;
  snprintf(scan_ctx.export_dir, sizeof(scan_ctx.export_dir), "%s",
           save_dir ? save_dir : SD_CARD_MOUNT_POINT);
  snprintf(scan_ctx.source_name, sizeof(scan_ctx.source_name), "%s",
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

static void scan_kef_return_cb(void) {
  kef_decrypt_page_destroy();
  if (scan_ctx.return_cb)
    scan_ctx.return_cb();
}

static void scan_kef_success_cb(const uint8_t *data, size_t len) {
  // Copy before destroying the page (data is page-owned) and NUL-terminate so
  // the layer-2 text detectors can treat it as a C string.
  char *content = malloc(len + 1);
  if (content) {
    memcpy(content, data, len);
    content[len] = '\0';
  }
  kef_decrypt_page_destroy();
  if (!content) {
    dialog_show_error_timeout("Out of memory", scan_ctx.return_cb, 0);
    return;
  }
  // The decrypted payload is a descriptor (text) or mnemonic (compact SeedQR
  // bytes) — re-run the layer-2 heuristics on it.
  finish_dispatch(content, len, false, FORMAT_NONE);
}

void scan_load_content(lv_obj_t *parent, const uint8_t *data, size_t len,
                       const char *save_dir, const char *source_name,
                       void (*return_cb)(void), void (*complete_cb)(void)) {
  if (!parent || !data || len == 0)
    return;

  reset_export_context(save_dir, source_name);
  scan_ctx.return_cb = return_cb;
  scan_ctx.complete_cb = complete_cb;
  scan_ctx.screen = theme_create_page_container(parent);

  // A file may hold a serialized binary PSBT — try that first (mirroring the
  // BBQr path); otherwise normalize the text for the layer-2 detectors.
  scan_psbt_cleanup();
  bool parse_success = psbt_parse_payload(data, len, &scan_ctx.psbt);

  char *content = NULL;
  if (!parse_success) {
    content = normalize_file_text(data, len);
    if (!content) {
      dialog_show_error_timeout("No loadable content in file",
                                scan_ctx.return_cb, 0);
      return;
    }
  }

  finish_dispatch(content, content ? strlen(content) : len, parse_success,
                  FORMAT_NONE);
}

void scan_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded()) {
    return;
  }

  scan_ctx.return_cb = return_cb;
  scan_ctx.complete_cb = NULL;
  reset_export_context(NULL, NULL);

  scan_ctx.screen = theme_create_page_container(parent);
  qr_scanner_page_create(NULL, return_from_qr_scanner_cb);
  qr_scanner_page_show();
}

void scan_page_show(void) {
  if (scan_ctx.screen) {
    lv_obj_clear_flag(scan_ctx.screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void scan_page_hide(void) {
  if (scan_ctx.screen) {
    lv_obj_add_flag(scan_ctx.screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void scan_page_destroy(void) {
  scan_dismiss_progress();
  scan_export_destroy_menu();
  qr_scanner_page_destroy();
  load_descriptor_storage_page_destroy();
  descriptor_loader_destroy_source_menu();
  address_checker_destroy();

  scan_psbt_cleanup();

  SECURE_FREE_STRING(scan_ctx.scanned_mnemonic);

  if (scan_ctx.tx_diagram) {
    sankey_diagram_destroy(scan_ctx.tx_diagram);
    scan_ctx.tx_diagram = NULL;
  }

  scan_ctx.info_container = NULL;

  if (scan_ctx.screen) {
    lv_obj_del(scan_ctx.screen);
    scan_ctx.screen = NULL;
  }

  scan_ctx.return_cb = NULL;
  scan_ctx.complete_cb = NULL;
}
