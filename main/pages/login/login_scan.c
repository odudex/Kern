// Login "Scan": keyless QR dispatch — load a mnemonic, else a watch-only
// descriptor, else show the raw content as unidentified.

#include "login_scan.h"
#include "../../core/base43.h"
#include "../../core/kef.h"
#include "../../core/registry.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../qr/scanner.h"
#include "../../ui/dialog.h"
#include "../../utils/secure_mem.h"
#include "../home/addresses.h"
#include "../home/home.h"
#include "../shared/descriptor_loader.h"
#include "../shared/kef_decrypt_page.h"
#include "../shared/key_confirmation.h"
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip39.h>
#include <wally_core.h>

static void (*s_return_to_login)(void) = NULL;
static char *s_scan_content = NULL; // raw scan, kept for the unidentified view

static void clear_content(void) {
  if (s_scan_content) {
    free(s_scan_content);
    s_scan_content = NULL;
  }
}

static void finish_to_login(void) {
  void (*ret)(void) = s_return_to_login;
  clear_content();
  s_return_to_login = NULL;
  if (ret)
    ret();
}

/* ---------- Mnemonic sub-flow (mirrors load_menu.c) ---------- */

static void return_from_key_confirmation_cb(void) {
  key_confirmation_page_destroy();
  finish_to_login();
}

static void success_from_key_confirmation_cb(void) {
  key_confirmation_page_destroy();
  clear_content();
  s_return_to_login = NULL;
  home_page_create(lv_screen_active());
  home_page_show();
}

static void return_from_kef_decrypt_cb(void) {
  kef_decrypt_page_destroy();
  finish_to_login();
}

static void success_from_kef_decrypt_cb(const uint8_t *data, size_t len) {
  /* key_confirmation copies data, so create before destroying the kef page */
  key_confirmation_page_create(
      lv_screen_active(), return_from_key_confirmation_cb,
      success_from_key_confirmation_cb, (const char *)data, len);
  key_confirmation_page_show();
  kef_decrypt_page_destroy();
}

/* ---------- Watch-only descriptor sub-flow ---------- */

static void wo_return_from_addresses_cb(void) {
  addresses_page_destroy();
  wallet_clear_watch_only();
  finish_to_login();
}

static void unidentified_dismissed_cb(void *user_data) {
  (void)user_data;
  finish_to_login();
}

static void show_unidentified(void) {
  dialog_show_info("Unidentified content",
                   s_scan_content ? s_scan_content : "(empty)",
                   unidentified_dismissed_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static void show_psbt_needs_key(void) {
  dialog_show_info("PSBT detected", "Load a key first to sign transactions",
                   unidentified_dismissed_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static bool is_psbt_content(const char *content, size_t len) {
  if (!content)
    return false;
  if (len >= 6 && strncmp(content, "cHNidP", 6) == 0)
    return true;
  if (len >= 5 && memcmp(content, "psbt\xff", 5) == 0)
    return true;
  return false;
}

static void wo_validation_cb(descriptor_validation_result_t result,
                             void *user_data) {
  (void)user_data;
  if (result == VALIDATION_SUCCESS) {
    addresses_page_set_descriptor_only(registry_count() - 1);
    addresses_page_create(lv_screen_active(), wo_return_from_addresses_cb);
    addresses_page_show();
    return;
  }

  wallet_clear_watch_only();
  if (result == VALIDATION_PARSE_ERROR) {
    // Not a descriptor either: fall back to showing the raw content.
    show_unidentified();
    return;
  }
  if (result != VALIDATION_USER_DECLINED)
    descriptor_loader_show_error(result);
  finish_to_login();
}

/* ---------- Scan completion dispatch ---------- */

// Returns true if the content was handled as a mnemonic (KEF or plaintext).
static bool try_mnemonic(const char *content, size_t len) {
  const uint8_t *envelope = (const uint8_t *)content;
  size_t envelope_len = len;
  uint8_t *decoded = NULL;
  bool is_kef = kef_is_envelope(envelope, envelope_len);
  if (!is_kef) {
    size_t decoded_len = 0;
    if (base43_decode(content, len, &decoded, &decoded_len) &&
        kef_is_envelope(decoded, decoded_len)) {
      envelope = decoded;
      envelope_len = decoded_len;
      is_kef = true;
    } else {
      free(decoded);
      decoded = NULL;
    }
  }
  if (is_kef) {
    kef_decrypt_page_create(lv_screen_active(), return_from_kef_decrypt_cb,
                            success_from_kef_decrypt_cb, envelope,
                            envelope_len);
    kef_decrypt_page_show();
    free(decoded);
    return true;
  }
  free(decoded);

  // Plaintext / SeedQR: only treat as a mnemonic if it actually validates, so
  // descriptors fall through to the watch-only path.
  char *mnemonic = mnemonic_qr_to_mnemonic(content, len, NULL);
  bool valid = mnemonic && bip39_mnemonic_validate(NULL, mnemonic) == WALLY_OK;
  SECURE_FREE_STRING(mnemonic);
  if (!valid)
    return false;

  key_confirmation_page_create(lv_screen_active(),
                               return_from_key_confirmation_cb,
                               success_from_key_confirmation_cb, content, len);
  key_confirmation_page_show();
  return true;
}

static void on_scan_done(void) {
  size_t len = 0;
  char *content = qr_scanner_get_completed_content_with_len(&len);
  // UR type and descriptor candidate (UR crypto-output/account + plain text)
  // must be read while the scanner state is still valid.
  const char *ur_type = NULL;
  qr_scanner_get_ur_result(&ur_type, NULL, NULL);
  bool psbt_scanned = (ur_type && strcmp(ur_type, "crypto-psbt") == 0) ||
                      is_psbt_content(content, len);
  char *desc_candidate = descriptor_extract_from_scanner();

  qr_scanner_page_hide();
  qr_scanner_page_destroy();

  s_scan_content =
      content; // owned here; freed by finish_to_login/clear_content

  if (psbt_scanned) {
    free(desc_candidate);
    show_psbt_needs_key();
    return;
  }

  if (!content && !desc_candidate) {
    finish_to_login();
    return;
  }

  if (content && try_mnemonic(content, len)) {
    free(desc_candidate);
    return;
  }

  // Not a mnemonic: try a watch-only descriptor. On VALIDATION_PARSE_ERROR the
  // callback shows the raw content as unidentified.
  descriptor_loader_process_string_watch_only(
      desc_candidate ? desc_candidate : content, wo_validation_cb, NULL);
  free(desc_candidate);
}

void login_scan_start(void (*return_to_login_cb)(void)) {
  s_return_to_login = return_to_login_cb;
  clear_content();
  qr_scanner_page_create(lv_screen_active(), on_scan_done);
  qr_scanner_page_show();
}
