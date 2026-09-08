/*
 * Handlers for scanned descriptors, addresses and mnemonics.
 */

#include "../../core/key.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../ui/assets/icons.h"
#include "../../ui/dialog.h"
#include "../../ui/theme.h"
#include "../../utils/secure_mem.h"
#include "../shared/address_checker.h"
#include "../shared/descriptor_loader.h"
#include "kern_wally.h"
#include "scan_internal.h"
#include <lvgl.h>
#include <stdio.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>

// A descriptor finished loading — nothing left to browse for, so return to the
// opener (home) when a completion callback is set; the QR scanner path has none
// and falls back to its own return.
static void descriptor_load_done_cb(void) {
  if (scan_ctx.complete_cb)
    scan_ctx.complete_cb();
  else if (scan_ctx.return_cb)
    scan_ctx.return_cb();
}

static void scan_descriptor_validation_cb(descriptor_validation_result_t result,
                                          void *user_data) {
  (void)user_data;

  if (result == VALIDATION_SUCCESS) {
    descriptor_loader_show_loaded_menu(descriptor_load_done_cb);
    return;
  }

  descriptor_loader_show_error(result);
  if (scan_ctx.return_cb)
    scan_ctx.return_cb();
}

void scan_handle_descriptor(const char *descriptor_str) {
  descriptor_loader_process_string(descriptor_str,
                                   scan_descriptor_validation_cb, NULL);
}

static void address_found_cb(void) {
  address_checker_destroy();
  if (scan_ctx.return_cb)
    scan_ctx.return_cb();
}

static void address_not_found_cb(void) {
  address_checker_destroy();
  if (scan_ctx.return_cb)
    scan_ctx.return_cb();
}

void scan_handle_address(const char *content) {
  address_checker_check(content, address_found_cb, address_not_found_cb);
}

static void mnemonic_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;

  if (!confirmed || !scan_ctx.scanned_mnemonic) {
    SECURE_FREE_STRING(scan_ctx.scanned_mnemonic);
    if (scan_ctx.return_cb)
      scan_ctx.return_cb();
    return;
  }

  wallet_network_t net = wallet_get_network();

  // Unload current state
  wallet_unload();

  // Load new mnemonic (no passphrase, will use current network)
  if (!key_load_from_mnemonic(scan_ctx.scanned_mnemonic, NULL,
                              net == WALLET_NETWORK_TESTNET)) {
    SECURE_FREE_STRING(scan_ctx.scanned_mnemonic);
    dialog_show_error_timeout("Failed to load mnemonic", scan_ctx.return_cb, 0);
    return;
  }

  if (!wallet_init(net)) {
    SECURE_FREE_STRING(scan_ctx.scanned_mnemonic);
    dialog_show_error_timeout("Failed to initialize wallet", scan_ctx.return_cb,
                              0);
    return;
  }

  SECURE_FREE_STRING(scan_ctx.scanned_mnemonic);

  // Return to home — it will recreate with new key info
  if (scan_ctx.return_cb)
    scan_ctx.return_cb();
}

void scan_handle_mnemonic(const char *data, size_t len) {
  char *mnemonic = mnemonic_qr_to_mnemonic(data, len, NULL);
  if (!mnemonic || bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    SECURE_FREE_STRING(mnemonic);
    dialog_show_error_timeout("Invalid mnemonic", scan_ctx.return_cb, 0);
    return;
  }

  // Get current fingerprint
  char current_fp[9];
  if (!key_get_fingerprint_hex(current_fp))
    strcpy(current_fp, "????????");

  char new_fp[9];
  if (!key_mnemonic_fingerprint_hex(mnemonic, new_fp)) {
    SECURE_FREE_STRING(mnemonic);
    dialog_show_error_timeout("Failed to process mnemonic", scan_ctx.return_cb,
                              0);
    return;
  }

  // Store mnemonic for confirmation callback
  scan_ctx.scanned_mnemonic = mnemonic;

  lv_color32_t c = lv_color_to_32(highlight_color(), LV_OPA_COVER);
  uint32_t highlight = (c.red << 16) | (c.green << 8) | c.blue;

  char msg[256];
  snprintf(msg, sizeof(msg),
           "Replace current key?\n\n" ICON_FINGERPRINT " %s\n" LV_SYMBOL_DOWN
           "\n#%06X " ICON_FINGERPRINT " %s#\n\n"
           "Passphrase and descriptors will be discarded.",
           current_fp, (unsigned)highlight, new_fp);

  dialog_show_confirm(msg, mnemonic_confirm_cb, NULL, DIALOG_STYLE_FULLSCREEN);
}
