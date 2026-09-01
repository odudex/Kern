/*
 * Handlers for scanned descriptors, addresses and mnemonics.
 */

#include "../../core/key.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../ui/dialog.h"
#include "../../ui/theme.h"
#include "../../utils/secure_mem.h"
#include "../shared/address_checker.h"
#include "../shared/descriptor_loader.h"
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
static void descriptor_load_done_cb(void *user_data) {
  (void)user_data;
  if (scan_ctx.complete_cb)
    scan_ctx.complete_cb();
  else if (scan_ctx.return_cb)
    scan_ctx.return_cb();
}

static void scan_descriptor_validation_cb(descriptor_validation_result_t result,
                                          void *user_data) {
  (void)user_data;

  if (result == VALIDATION_SUCCESS) {
    dialog_show_info("Descriptor Loaded", "Wallet descriptor added to session",
                     descriptor_load_done_cb, NULL, DIALOG_STYLE_FULLSCREEN);
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
  scan_ctx.scanned_mnemonic = mnemonic;

  char msg[256];
  snprintf(
      msg, sizeof(msg),
      "Replace current key?\n\n"
      "  %s > #%06X %s#\n\n"
      "Passphrase and descriptors will be discarded.",
      current_fp,
      (unsigned)((lv_color_to_32(highlight_color(), LV_OPA_COVER).red << 16) |
                 (lv_color_to_32(highlight_color(), LV_OPA_COVER).green << 8) |
                 lv_color_to_32(highlight_color(), LV_OPA_COVER).blue),
      new_fp);

  dialog_show_confirm(msg, mnemonic_confirm_cb, NULL, DIALOG_STYLE_FULLSCREEN);
}
