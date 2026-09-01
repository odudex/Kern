/*
 * PSBT signing and export of the signed result as a QR code or an SD file.
 */

#include "../../core/psbt.h"
#include "../../core/settings.h"
#include "../../qr/parser.h"
#include "../../qr/viewer.h"
#include "../../ui/dialog.h"
#include "../../ui/menu.h"
#include "scan.h"
#include "scan_internal.h"
#include "sd_card.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>
#include <wally_psbt.h>

static void show_export_choice(void);

void scan_export_destroy_menu(void) {
  if (scan_ctx.export_menu) {
    ui_menu_destroy(scan_ctx.export_menu);
    scan_ctx.export_menu = NULL;
  }
}

static void partial_sign_ack_cb(void *user_data) {
  (void)user_data;
  show_export_choice();
}

static void deferred_sign_cb(lv_timer_t *timer) {
  (void)timer;

  if (!scan_ctx.psbt) {
    scan_dismiss_progress();
    dialog_show_error_timeout("No PSBT loaded", NULL, 2000);
    return;
  }

  psbt_sign_policy_t sign_policy = {
      .allow_unsafe = settings_get_permissive_signing(),
      .allow_expected_owned = settings_get_expected_owned_signing(),
  };
  psbt_sign_result_t sign_result;
  size_t signatures_added =
      psbt_sign(scan_ctx.psbt, scan_ctx.is_testnet, sign_policy, &sign_result);

  if (signatures_added == 0) {
    scan_dismiss_progress();
    dialog_show_error_timeout("Failed to sign PSBT", NULL, 2000);
    return;
  }

  if (scan_ctx.signed_psbt_base64) {
    wally_free_string(scan_ctx.signed_psbt_base64);
    scan_ctx.signed_psbt_base64 = NULL;
  }

  // Trimming rebuilds the PSBT from its tx and drops global unknowns, which
  // would strip the BIP322 message field — export those untrimmed (tiny).
  struct wally_psbt *trimmed_psbt =
      scan_ctx.is_bip322 ? NULL : psbt_trim(scan_ctx.psbt);
  struct wally_psbt *export_psbt = trimmed_psbt ? trimmed_psbt : scan_ctx.psbt;

  int ret = wally_psbt_to_base64(export_psbt, 0, &scan_ctx.signed_psbt_base64);

  if (trimmed_psbt) {
    wally_psbt_free(trimmed_psbt);
  }

  scan_dismiss_progress();

  if (ret != WALLY_OK) {
    dialog_show_error_timeout("Failed to encode PSBT", NULL, 2000);
    return;
  }

  scan_ctx.saved_return_cb =
      scan_ctx.complete_cb ? scan_ctx.complete_cb : scan_ctx.return_cb;

  // A PSBT built so that refused inputs pick up a signature from a key used
  // elsewhere in the same transaction is not an accident. The signatures were
  // stripped; say so, because the next PSBT from that source is suspect too.
  if (sign_result.blocked) {
    char body[320];
    snprintf(body, sizeof(body),
             "%zu input%s that this wallet refused to sign attempted to "
             "collect a signature from a key used by another input.\n\n"
             "Those signatures were discarded. A PSBT arranged this way does "
             "not come from an honest coordinator -- treat its source as "
             "compromised.",
             sign_result.blocked, sign_result.blocked == 1 ? "" : "s");
    dialog_show_info("Signatures discarded", body, partial_sign_ack_cb, NULL,
                     DIALOG_STYLE_FULLSCREEN);
    return;
  }

  // Exporting a partly-signed PSBT without saying so is what an attacker
  // harvesting one signature per session relies on: each round looks like a
  // clean success. Name the shortfall before the export menu appears.
  if (sign_result.signed_ok < sign_result.attempted) {
    char body[320];
    snprintf(body, sizeof(body),
             "%zu of %zu inputs belonging to this wallet did not receive a "
             "signature.\n\n"
             "The exported PSBT is incomplete. If you did not expect this, do "
             "not treat the transaction as reviewed -- re-export it from the "
             "coordinator with full previous transactions and try again.",
             sign_result.attempted - sign_result.signed_ok,
             sign_result.attempted);
    dialog_show_info("Incomplete signing", body, partial_sign_ack_cb, NULL,
                     DIALOG_STYLE_FULLSCREEN);
    return;
  }

  show_export_choice();
}

// Tears down the chooser, then returns to the caller that opened the
// scan/sign flow — the return callback owns scan_page_destroy(). Used once a
// signed PSBT has been exported (QR or SD) or the user backs out of the
// export choice.
static void finish_export(void) {
  scan_export_destroy_menu();
  if (scan_ctx.saved_return_cb) {
    void (*cb)(void) = scan_ctx.saved_return_cb;
    scan_ctx.saved_return_cb = NULL;
    cb();
  }
}

static void export_choice_back_cb(void) { finish_export(); }

static void export_show_qr_cb(void) {
  scan_export_destroy_menu();

  int export_format =
      (scan_ctx.qr_format == -1) ? FORMAT_NONE : scan_ctx.qr_format;

  // File-loaded PSBTs carry no source QR format — default to UR so the
  // export animates instead of cramming one dense raw QR.
  if (export_format == FORMAT_NONE && scan_ctx.source_name[0])
    export_format = FORMAT_UR;

  if (!qr_viewer_page_create_with_format(
          lv_screen_active(), export_format, scan_ctx.signed_psbt_base64,
          "Signed PSBT", scan_qr_viewer_return_cb)) {
    dialog_show_error_timeout("Failed to create QR viewer", scan_ctx.return_cb,
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

// Writes the signed PSBT to scan_ctx.export_dir under an auto-generated,
// non-clobbering name, mirroring the source encoding — base64 text saves as
// .txt, binary as .psbt. Unlike QR export there is no payload-size pressure,
// so the full PSBT is serialized rather than the trimmed copy.
static void deferred_export_save_cb(lv_timer_t *timer) {
  (void)timer;

  if (!scan_ctx.psbt) {
    scan_dismiss_progress();
    dialog_show_error_timeout("No PSBT loaded", NULL, 2000);
    return;
  }

  // The card may have been swapped (no card-detect line) — remount fresh.
  esp_err_t mret = sd_card_remount();
  scan_dismiss_progress();
  if (mret != ESP_OK) {
    dialog_show_error_timeout("No SD card", show_export_choice, 0);
    return;
  }

  // Derive a stem from the original file name (extension stripped); when there
  // is none (QR source) the file is numbered instead.
  char base[96];
  base[0] = '\0';
  if (scan_ctx.source_name[0]) {
    size_t blen = strlen(scan_ctx.source_name);
    const char *dot = strrchr(scan_ctx.source_name, '.');
    if (dot && dot != scan_ctx.source_name)
      blen = (size_t)(dot - scan_ctx.source_name);
    if (blen >= sizeof(base))
      blen = sizeof(base) - 1;
    memcpy(base, scan_ctx.source_name, blen);
    base[blen] = '\0';
  }

  const char *ext = scan_ctx.source_base64 ? "txt" : "psbt";
  char path[700];
  bool found = false;
  for (int n = 1; n <= 1000; n++) {
    if (base[0]) {
      if (n == 1)
        snprintf(path, sizeof(path), "%s/signed-%s.%s", scan_ctx.export_dir,
                 base, ext);
      else
        snprintf(path, sizeof(path), "%s/signed-%s-%d.%s", scan_ctx.export_dir,
                 base, n, ext);
    } else {
      snprintf(path, sizeof(path), "%s/signed-%d.%s", scan_ctx.export_dir, n,
               ext);
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
  if (scan_ctx.source_base64) {
    char *full_b64 = NULL;
    if (wally_psbt_to_base64(scan_ctx.psbt, 0, &full_b64) != WALLY_OK) {
      dialog_show_error_timeout("Failed to encode PSBT", show_export_choice, 0);
      return;
    }
    wret =
        sd_card_write_file(path, (const uint8_t *)full_b64, strlen(full_b64));
    wally_free_string(full_b64);
  } else {
    size_t bin_len = 0;
    if (wally_psbt_get_length(scan_ctx.psbt, 0, &bin_len) != WALLY_OK) {
      dialog_show_error_timeout("Failed to encode PSBT", show_export_choice, 0);
      return;
    }
    uint8_t *bin = malloc(bin_len);
    if (!bin) {
      dialog_show_error_timeout("Out of memory", show_export_choice, 0);
      return;
    }
    size_t written = 0;
    if (wally_psbt_to_bytes(scan_ctx.psbt, 0, bin, bin_len, &written) !=
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
  scan_export_destroy_menu();

  // Remounting probes the card and can take a while — show progress and defer
  // the work so LVGL gets to render it first.
  scan_defer_with_progress("Save", "Saving...", deferred_export_save_cb);
}

// Offers the signed PSBT as a QR code or an SD-card file. Shown over the
// (hidden) review screen so a back-out can still return cleanly.
static void show_export_choice(void) {
  scan_page_hide();

  scan_ctx.export_menu = ui_menu_create(
      lv_screen_active(), "Export Signed PSBT", export_choice_back_cb);
  if (!scan_ctx.export_menu) {
    export_show_qr_cb(); // fall back to the QR viewer if the menu can't build
    return;
  }
  ui_menu_add_entry(scan_ctx.export_menu, "Show QR code", export_show_qr_cb);
  ui_menu_add_entry(scan_ctx.export_menu, "Save to SD card", export_save_sd_cb);
  ui_menu_show(scan_ctx.export_menu);
}

void scan_psbt_sign_button_cb(lv_event_t *e) {
  (void)e;
  if (!scan_ctx.psbt) {
    dialog_show_error_timeout("No PSBT loaded", NULL, 2000);
    return;
  }

  // Signing big PSBTs can take a few seconds — show a progress dialog and
  // defer the work to a one-shot timer so LVGL gets to render it first.
  scan_defer_with_progress("Sign", "Processing...", deferred_sign_cb);
}

void scan_qr_viewer_return_cb(void) {
  qr_viewer_page_destroy();
  if (scan_ctx.saved_return_cb) {
    void (*callback)(void) = scan_ctx.saved_return_cb;
    scan_ctx.saved_return_cb = NULL;
    callback();
  }
}
