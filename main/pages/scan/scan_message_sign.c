/*
 * Review screens for plain message signing and PSBT-based BIP322 requests.
 */

#include "../../core/message_sign.h"
#include "../../core/wallet.h"
#include "../../qr/viewer.h"
#include "../../ui/dialog.h"
#include "../../ui/theme_widgets.h"
#include "scan.h"
#include "scan_internal.h"
#include <lvgl.h>
#include <wally_core.h>

static void message_sign_button_cb(lv_event_t *e);

void scan_message_create_display(void) {
  if (!scan_ctx.screen) {
    return;
  }

  wallet_network_t net = wallet_get_network();
  bool testnet = (net == WALLET_NETWORK_TESTNET);

  char *address = NULL;
  if (!message_sign_get_address(scan_ctx.message.derivation_path, testnet,
                                &address)) {
    dialog_show_error_timeout("Failed to derive address", scan_ctx.return_cb,
                              0);
    return;
  }

  scan_ctx.info_container = theme_create_scroll_column(scan_ctx.screen, 10, 10);

  theme_create_page_title(scan_ctx.info_container, "Sign Message");

  lv_obj_t *path_title =
      theme_create_label(scan_ctx.info_container, "Path:", false);
  theme_apply_label(path_title, true);
  lv_obj_set_style_text_color(path_title, secondary_color(), 0);

  lv_obj_t *path_label = theme_create_label(
      scan_ctx.info_container, scan_ctx.message.derivation_path, false);
  lv_obj_set_width(path_label, LV_PCT(100));

  lv_obj_t *addr_title =
      theme_create_label(scan_ctx.info_container, "Address:", false);
  theme_apply_label(addr_title, true);
  lv_obj_set_style_text_color(addr_title, secondary_color(), 0);

  scan_create_address_label(scan_ctx.info_container, address, highlight_color(),
                            0);

  wally_free_string(address);

  theme_create_separator(scan_ctx.info_container, primary_color());

  lv_obj_t *msg_title =
      theme_create_label(scan_ctx.info_container, "Message:", false);
  theme_apply_label(msg_title, true);
  lv_obj_set_style_text_color(msg_title, secondary_color(), 0);

  lv_obj_t *msg_label = theme_create_label(scan_ctx.info_container,
                                           scan_ctx.message.message, false);
  lv_obj_set_width(msg_label, LV_PCT(100));
  lv_label_set_long_mode(msg_label, LV_LABEL_LONG_WRAP);

  scan_create_sign_action_row(scan_ctx.info_container, message_sign_button_cb);
}

// Review screen for a PSBT-based BIP322 signing request. Signing goes through
// the regular PSBT sign path (scan_psbt_sign_button_cb), so input ownership is
// enforced by psbt_sign's classification and the signed PSBT is exported as
// usual.
void scan_bip322_create_display(void) {
  if (!scan_ctx.screen) {
    return;
  }

  scan_ctx.info_container = theme_create_scroll_column(scan_ctx.screen, 10, 10);

  theme_create_page_title(scan_ctx.info_container, "Sign Message");

  lv_obj_t *addr_title =
      theme_create_label(scan_ctx.info_container, "Address:", false);
  theme_apply_label(addr_title, true);
  lv_obj_set_style_text_color(addr_title, secondary_color(), 0);

  scan_create_address_label(scan_ctx.info_container, scan_ctx.bip322.address,
                            highlight_color(), 0);

  theme_create_separator(scan_ctx.info_container, primary_color());

  lv_obj_t *msg_title =
      theme_create_label(scan_ctx.info_container, "Message:", false);
  theme_apply_label(msg_title, true);
  lv_obj_set_style_text_color(msg_title, secondary_color(), 0);

  lv_obj_t *msg_label = theme_create_label(scan_ctx.info_container,
                                           scan_ctx.bip322.message, false);
  lv_obj_set_width(msg_label, LV_PCT(100));
  lv_label_set_long_mode(msg_label, LV_LABEL_LONG_WRAP);

  scan_create_sign_action_row(scan_ctx.info_container,
                              scan_psbt_sign_button_cb);
}

static void message_sign_button_cb(lv_event_t *e) {
  char *sig_b64 = NULL;
  if (!message_sign_sign(scan_ctx.message.derivation_path,
                         scan_ctx.message.message, &sig_b64)) {
    dialog_show_error_timeout("Failed to sign message", NULL, 2000);
    return;
  }

  scan_ctx.saved_return_cb =
      scan_ctx.complete_cb ? scan_ctx.complete_cb : scan_ctx.return_cb;

  qr_viewer_page_create(lv_screen_active(), sig_b64, "Message Signature",
                        scan_qr_viewer_return_cb);
  wally_free_string(sig_b64);

  scan_page_hide();
  scan_page_destroy();

  qr_viewer_page_show();
}
