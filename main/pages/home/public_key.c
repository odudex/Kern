#include "public_key.h"
#include "../../core/key.h"
#include "../../core/wallet.h"
#include "../../ui/battery.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/settings_row.h"
#include "../../ui/theme.h"
#include "../settings/wallet_settings.h"
#include "../shared/wallet_source_picker.h"
#include <esp_log.h>
#include <lvgl.h>
#include <stdio.h>
#include <wally_core.h>

static lv_obj_t *public_key_screen = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *settings_button = NULL;
static lv_obj_t *content_wrapper = NULL;
static lv_obj_t *picker_row = NULL;
static lv_obj_t *multisig_switch = NULL;
static wallet_source_picker_t *picker = NULL;
static wallet_source_t current_source = {0, 0};
static bool multisig_mode = false;
static void (*return_callback)(void) = NULL;

// Singlesig dropdown index -> BIP purpose number.
static const uint32_t PURPOSE_FOR_SOURCE[4] = {
    84, /* 0 Native SegWit  */
    86, /* 1 Taproot        */
    44, /* 2 Legacy         */
    49, /* 3 Nested SegWit  */
};

static void back_button_cb(lv_event_t *e) {
  (void)e;
  if (return_callback) {
    return_callback();
  }
}

static void return_from_wallet_settings_cb(void) {
  wallet_settings_page_destroy();
  // Save callback before destroy clears it
  void (*saved_callback)(void) = return_callback;
  // Recreate page to refresh with updated key/wallet data
  public_key_page_destroy();
  public_key_page_create(lv_screen_active(), saved_callback);
  public_key_page_show();
}

static void settings_button_cb(lv_event_t *e) {
  (void)e;
  public_key_page_hide();
  wallet_settings_page_create(lv_screen_active(),
                              return_from_wallet_settings_cb);
  wallet_settings_page_show();
}

static void render_xpub(void) {
  if (!content_wrapper)
    return;
  lv_obj_clean(content_wrapper);

  uint32_t coin = (wallet_get_network() == WALLET_NETWORK_MAINNET) ? 0 : 1;

  char derivation_path[64];
  char derivation_compact[48];
  if (multisig_mode) {
    wallet_bip48_script_t script =
        wallet_source_picker_bip48_script(current_source.source);
    uint32_t subscript = (script == WALLET_BIP48_P2WSH) ? 2 : 1;
    snprintf(derivation_path, sizeof(derivation_path), "m/48'/%u'/%u'/%u'",
             coin, current_source.account, subscript);
    snprintf(derivation_compact, sizeof(derivation_compact), "48h/%uh/%uh/%uh",
             coin, current_source.account, subscript);
  } else {
    uint32_t purpose = PURPOSE_FOR_SOURCE[current_source.source];
    snprintf(derivation_path, sizeof(derivation_path), "m/%u'/%u'/%u'", purpose,
             coin, current_source.account);
    snprintf(derivation_compact, sizeof(derivation_compact), "%uh/%uh/%uh",
             purpose, coin, current_source.account);
  }

  char fingerprint_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  if (!key_get_fingerprint_hex(fingerprint_hex))
    return;

  char *xpub_str = NULL;
  if (!key_get_xpub(derivation_path, &xpub_str)) {
    lv_obj_t *error_value =
        theme_create_label(content_wrapper, "Error: Failed to get XPUB", false);
    lv_obj_set_style_text_color(error_value, error_color(), 0);
    lv_obj_set_width(error_value, LV_PCT(100));
    return;
  }

  char key_origin[512];
  snprintf(key_origin, sizeof(key_origin), "[%s/%s]%s", fingerprint_hex,
           derivation_compact, xpub_str);

  // Cap by both width and height so the QR doesn't crowd out the xpub label
  // on square panels (wave_4b is 720x720 and has more rows above the QR).
  int32_t w_based = theme_get_screen_width() * 60 / 100;
  int32_t h_based = theme_get_screen_height() * 45 / 100;
  int32_t square_size = (w_based < h_based) ? w_based : h_based;

  lv_obj_t *qr_container = lv_obj_create(content_wrapper);
  lv_obj_set_size(qr_container, square_size, square_size);
  lv_obj_set_style_bg_color(qr_container, lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_bg_opa(qr_container, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(qr_container, 0, 0);
  lv_obj_set_style_pad_all(qr_container, 15, 0);
  lv_obj_set_style_radius(qr_container, 0, 0);
  lv_obj_clear_flag(qr_container, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_update_layout(qr_container);

  int32_t container_width = lv_obj_get_content_width(qr_container);
  int32_t container_height = lv_obj_get_content_height(qr_container);
  int32_t qr_size =
      (container_width < container_height) ? container_width : container_height;

  lv_obj_t *qr = lv_qrcode_create(qr_container);
  lv_qrcode_set_size(qr, qr_size);
  lv_qrcode_update(qr, key_origin, strlen(key_origin));
  lv_obj_center(qr);

  lv_obj_t *xpub_value = theme_create_label(content_wrapper, xpub_str, false);
  lv_obj_set_width(xpub_value, LV_PCT(95));
  lv_label_set_long_mode(xpub_value, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(xpub_value, LV_TEXT_ALIGN_CENTER, 0);

  wally_free_string(xpub_str);
}

// BIP48 only covers SegWit multisig (P2WSH, P2SH-P2WSH). When the user is in
// singlesig mode on Taproot or Legacy, disable the toggle so they cannot
// flip into a multisig variant that does not exist for those script types.
// Always enabled in multisig mode so the user can exit.
static void update_multisig_switch_state(void) {
  if (!multisig_switch)
    return;
  bool enabled =
      multisig_mode || current_source.source == 0 || current_source.source == 3;
  if (enabled)
    lv_obj_clear_state(multisig_switch, LV_STATE_DISABLED);
  else
    lv_obj_add_state(multisig_switch, LV_STATE_DISABLED);
}

static void picker_changed_cb(const wallet_source_t *src, void *user_data) {
  (void)user_data;
  current_source = *src;
  update_multisig_switch_state();
  render_xpub();
}

static void multisig_switch_cb(lv_event_t *e) {
  (void)e;
  bool now_multisig = lv_obj_has_state(multisig_switch, LV_STATE_CHECKED);
  if (now_multisig == multisig_mode)
    return;
  multisig_mode = now_multisig;

  // Recreate the picker with the new mode. Reset the script index (option
  // sets differ between modes); preserve the account so the user does not
  // have to re-enter it on every toggle.
  wallet_source_t carry_over = {0, current_source.account};
  wallet_source_picker_destroy(picker);
  current_source = carry_over;
  picker = wallet_source_picker_create(
      picker_row,
      multisig_mode ? WALLET_PICKER_MULTISIG_BIP48 : WALLET_PICKER_SINGLESIG,
      &current_source, picker_changed_cb, NULL);
  update_multisig_switch_state();
  render_xpub();
}

void public_key_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded() || !wallet_is_initialized())
    return;

  return_callback = return_cb;
  current_source = (wallet_source_t){0, 0};
  multisig_mode = false;

  public_key_screen = lv_obj_create(parent);
  lv_obj_set_size(public_key_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(public_key_screen);
  lv_obj_set_style_pad_all(public_key_screen, theme_get_default_padding(), 0);
  lv_obj_set_flex_flow(public_key_screen, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(public_key_screen, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(public_key_screen, theme_get_default_padding(), 0);

  // Key info header at top
  lv_obj_t *header = ui_key_info_create(public_key_screen);
  ui_battery_create(header);

  // Top row: source picker. Held as a static (`picker_row`) because the
  // multisig toggle recreates the picker into the same row.
  picker_row = lv_obj_create(public_key_screen);
  lv_obj_set_size(picker_row, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(picker_row);
  lv_obj_set_flex_flow(picker_row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(picker_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  picker =
      wallet_source_picker_create(picker_row, WALLET_PICKER_SINGLESIG,
                                  &current_source, picker_changed_cb, NULL);

  // Multisig toggle: switches the picker between singlesig (BIP44/49/84/86)
  // and multisig BIP48 (P2WSH / P2SH-P2WSH). Disabled for Taproot / Legacy
  // since BIP48 only covers SegWit multisig.
  lv_obj_t *multisig_row = settings_row_toggle(
      public_key_screen, "Multisig", false, multisig_switch_cb, "Multisig",
      "BIP48 cosigner xpub for multisig wallets. SegWit only (Native or "
      "Nested).");
  // Drop the touch-target min_height; the public_key page is space-constrained
  // and the switch has its own hit area.
  lv_obj_set_style_min_height(multisig_row, 0, 0);
  multisig_switch = settings_row_get_widget(multisig_row);
  update_multisig_switch_state();

  content_wrapper = lv_obj_create(public_key_screen);
  lv_obj_set_size(content_wrapper, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(content_wrapper);
  lv_obj_set_flex_flow(content_wrapper, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content_wrapper, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(content_wrapper, theme_get_default_padding(), 0);

  render_xpub();

  // Back button (on parent for absolute positioning)
  back_button = ui_create_back_button(parent, back_button_cb);

  // Settings button at top-right
  settings_button = ui_create_settings_button(parent, settings_button_cb);
}

void public_key_page_show(void) {
  if (public_key_screen) {
    lv_obj_clear_flag(public_key_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void public_key_page_hide(void) {
  if (public_key_screen) {
    lv_obj_add_flag(public_key_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void public_key_page_destroy(void) {
  wallet_source_picker_destroy(picker);
  picker = NULL;

  if (back_button) {
    lv_obj_del(back_button);
    back_button = NULL;
  }
  if (settings_button) {
    lv_obj_del(settings_button);
    settings_button = NULL;
  }
  if (public_key_screen) {
    lv_obj_del(public_key_screen);
    public_key_screen = NULL;
  }
  content_wrapper = NULL;
  picker_row = NULL;
  multisig_switch = NULL;
  return_callback = NULL;
  current_source = (wallet_source_t){0, 0};
  multisig_mode = false;
}
