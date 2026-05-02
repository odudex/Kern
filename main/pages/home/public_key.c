#include "public_key.h"
#include "../../core/key.h"
#include "../../core/wallet.h"
#include "../../ui/battery.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
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
static wallet_source_picker_t *picker = NULL;
static wallet_source_t current_source = {0, 0};
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
  uint32_t purpose = PURPOSE_FOR_SOURCE[current_source.source];

  char derivation_path[48];
  snprintf(derivation_path, sizeof(derivation_path), "m/%u'/%u'/%u'", purpose,
           coin, current_source.account);
  char derivation_compact[32];
  snprintf(derivation_compact, sizeof(derivation_compact), "%uh/%uh/%uh",
           purpose, coin, current_source.account);

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

  int32_t square_size = theme_get_screen_width() * 60 / 100;

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

static void picker_changed_cb(const wallet_source_t *src, void *user_data) {
  (void)user_data;
  current_source = *src;
  render_xpub();
}

void public_key_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded() || !wallet_is_initialized())
    return;

  return_callback = return_cb;
  current_source = (wallet_source_t){0, 0};

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

  // Top row: source picker (singlesig only — public_key generates xpubs for
  // coordinators, not for verifying existing wallets, so descriptor entries
  // would not produce a meaningful display).
  lv_obj_t *top_row = lv_obj_create(public_key_screen);
  lv_obj_set_size(top_row, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(top_row);
  lv_obj_set_flex_flow(top_row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(top_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  picker =
      wallet_source_picker_create(top_row, WALLET_PICKER_SINGLESIG,
                                  &current_source, picker_changed_cb, NULL);

  content_wrapper = lv_obj_create(public_key_screen);
  lv_obj_set_size(content_wrapper, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(content_wrapper);
  lv_obj_set_flex_flow(content_wrapper, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content_wrapper, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(content_wrapper, theme_get_default_padding(), 0);
  lv_obj_set_flex_grow(content_wrapper, 1);

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
  return_callback = NULL;
  current_source = (wallet_source_t){0, 0};
}
