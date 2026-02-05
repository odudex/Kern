#include "public_key.h"
#include "../../core/key.h"
#include "../../core/wallet.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/theme.h"
#include "../settings/wallet_settings.h"
#include <esp_log.h>
#include <lvgl.h>
#include <stdio.h>
#include <wally_core.h>

static lv_obj_t *public_key_screen = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *settings_button = NULL;
static void (*return_callback)(void) = NULL;

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

void public_key_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded() || !wallet_is_initialized())
    return;

  return_callback = return_cb;

  const char *derivation_path = wallet_get_derivation();
  char derivation_compact[32];
  wallet_format_derivation_compact(
      derivation_compact, sizeof(derivation_compact), wallet_get_policy(),
      wallet_get_network(), wallet_get_account());

  public_key_screen = lv_obj_create(parent);
  lv_obj_set_size(public_key_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(public_key_screen);
  lv_obj_set_style_pad_all(public_key_screen, theme_get_default_padding(), 0);
  lv_obj_set_flex_flow(public_key_screen, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(public_key_screen, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(public_key_screen, theme_get_default_padding(), 0);

  // Key info header at top
  ui_key_info_create(public_key_screen);

  lv_obj_t *content_wrapper = lv_obj_create(public_key_screen);
  lv_obj_set_size(content_wrapper, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(content_wrapper);
  lv_obj_set_flex_flow(content_wrapper, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content_wrapper, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(content_wrapper, theme_get_default_padding(), 0);
  lv_obj_set_flex_grow(content_wrapper, 1);

  char fingerprint_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  if (!key_get_fingerprint_hex(fingerprint_hex))
    return;

  char *xpub_str = NULL;
  if (key_get_xpub(derivation_path, &xpub_str)) {
    char key_origin[512];
    snprintf(key_origin, sizeof(key_origin), "[%s/%s]%s", fingerprint_hex,
             derivation_compact, xpub_str);

    int32_t square_size = lv_disp_get_hor_res(NULL) * 60 / 100;

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
    int32_t qr_size = (container_width < container_height) ? container_width
                                                           : container_height;

    lv_obj_t *qr = lv_qrcode_create(qr_container);
    lv_qrcode_set_size(qr, qr_size);
    lv_qrcode_update(qr, key_origin, strlen(key_origin));
    lv_obj_center(qr);

    lv_obj_t *xpub_value = theme_create_label(content_wrapper, xpub_str, false);
    lv_obj_set_width(xpub_value, LV_PCT(95));
    lv_label_set_long_mode(xpub_value, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_align(xpub_value, LV_TEXT_ALIGN_CENTER, 0);

    wally_free_string(xpub_str);
  } else {
    lv_obj_t *error_value =
        theme_create_label(content_wrapper, "Error: Failed to get XPUB", false);
    lv_obj_set_style_text_color(error_value, error_color(), 0);
    lv_obj_set_width(error_value, LV_PCT(100));
  }

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
  return_callback = NULL;
}
