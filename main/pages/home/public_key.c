#include "public_key.h"
#include "../../core/key.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../qr/viewer.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/theme_widgets.h"
#include "../../ui/wallet_source_picker.h"
#include "../settings/wallet_settings.h"
#include "sd_card.h"
#include <lvgl.h>
#include <stdio.h>
#include <string.h>
#include <wally_core.h>

static lv_obj_t *public_key_screen = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *settings_button = NULL;
static lv_obj_t *qr_parent = NULL;
static lv_obj_t *xpub_parent = NULL;
static lv_obj_t *picker_row = NULL;
static lv_obj_t *policy_dropdown = NULL;
static lv_obj_t *progress_dialog = NULL;
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

static wallet_picker_mode_t current_picker_mode(void) {
  return multisig_mode ? WALLET_PICKER_MULTISIG_BIP48 : WALLET_PICKER_SINGLESIG;
}

static void back_button_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

static void return_from_wallet_settings_cb(void) {
  wallet_settings_page_destroy();
  void (*saved_callback)(void) = return_callback;
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

static void format_derivation(char *path, size_t path_size, char *compact,
                              size_t compact_size) {
  uint32_t coin = (wallet_get_network() == WALLET_NETWORK_MAINNET) ? 0 : 1;
  uint32_t account = current_source.account;

  if (multisig_mode) {
    wallet_bip48_script_t script =
        wallet_source_picker_bip48_script(current_source.source);
    uint32_t subscript = (script == WALLET_BIP48_P2WSH) ? 2 : 1;
    snprintf(path, path_size, "m/48'/%u'/%u'/%u'", coin, account, subscript);
    snprintf(compact, compact_size, "48h/%uh/%uh/%uh", coin, account,
             subscript);
    return;
  }

  uint32_t purpose = PURPOSE_FOR_SOURCE[current_source.source];
  snprintf(path, path_size, "m/%u'/%u'/%u'", purpose, coin, account);
  snprintf(compact, compact_size, "%uh/%uh/%uh", purpose, coin, account);
}

static void render_xpub(void) {
  if (!qr_parent || !xpub_parent)
    return;
  lv_obj_clean(qr_parent);
  if (xpub_parent != qr_parent)
    lv_obj_clean(xpub_parent);

  char derivation_path[64];
  char derivation_compact[48];
  format_derivation(derivation_path, sizeof(derivation_path),
                    derivation_compact, sizeof(derivation_compact));

  char fingerprint_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  if (!key_get_fingerprint_hex(fingerprint_hex))
    return;

  char *xpub_str = NULL;
  if (!key_get_xpub(derivation_path, &xpub_str)) {
    lv_obj_t *error_value =
        theme_create_label(xpub_parent, "Error: Failed to get XPUB", false);
    lv_obj_set_style_text_color(error_value, error_color(), 0);
    lv_obj_set_width(error_value, LV_PCT(100));
    return;
  }

  char key_origin[512];
  snprintf(key_origin, sizeof(key_origin), "[%s/%s]%s", fingerprint_hex,
           derivation_compact, xpub_str);

  lv_obj_update_layout(public_key_screen);
  int32_t qr_w = lv_obj_get_content_width(qr_parent);
  int32_t qr_h = lv_obj_get_content_height(qr_parent);
  int32_t square_size = theme_is_landscape()
                            ? LV_MIN(qr_w, qr_h)
                            : LV_MIN(qr_w * 65 / 100, qr_h * 70 / 100);

  lv_obj_t *qr_container =
      theme_create_qr_container(qr_parent, square_size, theme_small_padding());
  lv_obj_update_layout(qr_container);

  qr_create_optimal(qr_container, lv_obj_get_content_width(qr_container),
                    key_origin);
  qr_viewer_attach_fullscreen(qr_container, key_origin, derivation_path);

  lv_obj_t *xpub_value = theme_create_label(xpub_parent, xpub_str, false);
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

static void create_picker(void) {
  picker =
      wallet_source_picker_create(picker_row, current_picker_mode(),
                                  &current_source, picker_changed_cb, NULL);
}

static void policy_dropdown_cb(lv_event_t *e) {
  (void)e;
  bool now_multisig = lv_dropdown_get_selected(policy_dropdown) == 1;
  if (now_multisig == multisig_mode)
    return;
  multisig_mode = now_multisig;

  // Reset the script index when picker option sets change, but keep account.
  current_source = (wallet_source_t){0, current_source.account};
  wallet_source_picker_destroy(picker);
  create_picker();
  render_xpub();
}

static void dismiss_progress(void) {
  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }
}

// Writes the current key origin ("[fp/path]xpub") to the card root, named
// after it ("xpub-<fp>-84h-0h-0h.txt") — same selection, same file, so
// re-saves overwrite instead of piling up copies.
static void deferred_save_xpub_cb(lv_timer_t *timer) {
  (void)timer;

  // The card may have been swapped (no card-detect line) — remount fresh.
  esp_err_t mret = sd_card_remount();
  dismiss_progress();
  if (mret != ESP_OK) {
    dialog_show_error_timeout("No SD card", NULL, 0);
    return;
  }

  char derivation_path[64];
  char derivation_compact[48];
  format_derivation(derivation_path, sizeof(derivation_path),
                    derivation_compact, sizeof(derivation_compact));

  char fingerprint_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  char *xpub_str = NULL;
  if (!key_get_fingerprint_hex(fingerprint_hex) ||
      !key_get_xpub(derivation_path, &xpub_str)) {
    dialog_show_error_timeout("Failed to get XPUB", NULL, 0);
    return;
  }

  char key_origin[512];
  snprintf(key_origin, sizeof(key_origin), "[%s/%s]%s", fingerprint_hex,
           derivation_compact, xpub_str);
  wally_free_string(xpub_str);

  char stem[64];
  snprintf(stem, sizeof(stem), "%s-%s", fingerprint_hex, derivation_compact);
  for (char *c = stem; *c; c++)
    if (*c == '/')
      *c = '-';
  char path[128];
  snprintf(path, sizeof(path), "%s/xpub-%s.txt", SD_CARD_MOUNT_POINT, stem);

  if (sd_card_write_file(path, (const uint8_t *)key_origin,
                         strlen(key_origin)) != ESP_OK) {
    dialog_show_error_timeout("Failed to save", NULL, 0);
    return;
  }

  char msg[160];
  snprintf(msg, sizeof(msg), "Saved to:\n%s", path);
  dialog_show_info("Saved", msg, NULL, NULL, DIALOG_STYLE_OVERLAY);
}

static void save_sd_button_cb(lv_event_t *e) {
  (void)e;
  // Remounting probes the card and can take a while — show progress and defer
  // the work so LVGL gets to render it first.
  progress_dialog =
      dialog_show_progress("Save", "Saving...", DIALOG_STYLE_OVERLAY);
  lv_timer_t *t = lv_timer_create(deferred_save_xpub_cb, 50, NULL);
  lv_timer_set_repeat_count(t, 1);
}

// Styled like the picker's account button, with the policy dropdown's height
// so the row adds no height beyond the dropdown alone; portrait shares the
// account button's 25% width too.
static void create_save_sd_button(lv_obj_t *parent, bool landscape) {
  lv_obj_t *btn = lv_btn_create(parent);
  theme_apply_touch_button(btn, false);
  lv_obj_update_layout(policy_dropdown);
  lv_obj_set_size(btn, landscape ? theme_min_touch_size() : LV_PCT(25),
                  lv_obj_get_height(policy_dropdown));
  lv_obj_t *label = lv_label_create(btn);
  lv_label_set_text(label, LV_SYMBOL_SD_CARD);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  lv_obj_set_style_text_color(label, highlight_color(), 0);
  lv_obj_center(label);
  lv_obj_add_event_cb(btn, save_sd_button_cb, LV_EVENT_CLICKED, NULL);
}

static lv_obj_t *create_flex_container(lv_obj_t *parent, lv_flex_flow_t flow,
                                       lv_flex_align_t main_place,
                                       int32_t gap) {
  lv_obj_t *obj = lv_obj_create(parent);
  theme_apply_transparent_container(obj);
  lv_obj_set_flex_flow(obj, flow);
  lv_obj_set_flex_align(obj, main_place, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(obj, gap, 0);
  return obj;
}

static lv_obj_t *create_public_key_screen(lv_obj_t *parent, bool landscape) {
  lv_obj_t *screen = lv_obj_create(parent);
  lv_obj_set_size(screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(screen);
  lv_obj_set_style_pad_all(
      screen, landscape ? theme_small_padding() : theme_default_padding(), 0);
  lv_obj_set_style_pad_top(screen, theme_small_padding(), 0);
  lv_obj_set_flex_flow(screen, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(screen, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(screen, theme_default_padding(), 0);
  return screen;
}

static lv_obj_t *make_bottom_cell(lv_obj_t *parent) {
  lv_obj_t *cell = create_flex_container(parent, LV_FLEX_FLOW_COLUMN,
                                         LV_FLEX_ALIGN_CENTER, 0);
  lv_obj_set_height(cell, LV_PCT(100));
  lv_obj_set_flex_grow(cell, 1);
  return cell;
}

static lv_obj_t *create_landscape_layout(void) {
  lv_obj_t *body =
      create_flex_container(public_key_screen, LV_FLEX_FLOW_COLUMN,
                            LV_FLEX_ALIGN_START, theme_small_padding());
  lv_obj_set_size(body, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_grow(body, 1);

  lv_obj_t *controls = create_flex_container(
      body, LV_FLEX_FLOW_ROW, LV_FLEX_ALIGN_START, theme_default_padding());
  lv_obj_set_size(controls, LV_PCT(100), LV_SIZE_CONTENT);

  lv_obj_t *bottom_row = create_flex_container(
      body, LV_FLEX_FLOW_ROW, LV_FLEX_ALIGN_CENTER, theme_default_padding());
  lv_obj_set_size(bottom_row, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_grow(bottom_row, 1);

  qr_parent = make_bottom_cell(bottom_row);
  xpub_parent = make_bottom_cell(bottom_row);
  return controls;
}

static void create_picker_row(lv_obj_t *controls_parent, bool landscape) {
  picker_row = create_flex_container(controls_parent, LV_FLEX_FLOW_ROW,
                                     LV_FLEX_ALIGN_SPACE_BETWEEN, 0);
  if (landscape) {
    lv_obj_set_height(picker_row, theme_min_touch_size());
    // Twice the policy dropdown's share: this row also holds the account
    // button, and the script names are longer than the policy names.
    lv_obj_set_flex_grow(picker_row, 2);
  } else {
    lv_obj_set_height(picker_row, LV_SIZE_CONTENT);
    lv_obj_set_width(picker_row, LV_PCT(100));
  }
  create_picker();
}

// In portrait the dropdown shares its row with the save-to-SD button, sized
// like the picker row below (72% dropdown / 25% button) so the columns align.
static void create_policy_row(lv_obj_t *controls_parent, bool landscape) {
  lv_obj_t *parent = controls_parent;
  if (!landscape) {
    parent = create_flex_container(controls_parent, LV_FLEX_FLOW_ROW,
                                   LV_FLEX_ALIGN_SPACE_BETWEEN, 0);
    lv_obj_set_size(parent, LV_PCT(100), LV_SIZE_CONTENT);
  }

  policy_dropdown = theme_create_dropdown(parent, "Singlesig\nMultisig");
  lv_dropdown_set_selected(policy_dropdown, multisig_mode ? 1 : 0);
  if (landscape)
    lv_obj_set_flex_grow(policy_dropdown, 1);
  else
    lv_obj_set_width(policy_dropdown, LV_PCT(72));
  lv_obj_add_event_cb(policy_dropdown, policy_dropdown_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);

  if (!landscape)
    create_save_sd_button(parent, false);
}

static void create_portrait_content(void) {
  lv_obj_t *content = create_flex_container(
      public_key_screen, LV_FLEX_FLOW_COLUMN, LV_FLEX_ALIGN_SPACE_EVENLY,
      theme_default_padding());
  lv_obj_set_size(content, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_grow(content, 1);
  qr_parent = content;
  xpub_parent = content;
}

static void delete_obj(lv_obj_t **obj) {
  if (!*obj)
    return;
  lv_obj_del(*obj);
  *obj = NULL;
}

void public_key_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded() || !wallet_is_initialized())
    return;

  return_callback = return_cb;
  current_source = (wallet_source_t){0, 0};
  multisig_mode = false;

  bool landscape = theme_is_landscape();
  public_key_screen = create_public_key_screen(parent, landscape);
  ui_key_info_bar_create(public_key_screen);

  lv_obj_t *controls_parent =
      landscape ? create_landscape_layout() : public_key_screen;
  create_policy_row(controls_parent, landscape);
  create_picker_row(controls_parent, landscape);
  if (landscape)
    create_save_sd_button(controls_parent, true);
  else
    create_portrait_content();

  render_xpub();

  back_button = ui_create_back_button(parent, back_button_cb);
  settings_button = ui_create_settings_button(parent, settings_button_cb);
}

void public_key_page_show(void) {
  if (public_key_screen)
    lv_obj_clear_flag(public_key_screen, LV_OBJ_FLAG_HIDDEN);
}

void public_key_page_hide(void) {
  if (public_key_screen)
    lv_obj_add_flag(public_key_screen, LV_OBJ_FLAG_HIDDEN);
}

void public_key_page_destroy(void) {
  dismiss_progress();
  wallet_source_picker_destroy(picker);
  picker = NULL;

  delete_obj(&back_button);
  delete_obj(&settings_button);
  delete_obj(&public_key_screen);

  qr_parent = NULL;
  xpub_parent = NULL;
  picker_row = NULL;
  policy_dropdown = NULL;
  return_callback = NULL;
  current_source = (wallet_source_t){0, 0};
  multisig_mode = false;
}
