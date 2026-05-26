#include "public_key.h"
#include "../../core/key.h"
#include "../../core/wallet.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/settings_row.h"
#include "../../ui/theme.h"
#include "../../ui/wallet_source_picker.h"
#include "../settings/wallet_settings.h"
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

  lv_obj_t *qr_container = theme_create_qr_container(qr_parent, square_size,
                                                     theme_get_small_padding());
  lv_obj_update_layout(qr_container);

  lv_obj_t *qr = lv_qrcode_create(qr_container);
  lv_qrcode_set_size(qr, lv_obj_get_content_width(qr_container));
  lv_qrcode_update(qr, key_origin, strlen(key_origin));
  lv_obj_center(qr);

  lv_obj_t *xpub_value = theme_create_label(xpub_parent, xpub_str, false);
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

static void create_picker(void) {
  picker =
      wallet_source_picker_create(picker_row, current_picker_mode(),
                                  &current_source, picker_changed_cb, NULL);
}

static void multisig_switch_cb(lv_event_t *e) {
  (void)e;
  bool now_multisig = lv_obj_has_state(multisig_switch, LV_STATE_CHECKED);
  if (now_multisig == multisig_mode)
    return;
  multisig_mode = now_multisig;

  // Reset the script index when picker option sets change, but keep account.
  current_source = (wallet_source_t){0, current_source.account};
  wallet_source_picker_destroy(picker);
  create_picker();
  update_multisig_switch_state();
  render_xpub();
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
      screen,
      landscape ? theme_get_small_padding() : theme_get_default_padding(), 0);
  lv_obj_set_style_pad_top(screen, theme_get_small_padding(), 0);
  lv_obj_set_flex_flow(screen, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(screen, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(screen, theme_get_default_padding(), 0);
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
                            LV_FLEX_ALIGN_START, theme_get_small_padding());
  lv_obj_set_size(body, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_grow(body, 1);

  lv_obj_t *controls = create_flex_container(
      body, LV_FLEX_FLOW_ROW, LV_FLEX_ALIGN_START, theme_get_default_padding());
  lv_obj_set_size(controls, LV_PCT(100), LV_SIZE_CONTENT);

  lv_obj_t *bottom_row =
      create_flex_container(body, LV_FLEX_FLOW_ROW, LV_FLEX_ALIGN_CENTER,
                            theme_get_default_padding());
  lv_obj_set_size(bottom_row, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_grow(bottom_row, 1);

  qr_parent = make_bottom_cell(bottom_row);
  xpub_parent = make_bottom_cell(bottom_row);
  return controls;
}

static void create_picker_row(lv_obj_t *controls_parent, bool landscape) {
  picker_row = create_flex_container(controls_parent, LV_FLEX_FLOW_ROW,
                                     LV_FLEX_ALIGN_SPACE_BETWEEN, 0);
  lv_obj_set_height(picker_row, LV_SIZE_CONTENT);
  if (landscape) {
    lv_obj_set_flex_grow(picker_row, 1);
    lv_obj_set_style_min_height(picker_row, theme_get_min_touch_size(), 0);
  } else {
    lv_obj_set_width(picker_row, LV_PCT(100));
  }
  create_picker();
}

static void create_multisig_row(lv_obj_t *controls_parent, bool landscape) {
  lv_obj_t *multisig_row = settings_row_toggle(
      controls_parent, "Multisig", false, multisig_switch_cb, "Multisig",
      "BIP48 cosigner xpub for multisig wallets. SegWit only (Native or "
      "Nested).");
  if (landscape)
    lv_obj_set_flex_grow(multisig_row, 1);
  multisig_switch = settings_row_get_widget(multisig_row);
  update_multisig_switch_state();
}

static void create_portrait_content(void) {
  lv_obj_t *content = create_flex_container(
      public_key_screen, LV_FLEX_FLOW_COLUMN, LV_FLEX_ALIGN_SPACE_EVENLY,
      theme_get_default_padding());
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
  create_picker_row(controls_parent, landscape);
  create_multisig_row(controls_parent, landscape);
  if (!landscape)
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
  wallet_source_picker_destroy(picker);
  picker = NULL;

  delete_obj(&back_button);
  delete_obj(&settings_button);
  delete_obj(&public_key_screen);

  qr_parent = NULL;
  xpub_parent = NULL;
  picker_row = NULL;
  multisig_switch = NULL;
  return_callback = NULL;
  current_source = (wallet_source_t){0, 0};
  multisig_mode = false;
}
