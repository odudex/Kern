#include "public_key.h"
#include "../../core/bip32_path.h"
#include "../../core/key.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../qr/viewer.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/path_keypad.h"
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
static lv_obj_t *details_parent = NULL;
static lv_obj_t *picker_row = NULL;
static lv_obj_t *policy_dropdown = NULL;
static lv_obj_t *account_row = NULL;
static lv_obj_t *account_label = NULL;
static lv_obj_t *account_minus_btn = NULL;
static lv_obj_t *account_plus_btn = NULL;
static lv_obj_t *progress_dialog = NULL;
static wallet_source_picker_t *picker = NULL;
static wallet_source_t current_source = {0, 0};

typedef enum {
  POLICY_SINGLESIG,
  POLICY_MULTISIG,
  POLICY_MINISCRIPT,
} policy_type_t;
static policy_type_t policy = POLICY_SINGLESIG;

// Miniscript custom derivation, edited via the picker row's path button.
// Seeded to the BIP48-style default when miniscript is selected; not synced
// back to the account button when switching away.
static char miniscript_path[96];
static lv_obj_t *path_btn = NULL;
static ui_path_keypad_t *path_keypad = NULL;
static void (*return_callback)(void) = NULL;

// Singlesig dropdown index -> BIP purpose number.
static const uint32_t PURPOSE_FOR_SOURCE[4] = {
    84, /* 0 Native SegWit  */
    86, /* 1 Taproot        */
    44, /* 2 Legacy         */
    49, /* 3 Nested SegWit  */
};

static wallet_picker_mode_t current_picker_mode(void) {
  switch (policy) {
  case POLICY_MULTISIG:
    return WALLET_PICKER_MULTISIG_BIP48;
  case POLICY_MINISCRIPT:
    return WALLET_PICKER_MINISCRIPT;
  default:
    return WALLET_PICKER_SINGLESIG;
  }
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

  // Miniscript paths are already h-notation with a fixed "m/" prefix.
  if (policy == POLICY_MINISCRIPT) {
    snprintf(path, path_size, "%s", miniscript_path);
    snprintf(compact, compact_size, "%s", miniscript_path + 2);
    return;
  }

  if (policy == POLICY_MULTISIG) {
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

// Seeds the editable miniscript path to the BIP48 default for the selected
// script type: subscript 2h for Native SegWit (wsh), 3h for Taproot (tr).
static void seed_miniscript_path(uint32_t account) {
  uint32_t coin = (wallet_get_network() == WALLET_NETWORK_MAINNET) ? 0 : 1;
  uint32_t subscript = (current_source.source == 1) ? 3 : 2;
  snprintf(miniscript_path, sizeof(miniscript_path), "m/48h/%uh/%uh/%uh", coin,
           account, subscript);
}

// Only offer account shortcuts for the selected network/script's standard
// four-node, fully hardened path. Custom paths remain editable via Path.
static bool miniscript_standard_account(uint32_t *account) {
  uint32_t nodes[4];
  size_t depth = 0;
  uint32_t coin = (wallet_get_network() == WALLET_NETWORK_MAINNET) ? 0 : 1;
  uint32_t subscript = (current_source.source == 1) ? 3 : 2;
  if (policy != POLICY_MINISCRIPT ||
      !bip32_path_parse(miniscript_path, nodes, &depth, 4) || depth != 4 ||
      nodes[0] != (48u | BIP32_PATH_HARDENED) ||
      nodes[1] != (coin | BIP32_PATH_HARDENED) ||
      !bip32_path_is_hardened(nodes[2]) ||
      nodes[3] != (subscript | BIP32_PATH_HARDENED))
    return false;
  *account = bip32_path_unharden(nodes[2]);
  return true;
}

static void update_account_row(void) {
  if (!account_row)
    return;
  uint32_t account;
  if (!miniscript_standard_account(&account)) {
    lv_obj_add_flag(account_row, LV_OBJ_FLAG_HIDDEN);
    return;
  }
  lv_obj_clear_flag(account_row, LV_OBJ_FLAG_HIDDEN);
  lv_label_set_text_fmt(account_label, "Account: %u", account);
  if (account == 0)
    lv_obj_add_state(account_minus_btn, LV_STATE_DISABLED);
  else
    lv_obj_clear_state(account_minus_btn, LV_STATE_DISABLED);
  if (account == BIP32_PATH_HARDENED - 1)
    lv_obj_add_state(account_plus_btn, LV_STATE_DISABLED);
  else
    lv_obj_clear_state(account_plus_btn, LV_STATE_DISABLED);
}

static void show_xpub_cb(lv_event_t *e) {
  (void)e;
  char path[96];
  char compact[96];
  format_derivation(path, sizeof(path), compact, sizeof(compact));

  char *xpub = NULL;
  if (!key_get_xpub(path, &xpub)) {
    dialog_show_error_timeout("Failed to get XPUB", NULL, 0);
    return;
  }
  dialog_show_info("XPUB", xpub, NULL, NULL, DIALOG_STYLE_OVERLAY);
  wally_free_string(xpub);
}

static void render_xpub(void) {
  update_account_row();
  if (!qr_parent || !details_parent)
    return;
  lv_obj_clean(qr_parent);
  lv_obj_clean(details_parent);

  char derivation_path[96];
  char derivation_compact[96];
  format_derivation(derivation_path, sizeof(derivation_path),
                    derivation_compact, sizeof(derivation_compact));

  char fingerprint_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  if (!key_get_fingerprint_hex(fingerprint_hex))
    return;

  char *xpub_str = NULL;
  if (!key_get_xpub(derivation_path, &xpub_str)) {
    lv_obj_t *error_value =
        theme_create_label(details_parent, "Error: Failed to get XPUB", false);
    lv_obj_set_style_text_color(error_value, error_color(), 0);
    lv_obj_set_width(error_value, LV_PCT(100));
    return;
  }

  char key_origin[512];
  snprintf(key_origin, sizeof(key_origin), "[%s/%s]%s", fingerprint_hex,
           derivation_compact, xpub_str);

  // With a custom path the picker row only shows a "Path" button, so surface
  // the resulting origin alongside the QR for the user to check.
  if (policy == POLICY_MINISCRIPT) {
    char origin[128];
    snprintf(origin, sizeof(origin), "[%s/%s]", fingerprint_hex,
             derivation_compact);
    lv_obj_t *origin_value = theme_create_label(details_parent, origin, false);
    lv_obj_set_style_text_color(origin_value, secondary_color(), 0);
    lv_obj_set_width(origin_value, LV_PCT(95));
    lv_label_set_long_mode(origin_value, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_align(origin_value, LV_TEXT_ALIGN_CENTER, 0);
  }

  lv_obj_t *show_btn = theme_create_button(details_parent, "Show XPUB", false);
  lv_obj_set_size(show_btn, theme_is_landscape() ? LV_PCT(90) : LV_PCT(60),
                  theme_min_touch_size());
  lv_obj_add_event_cb(show_btn, show_xpub_cb, LV_EVENT_CLICKED, NULL);

  // Reserve the path and button's actual height first; the QR can use all
  // remaining space without pushing either control off a small screen.
  lv_obj_update_layout(public_key_screen);
  int32_t square_size = LV_MIN(lv_obj_get_content_width(qr_parent),
                               lv_obj_get_content_height(qr_parent));
  lv_obj_t *qr_container =
      theme_create_qr_container(qr_parent, square_size, theme_small_padding());
  lv_obj_update_layout(qr_container);
  qr_create_optimal(qr_container, lv_obj_get_content_width(qr_container),
                    key_origin);
  qr_viewer_attach_fullscreen(qr_container, key_origin, derivation_path);
  wally_free_string(xpub_str);
}

static void picker_changed_cb(const wallet_source_t *src, void *user_data) {
  (void)user_data;
  uint32_t account;
  // Preserve a standard Miniscript account across script changes. The
  // picker's account belongs to singlesig/multisig and is not updated here.
  if (!miniscript_standard_account(&account))
    account = src->account;
  current_source = *src;
  // In miniscript mode the dropdown selects the script type (wsh/tr), which
  // re-seeds the default path; any custom Path edit is intentionally reset.
  if (policy == POLICY_MINISCRIPT)
    seed_miniscript_path(account);
  render_xpub();
}

static void path_submit_cb(const char *path, void *user_data) {
  (void)user_data;
  snprintf(miniscript_path, sizeof(miniscript_path), "%s", path);
  render_xpub();
}

static void account_step_cb(lv_event_t *e) {
  uint32_t account;
  if (!miniscript_standard_account(&account))
    return;
  if (lv_event_get_target(e) == account_minus_btn) {
    if (account == 0)
      return;
    account--;
  } else {
    if (account == BIP32_PATH_HARDENED - 1)
      return;
    account++;
  }
  seed_miniscript_path(account);
  render_xpub();
}

static void path_btn_cb(lv_event_t *e) {
  (void)e;
  ui_path_keypad_config_t config = {
      .title = "Derivation Path",
      .initial_path = miniscript_path,
      .max_depth = 10,
      .invalid_message = "Invalid derivation path",
      .submit_cb = path_submit_cb,
      .cancel_cb = NULL,
      .user_data = NULL,
  };
  ui_path_keypad_open(&path_keypad, &config);
}

// Replaces the picker's account button in miniscript mode; styled the same.
// The path itself doesn't fit here — it shows beside the Show XPUB button.
static void create_path_btn(void) {
  path_btn = lv_btn_create(picker_row);
  theme_apply_touch_button(path_btn, false);
  lv_obj_update_layout(policy_dropdown);
  lv_obj_set_size(path_btn, LV_PCT(25), lv_obj_get_height(policy_dropdown));
  lv_obj_t *label = lv_label_create(path_btn);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  lv_label_set_text(label, "Path");
  lv_obj_center(label);
  lv_obj_add_event_cb(path_btn, path_btn_cb, LV_EVENT_CLICKED, NULL);
}

static void create_picker(void) {
  if (path_btn) {
    lv_obj_del(path_btn);
    path_btn = NULL;
  }
  picker =
      wallet_source_picker_create(picker_row, current_picker_mode(),
                                  &current_source, picker_changed_cb, NULL);
  if (policy == POLICY_MINISCRIPT)
    create_path_btn();
}

static void policy_dropdown_cb(lv_event_t *e) {
  (void)e;
  policy_type_t now = (policy_type_t)lv_dropdown_get_selected(policy_dropdown);
  if (now == policy)
    return;
  policy = now;

  // Reset the script index when picker option sets change, but keep account.
  current_source = (wallet_source_t){0, current_source.account};
  if (policy == POLICY_MINISCRIPT)
    seed_miniscript_path(current_source.account);
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

  char derivation_path[96];
  char derivation_compact[96];
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

  char stem[112];
  snprintf(stem, sizeof(stem), "%s-%s", fingerprint_hex, derivation_compact);
  for (char *c = stem; *c; c++)
    if (*c == '/')
      *c = '-';
  char path[192];
  snprintf(path, sizeof(path), "%s/xpub-%s.txt", SD_CARD_MOUNT_POINT, stem);

  if (sd_card_write_file(path, (const uint8_t *)key_origin,
                         strlen(key_origin)) != ESP_OK) {
    dialog_show_error_timeout("Failed to save", NULL, 0);
    return;
  }

  char msg[224];
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

// Match the picker's account button so the two settings rows align.
static void create_save_sd_button(lv_obj_t *parent) {
  lv_obj_t *btn = lv_btn_create(parent);
  theme_apply_touch_button(btn, false);
  lv_obj_update_layout(policy_dropdown);
  lv_obj_set_size(btn, LV_PCT(25), lv_obj_get_height(policy_dropdown));
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

static lv_obj_t *create_account_step_button(lv_obj_t *parent,
                                            const char *text) {
  lv_obj_t *btn = lv_btn_create(parent);
  theme_apply_touch_button(btn, false);
  lv_obj_update_layout(policy_dropdown);
  lv_obj_set_size(btn, LV_PCT(25), lv_obj_get_height(policy_dropdown));
  lv_obj_t *label = lv_label_create(btn);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  lv_label_set_text(label, text);
  lv_obj_center(label);
  lv_obj_add_event_cb(btn, account_step_cb, LV_EVENT_CLICKED, NULL);
  return btn;
}

static void create_account_row(lv_obj_t *parent) {
  account_row = create_flex_container(parent, LV_FLEX_FLOW_ROW,
                                      LV_FLEX_ALIGN_SPACE_BETWEEN, 0);
  lv_obj_set_size(account_row, LV_PCT(100), LV_SIZE_CONTENT);
  account_minus_btn = create_account_step_button(account_row, "-");
  account_label = theme_create_label(account_row, "", false);
  lv_obj_set_width(account_label, LV_PCT(48));
  lv_label_set_long_mode(account_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_font(account_label, theme_font_small(), 0);
  lv_obj_set_style_text_align(account_label, LV_TEXT_ALIGN_CENTER, 0);
  account_plus_btn = create_account_step_button(account_row, "+");
  update_account_row();
}

// Share the widget tree in both orientations. Landscape puts the details
// beside the QR so its path and button do not consume scarce vertical space.
static void create_key_content(lv_obj_t *parent, bool landscape) {
  lv_obj_t *content = create_flex_container(
      parent, landscape ? LV_FLEX_FLOW_ROW : LV_FLEX_FLOW_COLUMN,
      LV_FLEX_ALIGN_CENTER, theme_small_padding());
  lv_obj_set_size(content, LV_PCT(100), 0);
  lv_obj_set_flex_grow(content, 1);

  qr_parent = create_flex_container(content, LV_FLEX_FLOW_COLUMN,
                                    LV_FLEX_ALIGN_CENTER, 0);
  lv_obj_set_size(qr_parent, landscape ? 0 : LV_PCT(100),
                  landscape ? LV_PCT(100) : 0);
  lv_obj_set_flex_grow(qr_parent, 1);

  details_parent =
      create_flex_container(content, LV_FLEX_FLOW_COLUMN, LV_FLEX_ALIGN_CENTER,
                            theme_small_padding());
  lv_obj_set_size(details_parent, landscape ? LV_PCT(38) : LV_PCT(100),
                  LV_SIZE_CONTENT);
}

static lv_obj_t *create_control_row(lv_obj_t *parent, bool landscape,
                                    uint8_t grow) {
  lv_obj_t *row = create_flex_container(parent, LV_FLEX_FLOW_ROW,
                                        LV_FLEX_ALIGN_SPACE_BETWEEN, 0);
  lv_obj_set_size(row, landscape ? 0 : LV_PCT(100), LV_SIZE_CONTENT);
  if (landscape)
    lv_obj_set_flex_grow(row, grow);
  return row;
}

static void create_controls(lv_obj_t *parent, bool landscape) {
  lv_obj_t *controls = create_flex_container(
      parent, landscape ? LV_FLEX_FLOW_ROW : LV_FLEX_FLOW_COLUMN,
      LV_FLEX_ALIGN_START, theme_default_padding());
  lv_obj_set_size(controls, LV_PCT(100), LV_SIZE_CONTENT);

  // Script names need more width than policy names when rows sit side by side.
  lv_obj_t *policy_row = create_control_row(controls, landscape, 2);
  policy_dropdown =
      theme_create_dropdown(policy_row, "Singlesig\nMultisig\nMiniscript");
  lv_dropdown_set_selected(policy_dropdown, (uint16_t)policy);
  lv_obj_set_width(policy_dropdown, LV_PCT(72));
  lv_obj_add_event_cb(policy_dropdown, policy_dropdown_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);

  create_save_sd_button(policy_row);
  picker_row = create_control_row(controls, landscape, 3);
  create_picker();
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
  policy = POLICY_SINGLESIG;
  miniscript_path[0] = '\0';

  bool landscape = theme_is_landscape();
  public_key_screen = create_public_key_screen(parent, landscape);
  ui_key_info_bar_create(public_key_screen);

  create_controls(public_key_screen, landscape);
  create_account_row(public_key_screen);
  create_key_content(public_key_screen, landscape);

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
  ui_path_keypad_close(&path_keypad);
  wallet_source_picker_destroy(picker);
  picker = NULL;
  path_btn = NULL; // deleted with the screen

  delete_obj(&back_button);
  delete_obj(&settings_button);
  delete_obj(&public_key_screen);

  qr_parent = NULL;
  details_parent = NULL;
  picker_row = NULL;
  policy_dropdown = NULL;
  account_row = NULL;
  account_label = NULL;
  account_minus_btn = NULL;
  account_plus_btn = NULL;
  return_callback = NULL;
  current_source = (wallet_source_t){0, 0};
  policy = POLICY_SINGLESIG;
  miniscript_path[0] = '\0';
}
