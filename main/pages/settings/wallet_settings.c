// Wallet Settings Page - Allows changing wallet attributes (passphrase,
// network)

#include "wallet_settings.h"
#include "../../core/key.h"
#include "../../core/wallet.h"
#include "../../ui/assets/icons_24.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/theme.h"
#include "../passphrase.h"
#include "descriptor_manager.h"
#include <lvgl.h>
#include <stdio.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>

#include "../../utils/secure_mem.h"

static lv_obj_t *wallet_settings_screen = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *network_dropdown = NULL;
static lv_obj_t *policy_dropdown = NULL;
static lv_obj_t *passphrase_btn = NULL;
static lv_obj_t *descriptor_btn = NULL;
static lv_obj_t *apply_btn = NULL;
static lv_obj_t *apply_label = NULL;
static lv_obj_t *title_cont = NULL;
static lv_obj_t *derivation_label = NULL;

static void (*return_callback)(void) = NULL;
static char *stored_passphrase = NULL;
static char *mnemonic_content = NULL;
static char base_fingerprint_hex[9] = {0};
static wallet_network_t selected_network = WALLET_NETWORK_MAINNET;
static wallet_policy_t selected_policy = WALLET_POLICY_SINGLESIG;
static bool settings_changed = false;

static lv_obj_t *account_btn = NULL;
static lv_obj_t *account_value_label = NULL;
static lv_obj_t *account_overlay = NULL;
static lv_obj_t *account_numpad = NULL;
static lv_obj_t *account_input_label = NULL;
static uint32_t selected_account = 0;
static char account_input_buffer[12];
static int account_input_len = 0;

static const char *numpad_map[] = {"1",
                                   "2",
                                   "3",
                                   "\n",
                                   "4",
                                   "5",
                                   "6",
                                   "\n",
                                   "7",
                                   "8",
                                   "9",
                                   "\n",
                                   LV_SYMBOL_BACKSPACE,
                                   "0",
                                   LV_SYMBOL_OK,
                                   ""};

static void update_apply_button_state(void);

static bool g_settings_applied = false;

bool wallet_settings_were_applied(void) {
  bool result = g_settings_applied;
  g_settings_applied = false;
  return result;
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

static void update_derivation_path(void) {
  if (!derivation_label)
    return;
  char path[48];
  wallet_format_derivation_path(path, sizeof(path), selected_policy,
                                selected_network, selected_account);
  char buf[64];
  snprintf(buf, sizeof(buf), ICON_DERIVATION " %s", path);
  lv_label_set_text(derivation_label, buf);
}

static void update_account_display(void) {
  if (!account_value_label)
    return;
  char buf[24];
  snprintf(buf, sizeof(buf), "Account: %u", selected_account);
  lv_label_set_text(account_value_label, buf);
}

static void update_account_input_display(void) {
  if (!account_input_label)
    return;
  char display[14];
  if (account_input_len == 0) {
    snprintf(display, sizeof(display), "_");
  } else {
    snprintf(display, sizeof(display), "%s_", account_input_buffer);
  }
  lv_label_set_text(account_input_label, display);
}

static void update_numpad_buttons(void) {
  if (!account_numpad)
    return;

  bool empty = (account_input_len == 0);
  if (empty) {
    lv_btnmatrix_set_btn_ctrl(account_numpad, 12, LV_BTNMATRIX_CTRL_DISABLED);
    lv_btnmatrix_set_btn_ctrl(account_numpad, 14, LV_BTNMATRIX_CTRL_DISABLED);
  } else {
    lv_btnmatrix_clear_btn_ctrl(account_numpad, 12, LV_BTNMATRIX_CTRL_DISABLED);
    lv_btnmatrix_clear_btn_ctrl(account_numpad, 14, LV_BTNMATRIX_CTRL_DISABLED);
  }
}

static void close_account_overlay(void) {
  if (account_overlay) {
    lv_obj_del(account_overlay);
    account_overlay = NULL;
    account_numpad = NULL;
    account_input_label = NULL;
  }
}

static void numpad_event_cb(lv_event_t *e) {
  lv_obj_t *btnm = lv_event_get_target(e);
  uint32_t btn_id = lv_btnmatrix_get_selected_btn(btnm);
  const char *txt = lv_btnmatrix_get_btn_text(btnm, btn_id);

  if (strcmp(txt, LV_SYMBOL_OK) == 0) {
    if (account_input_len > 0) {
      unsigned long val = strtoul(account_input_buffer, NULL, 10);
      if (val <= 2147483647) {
        selected_account = (uint32_t)val;
        settings_changed = true;
        update_account_display();
        update_derivation_path();
        update_apply_button_state();
      }
    }
    close_account_overlay();
  } else if (strcmp(txt, LV_SYMBOL_BACKSPACE) == 0) {
    if (account_input_len > 0) {
      account_input_len--;
      account_input_buffer[account_input_len] = '\0';
      update_account_input_display();
      update_numpad_buttons();
    }
  } else if (account_input_len < 10) {
    account_input_buffer[account_input_len++] = txt[0];
    account_input_buffer[account_input_len] = '\0';
    update_account_input_display();
    update_numpad_buttons();
  }
}

static void show_account_overlay(void) {
  account_input_len =
      snprintf(account_input_buffer, sizeof(account_input_buffer), "%u",
               selected_account);

  account_overlay = lv_obj_create(lv_screen_active());
  lv_obj_remove_style_all(account_overlay);
  lv_obj_set_size(account_overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(account_overlay, lv_color_black(), 0);
  lv_obj_set_style_bg_opa(account_overlay, LV_OPA_50, 0);
  lv_obj_add_flag(account_overlay, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *modal = lv_obj_create(account_overlay);
  lv_obj_set_size(modal, LV_PCT(80), LV_PCT(80));
  lv_obj_center(modal);
  theme_apply_frame(modal);
  lv_obj_set_style_bg_opa(modal, LV_OPA_90, 0);
  lv_obj_clear_flag(modal, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(modal, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(modal, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(modal, theme_get_default_padding(), 0);
  lv_obj_set_style_pad_gap(modal, 15, 0);

  lv_obj_t *title = lv_label_create(modal);
  lv_label_set_text(title, "Account");
  lv_obj_set_style_text_font(title, theme_font_medium(), 0);
  lv_obj_set_style_text_color(title, main_color(), 0);

  account_input_label = lv_label_create(modal);
  lv_obj_set_style_text_font(account_input_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(account_input_label, highlight_color(), 0);
  update_account_input_display();

  account_numpad = lv_btnmatrix_create(modal);
  lv_btnmatrix_set_map(account_numpad, numpad_map);
  lv_obj_set_size(account_numpad, LV_PCT(100), LV_PCT(70));
  lv_obj_set_flex_grow(account_numpad, 1);
  theme_apply_btnmatrix(account_numpad);
  lv_obj_add_event_cb(account_numpad, numpad_event_cb, LV_EVENT_VALUE_CHANGED,
                      NULL);

  update_numpad_buttons();
}

static void account_btn_cb(lv_event_t *e) {
  (void)e;
  show_account_overlay();
}

static void update_apply_button_state(void) {
  if (!apply_btn)
    return;
  if (settings_changed) {
    lv_obj_clear_state(apply_btn, LV_STATE_DISABLED);
    if (apply_label)
      lv_obj_set_style_text_color(apply_label, main_color(), 0);
  } else {
    lv_obj_add_state(apply_btn, LV_STATE_DISABLED);
    if (apply_label)
      lv_obj_set_style_text_color(apply_label, disabled_color(), 0);
  }
}

static void network_dropdown_cb(lv_event_t *e) {
  uint16_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  wallet_network_t new_network =
      (sel == 0) ? WALLET_NETWORK_MAINNET : WALLET_NETWORK_TESTNET;
  if (new_network != selected_network) {
    selected_network = new_network;
    settings_changed = true;
    update_derivation_path();
    update_apply_button_state();
  }
}

static void policy_dropdown_cb(lv_event_t *e) {
  uint16_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  wallet_policy_t new_policy =
      (sel == 0) ? WALLET_POLICY_SINGLESIG : WALLET_POLICY_MULTISIG;
  if (new_policy != selected_policy) {
    selected_policy = new_policy;
    settings_changed = true;
    update_derivation_path();
    update_apply_button_state();
  }
}

static void add_fingerprint_pair(lv_obj_t *parent, const char *fp_hex,
                                 bool highlighted) {
  lv_color_t color = highlighted ? highlight_color() : secondary_color();
  ui_icon_text_row_create(parent, ICON_FINGERPRINT, fp_hex, color);
}

static void update_title_with_passphrase(const char *passphrase) {
  if (!title_cont || !mnemonic_content)
    return;

  // Clear existing content
  lv_obj_clean(title_cont);

  // If no passphrase, show only base fingerprint (highlighted)
  if (!passphrase || passphrase[0] == '\0') {
    add_fingerprint_pair(title_cont, base_fingerprint_hex, true);
    return;
  }

  // Calculate fingerprint with passphrase
  unsigned char seed[BIP39_SEED_LEN_512];
  struct ext_key *master_key = NULL;

  if (bip39_mnemonic_to_seed512(mnemonic_content, passphrase, seed,
                                sizeof(seed)) != WALLY_OK) {
    secure_memzero(seed, sizeof(seed));
    return;
  }

  if (bip32_key_from_seed_alloc(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0,
                                &master_key) != WALLY_OK) {
    secure_memzero(seed, sizeof(seed));
    return;
  }

  unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
  bip32_key_get_fingerprint(master_key, fingerprint, BIP32_KEY_FINGERPRINT_LEN);
  secure_memzero(seed, sizeof(seed));
  bip32_key_free(master_key);

  char *passphrase_fp_hex = NULL;
  if (wally_hex_from_bytes(fingerprint, BIP32_KEY_FINGERPRINT_LEN,
                           &passphrase_fp_hex) == WALLY_OK) {
    // Base fingerprint (not highlighted)
    add_fingerprint_pair(title_cont, base_fingerprint_hex, false);

    // Arrow separator
    lv_obj_t *arrow = lv_label_create(title_cont);
    lv_label_set_text(arrow, ">");
    lv_obj_set_style_text_font(arrow, theme_font_small(), 0);
    lv_obj_set_style_text_color(arrow, secondary_color(), 0);

    // Passphrase fingerprint (highlighted)
    add_fingerprint_pair(title_cont, passphrase_fp_hex, true);

    wally_free_string(passphrase_fp_hex);
  }
}

static void passphrase_return_cb(void) {
  passphrase_page_destroy();
  wallet_settings_page_show();
}

static void passphrase_success_cb(const char *passphrase) {
  SECURE_FREE_STRING(stored_passphrase);

  if (passphrase && passphrase[0] != '\0') {
    stored_passphrase = strdup(passphrase);
  }

  settings_changed = true;

  passphrase_page_destroy();
  wallet_settings_page_show();

  // Update title to show both fingerprints
  update_title_with_passphrase(stored_passphrase);
  update_apply_button_state();
}

static void refresh_wallet_attributes(void) {
  selected_network = wallet_get_network();
  selected_policy = wallet_get_policy();
  selected_account = wallet_get_account();
  settings_changed = false;

  if (network_dropdown)
    lv_dropdown_set_selected(
        network_dropdown, (selected_network == WALLET_NETWORK_MAINNET) ? 0 : 1);
  if (policy_dropdown)
    lv_dropdown_set_selected(
        policy_dropdown, (selected_policy == WALLET_POLICY_SINGLESIG) ? 0 : 1);

  update_account_display();
  update_derivation_path();
  update_apply_button_state();
}

static void descriptor_return_cb(void) {
  descriptor_manager_page_destroy();
  wallet_settings_page_show();
  // Descriptor loading can overwrite wallet attributes, in which case pending
  // page edits are no longer meaningful and we must resync from the wallet.
  if (descriptor_manager_was_changed()) {
    refresh_wallet_attributes();
  }
}

static void descriptor_btn_cb(lv_event_t *e) {
  (void)e;
  wallet_settings_page_hide();
  descriptor_manager_page_create(lv_screen_active(), descriptor_return_cb);
  descriptor_manager_page_show();
}

static void passphrase_btn_cb(lv_event_t *e) {
  (void)e;
  wallet_settings_page_hide();
  passphrase_page_create(lv_screen_active(), passphrase_return_cb,
                         passphrase_success_cb);
}

static void do_apply_settings(void) {
  if (!mnemonic_content)
    return;

  bool is_testnet = (selected_network == WALLET_NETWORK_TESTNET);
  wallet_cleanup();
  wallet_set_account(selected_account);
  wallet_set_policy(selected_policy);

  if (key_load_from_mnemonic(mnemonic_content, stored_passphrase, is_testnet)) {
    if (!wallet_init(selected_network)) {
      dialog_show_error("Failed to initialize wallet", return_callback, 0);
      return;
    }
    settings_changed = false;
    g_settings_applied = true;
    update_apply_button_state();
    if (return_callback)
      return_callback();
  } else {
    dialog_show_error("Failed to reload key", NULL, 0);
  }
}

static void apply_with_warning_cb(bool result, void *user_data) {
  (void)user_data;
  if (result) {
    do_apply_settings();
  }
}

static void apply_btn_cb(lv_event_t *e) {
  (void)e;
  if (!mnemonic_content)
    return;

  if (selected_account > 99) {
    dialog_show_confirm("Account numbers above 99 are not recommended.\n\n"
                        "Continue?",
                        apply_with_warning_cb, NULL, DIALOG_STYLE_OVERLAY);
    return;
  }
  do_apply_settings();
}

void wallet_settings_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded() || !wallet_is_initialized())
    return;

  return_callback = return_cb;
  selected_network = wallet_get_network();
  selected_account = wallet_get_account();
  selected_policy = wallet_get_policy();
  settings_changed = false;

  // Get current mnemonic for later use
  if (!key_get_mnemonic(&mnemonic_content)) {
    dialog_show_error("Failed to get mnemonic", return_callback, 0);
    return;
  }

  // Calculate base fingerprint (without passphrase)
  unsigned char seed[BIP39_SEED_LEN_512];
  struct ext_key *master_key = NULL;

  if (bip39_mnemonic_to_seed512(mnemonic_content, NULL, seed, sizeof(seed)) !=
          WALLY_OK ||
      bip32_key_from_seed_alloc(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0,
                                &master_key) != WALLY_OK) {
    secure_memzero(seed, sizeof(seed));
    dialog_show_error("Failed to process mnemonic", return_callback, 0);
    return;
  }

  unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
  bip32_key_get_fingerprint(master_key, fingerprint, BIP32_KEY_FINGERPRINT_LEN);
  secure_memzero(seed, sizeof(seed));
  bip32_key_free(master_key);

  char *fingerprint_hex = NULL;
  if (wally_hex_from_bytes(fingerprint, BIP32_KEY_FINGERPRINT_LEN,
                           &fingerprint_hex) != WALLY_OK) {
    dialog_show_error("Failed to format fingerprint", return_callback, 0);
    return;
  }

  strncpy(base_fingerprint_hex, fingerprint_hex,
          sizeof(base_fingerprint_hex) - 1);
  base_fingerprint_hex[sizeof(base_fingerprint_hex) - 1] = '\0';
  wally_free_string(fingerprint_hex);

  // Main screen
  wallet_settings_screen = lv_obj_create(parent);
  lv_obj_set_size(wallet_settings_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(wallet_settings_screen);
  lv_obj_clear_flag(wallet_settings_screen, LV_OBJ_FLAG_SCROLLABLE);

  int32_t top_h = theme_get_screen_height() * 5 / 36; // 100 @ 720

  // Top bar (same as key_confirmation.c)
  lv_obj_t *top = lv_obj_create(wallet_settings_screen);
  lv_obj_set_size(top, LV_PCT(100), top_h);
  lv_obj_align(top, LV_ALIGN_TOP_MID, 0, 0);
  lv_obj_set_style_bg_opa(top, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(top, 0, 0);
  lv_obj_set_style_pad_all(top, 0, 0);
  lv_obj_clear_flag(top, LV_OBJ_FLAG_SCROLLABLE);

  back_button = ui_create_back_button(top, back_btn_cb);

  // Header container for fingerprint and derivation (centered in top bar)
  lv_obj_t *header_cont = theme_create_flex_column(top);
  lv_obj_set_style_pad_row(header_cont, 4, 0);
  lv_obj_align(header_cont, LV_ALIGN_CENTER, 0, 0);

  // Container for fingerprint pair(s)
  title_cont = theme_create_flex_row(header_cont);
  lv_obj_set_style_pad_column(title_cont, 8, 0);

  // Add initial fingerprint (highlighted)
  add_fingerprint_pair(title_cont, base_fingerprint_hex, true);

  // Derivation path row
  char deriv_path[48];
  wallet_format_derivation_path(deriv_path, sizeof(deriv_path), selected_policy,
                                selected_network, selected_account);
  derivation_label = ui_icon_text_row_create(header_cont, ICON_DERIVATION,
                                             deriv_path, secondary_color());

  // Content container below top bar
  lv_obj_t *content = lv_obj_create(wallet_settings_screen);
  lv_obj_set_size(content, LV_PCT(100), LV_VER_RES - top_h);
  lv_obj_align(content, LV_ALIGN_TOP_MID, 0, top_h);
  lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(content, 0, 0);
  lv_obj_set_style_pad_all(content, 0, 0);
  lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content, LV_FLEX_ALIGN_SPACE_EVENLY,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  // Passphrase + Descriptor row container (side by side)
  lv_obj_t *pp_desc_row = lv_obj_create(content);
  lv_obj_set_size(pp_desc_row, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(pp_desc_row);
  lv_obj_set_flex_flow(pp_desc_row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(pp_desc_row, LV_FLEX_ALIGN_SPACE_EVENLY,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  passphrase_btn = lv_btn_create(pp_desc_row);
  lv_obj_set_size(passphrase_btn, LV_PCT(48), theme_get_min_touch_size());
  theme_apply_touch_button(passphrase_btn, false);
  lv_obj_add_event_cb(passphrase_btn, passphrase_btn_cb, LV_EVENT_CLICKED,
                      NULL);

  lv_obj_t *pp_label = lv_label_create(passphrase_btn);
  lv_label_set_text(pp_label, "Passphrase");
  lv_obj_set_style_text_font(pp_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(pp_label, main_color(), 0);
  lv_obj_center(pp_label);

  descriptor_btn = lv_btn_create(pp_desc_row);
  lv_obj_set_size(descriptor_btn, LV_PCT(48), theme_get_min_touch_size());
  theme_apply_touch_button(descriptor_btn, false);
  lv_obj_add_event_cb(descriptor_btn, descriptor_btn_cb, LV_EVENT_CLICKED,
                      NULL);

  lv_obj_t *desc_label = lv_label_create(descriptor_btn);
  lv_label_set_text(desc_label, "Descriptor");
  lv_obj_set_style_text_font(desc_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(desc_label, main_color(), 0);
  lv_obj_center(desc_label);

  // Network + Policy row container (side by side)
  lv_obj_t *net_policy_row = lv_obj_create(content);
  lv_obj_set_size(net_policy_row, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(net_policy_row);
  lv_obj_set_flex_flow(net_policy_row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(net_policy_row, LV_FLEX_ALIGN_SPACE_EVENLY,
                        LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);

  // Network column (label + dropdown)
  lv_obj_t *net_col = lv_obj_create(net_policy_row);
  lv_obj_set_size(net_col, LV_PCT(45), LV_SIZE_CONTENT);
  theme_apply_transparent_container(net_col);
  lv_obj_set_flex_flow(net_col, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(net_col, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(net_col, 5, 0);

  lv_obj_t *net_label = lv_label_create(net_col);
  lv_label_set_text(net_label, "Network");
  lv_obj_set_style_text_font(net_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(net_label, secondary_color(), 0);

  network_dropdown = theme_create_dropdown(net_col, "Mainnet\nTestnet");
  lv_dropdown_set_selected(
      network_dropdown, (selected_network == WALLET_NETWORK_MAINNET) ? 0 : 1);
  lv_obj_set_width(network_dropdown, LV_PCT(100));
  lv_obj_add_event_cb(network_dropdown, network_dropdown_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);

  // Policy column (label + dropdown)
  lv_obj_t *policy_col = lv_obj_create(net_policy_row);
  lv_obj_set_size(policy_col, LV_PCT(45), LV_SIZE_CONTENT);
  theme_apply_transparent_container(policy_col);
  lv_obj_set_flex_flow(policy_col, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(policy_col, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(policy_col, 5, 0);

  lv_obj_t *policy_label = lv_label_create(policy_col);
  lv_label_set_text(policy_label, "Policy");
  lv_obj_set_style_text_font(policy_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(policy_label, secondary_color(), 0);

  policy_dropdown = theme_create_dropdown(policy_col, "Single-sig\nMultisig");
  lv_dropdown_set_selected(
      policy_dropdown, (selected_policy == WALLET_POLICY_SINGLESIG) ? 0 : 1);
  lv_obj_set_width(policy_dropdown, LV_PCT(100));
  lv_obj_add_event_cb(policy_dropdown, policy_dropdown_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);

  // Account button (label lives on the button itself)
  account_btn = lv_btn_create(content);
  lv_obj_set_size(account_btn, LV_PCT(50), theme_get_min_touch_size());
  theme_apply_touch_button(account_btn, false);
  lv_obj_add_event_cb(account_btn, account_btn_cb, LV_EVENT_CLICKED, NULL);

  account_value_label = lv_label_create(account_btn);
  char acc_buf[24];
  snprintf(acc_buf, sizeof(acc_buf), "Account: %u", selected_account);
  lv_label_set_text(account_value_label, acc_buf);
  lv_obj_set_style_text_font(account_value_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(account_value_label, main_color(), 0);
  lv_obj_center(account_value_label);

  // Apply button
  apply_btn = lv_btn_create(content);
  lv_obj_set_size(apply_btn, LV_PCT(60), theme_get_min_touch_size());
  theme_apply_touch_button(apply_btn, false);
  lv_obj_add_event_cb(apply_btn, apply_btn_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_add_state(apply_btn, LV_STATE_DISABLED); // Disabled until changes made

  apply_label = lv_label_create(apply_btn);
  lv_label_set_text(apply_label, "Apply");
  lv_obj_set_style_text_font(apply_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(apply_label, disabled_color(),
                              0); // Start disabled
  lv_obj_center(apply_label);
}

void wallet_settings_page_show(void) {
  if (wallet_settings_screen)
    lv_obj_clear_flag(wallet_settings_screen, LV_OBJ_FLAG_HIDDEN);
}

void wallet_settings_page_hide(void) {
  if (wallet_settings_screen)
    lv_obj_add_flag(wallet_settings_screen, LV_OBJ_FLAG_HIDDEN);
}

void wallet_settings_page_destroy(void) {
  // Close account overlay if open
  close_account_overlay();

  SECURE_FREE_STRING(stored_passphrase);
  SECURE_FREE_STRING(mnemonic_content);

  if (wallet_settings_screen) {
    lv_obj_del(wallet_settings_screen);
    wallet_settings_screen = NULL;
  }
  back_button = NULL;

  network_dropdown = NULL;
  policy_dropdown = NULL;
  passphrase_btn = NULL;
  descriptor_btn = NULL;
  account_btn = NULL;
  account_value_label = NULL;
  apply_btn = NULL;
  apply_label = NULL;
  title_cont = NULL;
  derivation_label = NULL;
  secure_memzero(base_fingerprint_hex, sizeof(base_fingerprint_hex));
  return_callback = NULL;
  selected_network = WALLET_NETWORK_MAINNET;
  selected_policy = WALLET_POLICY_SINGLESIG;
  settings_changed = false;
}
