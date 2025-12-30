// Wallet Settings Page - Allows changing wallet attributes (passphrase,
// network)

#include "wallet_settings.h"
#include "../../key/key.h"
#include "../../ui_components/flash_error.h"
#include "../../ui_components/icons/icons_24.h"
#include "../../ui_components/theme.h"
#include "../../ui_components/ui_input_helpers.h"
#include "../../ui_components/ui_key_info.h"
#include "../../wallet/wallet.h"
#include "../login_pages/passphrase.h"
#include <lvgl.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>

static lv_obj_t *wallet_settings_screen = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *network_dropdown = NULL;
static lv_obj_t *passphrase_btn = NULL;
static lv_obj_t *apply_btn = NULL;
static lv_obj_t *apply_label = NULL;
static lv_obj_t *title_cont = NULL;
static lv_obj_t *derivation_label = NULL;

static void (*return_callback)(void) = NULL;
static char *stored_passphrase = NULL;
static char *mnemonic_content = NULL;
static char base_fingerprint_hex[9] = {0};
static wallet_network_t selected_network = WALLET_NETWORK_MAINNET;
static bool settings_changed = false;

// Global flag that persists after page is destroyed - indicates settings were
// applied
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
  const char *path = (selected_network == WALLET_NETWORK_MAINNET)
                         ? "m/84'/0'/0'"
                         : "m/84'/1'/0'";
  lv_label_set_text(derivation_label, path);
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

static void dropdown_open_cb(lv_event_t *e) {
  lv_obj_t *list = lv_dropdown_get_list(lv_event_get_target(e));
  if (list) {
    lv_obj_set_style_bg_color(list, disabled_color(), 0);
    lv_obj_set_style_text_color(list, main_color(), 0);
    lv_obj_set_style_bg_color(list, highlight_color(),
                              LV_PART_SELECTED | LV_STATE_CHECKED);
    lv_obj_set_style_bg_color(list, highlight_color(),
                              LV_PART_SELECTED | LV_STATE_PRESSED);
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
    return;
  }

  if (bip32_key_from_seed_alloc(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0,
                                &master_key) != WALLY_OK) {
    memset(seed, 0, sizeof(seed));
    return;
  }

  unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
  bip32_key_get_fingerprint(master_key, fingerprint, BIP32_KEY_FINGERPRINT_LEN);
  memset(seed, 0, sizeof(seed));
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
  // Store the passphrase
  if (stored_passphrase) {
    memset(stored_passphrase, 0, strlen(stored_passphrase));
    free(stored_passphrase);
    stored_passphrase = NULL;
  }

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

static void passphrase_btn_cb(lv_event_t *e) {
  (void)e;
  wallet_settings_page_hide();
  passphrase_page_create(lv_screen_active(), passphrase_return_cb,
                         passphrase_success_cb);
}

static void apply_btn_cb(lv_event_t *e) {
  (void)e;
  if (!mnemonic_content)
    return;

  bool is_testnet = (selected_network == WALLET_NETWORK_TESTNET);

  // Clean up existing wallet before reinitializing
  wallet_cleanup();

  if (key_load_from_mnemonic(mnemonic_content, stored_passphrase, is_testnet)) {
    if (!wallet_init(selected_network)) {
      show_flash_error("Failed to initialize wallet", return_callback, 0);
      return;
    }
    settings_changed = false;
    g_settings_applied = true;
    update_apply_button_state();
    if (return_callback)
      return_callback();
  } else {
    show_flash_error("Failed to reload key", NULL, 0);
  }
}

void wallet_settings_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded() || !wallet_is_initialized())
    return;

  return_callback = return_cb;
  selected_network = wallet_get_network();
  settings_changed = false;

  // Get current mnemonic for later use
  if (!key_get_mnemonic(&mnemonic_content)) {
    show_flash_error("Failed to get mnemonic", return_callback, 0);
    return;
  }

  // Calculate base fingerprint (without passphrase)
  unsigned char seed[BIP39_SEED_LEN_512];
  struct ext_key *master_key = NULL;

  if (bip39_mnemonic_to_seed512(mnemonic_content, NULL, seed, sizeof(seed)) !=
          WALLY_OK ||
      bip32_key_from_seed_alloc(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0,
                                &master_key) != WALLY_OK) {
    memset(seed, 0, sizeof(seed));
    show_flash_error("Failed to process mnemonic", return_callback, 0);
    return;
  }

  unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
  bip32_key_get_fingerprint(master_key, fingerprint, BIP32_KEY_FINGERPRINT_LEN);
  memset(seed, 0, sizeof(seed));
  bip32_key_free(master_key);

  char *fingerprint_hex = NULL;
  if (wally_hex_from_bytes(fingerprint, BIP32_KEY_FINGERPRINT_LEN,
                           &fingerprint_hex) != WALLY_OK) {
    show_flash_error("Failed to format fingerprint", return_callback, 0);
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

  // Top bar (same as key_confirmation.c)
  lv_obj_t *top = lv_obj_create(wallet_settings_screen);
  lv_obj_set_size(top, LV_PCT(100), 100);
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
  lv_obj_t *deriv_cont = ui_icon_text_row_create(
      header_cont, ICON_DERIVATION,
      (selected_network == WALLET_NETWORK_MAINNET) ? "m/84'/0'/0'"
                                                   : "m/84'/1'/0'",
      secondary_color());
  derivation_label = lv_obj_get_child(deriv_cont, 1);

  // Content container below top bar
  lv_obj_t *content = lv_obj_create(wallet_settings_screen);
  lv_obj_set_size(content, LV_PCT(100), LV_VER_RES - 100);
  lv_obj_align(content, LV_ALIGN_TOP_MID, 0, 100);
  lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(content, 0, 0);
  lv_obj_set_style_pad_all(content, 0, 0);
  lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(content, theme_get_default_padding(), 0);

  // Passphrase button
  passphrase_btn = lv_btn_create(content);
  lv_obj_set_size(passphrase_btn, LV_PCT(60), 50);
  lv_obj_set_style_margin_top(passphrase_btn, 20, 0);
  theme_apply_touch_button(passphrase_btn, false);
  lv_obj_add_event_cb(passphrase_btn, passphrase_btn_cb, LV_EVENT_CLICKED,
                      NULL);

  lv_obj_t *pp_label = lv_label_create(passphrase_btn);
  lv_label_set_text(pp_label, "Passphrase");
  lv_obj_set_style_text_font(pp_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(pp_label, main_color(), 0);
  lv_obj_center(pp_label);

  // Network label
  lv_obj_t *net_label = lv_label_create(content);
  lv_label_set_text(net_label, "Network");
  lv_obj_set_style_text_font(net_label, theme_font_small(), 0);
  lv_obj_set_style_text_color(net_label, secondary_color(), 0);
  lv_obj_set_style_margin_top(net_label, 20, 0);

  // Network dropdown
  network_dropdown = lv_dropdown_create(content);
  lv_dropdown_set_options(network_dropdown, "Mainnet\nTestnet");
  lv_dropdown_set_selected(
      network_dropdown, (selected_network == WALLET_NETWORK_MAINNET) ? 0 : 1);
  lv_obj_set_width(network_dropdown, LV_PCT(50));
  lv_obj_set_style_bg_color(network_dropdown, disabled_color(), 0);
  lv_obj_set_style_text_color(network_dropdown, main_color(), 0);
  lv_obj_set_style_text_font(network_dropdown, theme_font_small(), 0);
  lv_obj_set_style_border_color(network_dropdown, highlight_color(), 0);
  lv_obj_add_event_cb(network_dropdown, dropdown_open_cb, LV_EVENT_READY, NULL);
  lv_obj_add_event_cb(network_dropdown, network_dropdown_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);

  // Apply button
  apply_btn = lv_btn_create(content);
  lv_obj_set_size(apply_btn, LV_PCT(60), 60);
  lv_obj_set_style_margin_top(apply_btn, 20, 0);
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
  // Securely clear passphrase
  if (stored_passphrase) {
    memset(stored_passphrase, 0, strlen(stored_passphrase));
    free(stored_passphrase);
    stored_passphrase = NULL;
  }

  // Clear mnemonic
  if (mnemonic_content) {
    memset(mnemonic_content, 0, strlen(mnemonic_content));
    free(mnemonic_content);
    mnemonic_content = NULL;
  }

  if (wallet_settings_screen) {
    lv_obj_del(wallet_settings_screen);
    wallet_settings_screen = NULL;
  }
  back_button = NULL;

  network_dropdown = NULL;
  passphrase_btn = NULL;
  apply_btn = NULL;
  apply_label = NULL;
  title_cont = NULL;
  derivation_label = NULL;
  memset(base_fingerprint_hex, 0, sizeof(base_fingerprint_hex));
  return_callback = NULL;
  selected_network = WALLET_NETWORK_MAINNET;
  settings_changed = false;
}
