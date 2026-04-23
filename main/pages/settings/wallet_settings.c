// Wallet Settings Page - Allows changing wallet attributes (passphrase,
// network)

#include "wallet_settings.h"
#include "../../core/key.h"
#include "../../core/wallet.h"
#include "../../ui/assets/icons_24.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/settings_row.h"
#include "../../ui/theme.h"
#include "../passphrase.h"
#include "descriptor_manager.h"
#include <lvgl.h>
#include <stdio.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>

#include "../../core/settings.h"
#include "../../utils/secure_mem.h"

/* Help-modal text shown when the user taps the [?] button on a
 * setting row. Each is a string literal — settings_row_* stores the
 * pointer, doesn't copy. */
static const char *NETWORK_HELP =
    "Mainnet for live Bitcoin; Testnet for development and testing. "
    "Wallet attributes (descriptor, addresses) are derived per-network.";
static const char *PERMISSIVE_HELP =
    "Allow signing for unknown derivation paths after on-screen "
    "confirmation. Reduces safety. Default off.";

static lv_obj_t *wallet_settings_screen = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *network_dropdown = NULL;
/* Toggle/button refs aren't held statically — settings_row_* hides
 * the widget construction. Only the network dropdown is referenced
 * later (by refresh_wallet_attributes) so it's the only ref kept
 * alive between calls. */
static lv_obj_t *title_cont = NULL;

static void (*return_callback)(void) = NULL;
static char *stored_passphrase = NULL;
static char *mnemonic_content = NULL;
static char base_fingerprint_hex[9] = {0};
static wallet_network_t selected_network = WALLET_NETWORK_MAINNET;

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

static void network_dropdown_cb(lv_event_t *e) {
  uint16_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  wallet_network_t new_network =
      (sel == 0) ? WALLET_NETWORK_MAINNET : WALLET_NETWORK_TESTNET;
  if (new_network != selected_network) {
    selected_network = new_network;
  }
}

static void permissive_signing_cb(lv_event_t *e) {
  lv_obj_t *target = lv_event_get_target(e);
  settings_set_permissive_signing(lv_obj_has_state(target, LV_STATE_CHECKED));
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

  passphrase_page_destroy();
  wallet_settings_page_show();

  // Update title to show both fingerprints
  update_title_with_passphrase(stored_passphrase);
}

static void refresh_wallet_attributes(void) {
  selected_network = wallet_get_network();

  if (network_dropdown)
    lv_dropdown_set_selected(
        network_dropdown, (selected_network == WALLET_NETWORK_MAINNET) ? 0 : 1);
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

void wallet_settings_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded() || !wallet_is_initialized())
    return;

  return_callback = return_cb;
  selected_network = wallet_get_network();

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

  // Content container below top bar
  lv_obj_t *content = lv_obj_create(wallet_settings_screen);
  lv_obj_set_size(content, LV_PCT(100), LV_VER_RES - top_h);
  lv_obj_align(content, LV_ALIGN_TOP_MID, 0, top_h);
  lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(content, 0, 0);
  lv_obj_set_style_pad_all(content, 0, 0);
  /* Vertical scroll as a safety net — uniform [Label][Item][?] rows
   * fit in 320×480 (wave_35) without ever needing to scroll, but
   * this protects against future row additions or theme size changes. */
  lv_obj_add_flag(content, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_scroll_dir(content, LV_DIR_VER);
  lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  /* Tight gap — the rows are already touch-target tall and self-pad
   * internally; default_padding looked too sparse in 320×480. */
  lv_obj_set_style_pad_gap(content, 4, 0);

  /* Uniform single-column layout: every row is `[Label] [Item] [?]`
   * (toggle/dropdown rows) or `[Label] [>]` (action rows). The
   * settings_row_* helpers handle the row container, label, item
   * widget, and trailing button — the per-row hand-rolled flex
   * containers that lived here previously are gone. */

  settings_row_action(content, "Passphrase", passphrase_btn_cb);
  settings_row_action(content, "Descriptors", descriptor_btn_cb);

  lv_obj_t *net_row = settings_row_dropdown(
      content, "Network", "Mainnet\nTestnet",
      (selected_network == WALLET_NETWORK_MAINNET) ? 0 : 1, network_dropdown_cb,
      "Network", NETWORK_HELP);
  network_dropdown = settings_row_get_widget(net_row);

  settings_row_toggle(content, "Permissive signing",
                      settings_get_permissive_signing(), permissive_signing_cb,
                      "Permissive signing", PERMISSIVE_HELP);

  /* Registered Descriptors moved into the Descriptors sub-page
   * (descriptor_manager_page). This page is one level shallower. */

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
  SECURE_FREE_STRING(stored_passphrase);
  SECURE_FREE_STRING(mnemonic_content);

  if (wallet_settings_screen) {
    lv_obj_del(wallet_settings_screen);
    wallet_settings_screen = NULL;
  }
  back_button = NULL;

  network_dropdown = NULL;
  title_cont = NULL;
  secure_memzero(base_fingerprint_hex, sizeof(base_fingerprint_hex));
  return_callback = NULL;
  selected_network = WALLET_NETWORK_MAINNET;
}
