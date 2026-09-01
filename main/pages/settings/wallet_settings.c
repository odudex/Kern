// Wallet Settings Page - Allows changing wallet attributes (passphrase,
// network)

#include "wallet_settings.h"
#include "../../core/key.h"
#include "../../core/registry.h"
#include "../../core/wallet.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/settings_row.h"
#include "../../ui/theme_widgets.h"
#include "../passphrase.h"
#include "descriptor_manager.h"
#include <lvgl.h>
#include <stdio.h>
#include <string.h>

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
static const char *PARTIAL_HELP =
    "Allow signing PSBTs where some inputs are not yours (e.g. "
    "CoinJoin). Default off -- safer.";
static const char *EXPECTED_OWNED_HELP =
    "Sign inputs where our fingerprint matches but the script cannot be "
    "re-derived from the keypath. The device trusts the PSBT's keypath "
    "claim without cryptographic verification -- risky if your coordinator "
    "is compromised. Default off -- safer.";

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
static wallet_network_t selected_network = WALLET_NETWORK_DEFAULT;

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

/* Re-derive the live key+wallet from the current mnemonic, passphrase
 * and selected network. With the Apply button gone, network and
 * passphrase edits must take effect at the moment they're made. */
static bool apply_wallet_changes(void) {
  if (!mnemonic_content)
    return false;
  bool is_testnet = (selected_network == WALLET_NETWORK_TESTNET);
  wallet_unload();
  if (!key_load_from_mnemonic(mnemonic_content, stored_passphrase,
                              is_testnet)) {
    dialog_show_error_timeout("Failed to reload key", return_callback, 0);
    return false;
  }
  if (!wallet_init(selected_network)) {
    dialog_show_error_timeout("Failed to initialize wallet", return_callback,
                              0);
    return false;
  }
  registry_init(is_testnet);
  g_settings_applied = true;
  return true;
}

static void network_dropdown_cb(lv_event_t *e) {
  uint16_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  wallet_network_t new_network =
      (sel == 0) ? WALLET_NETWORK_MAINNET : WALLET_NETWORK_TESTNET;
  if (new_network != selected_network) {
    selected_network = new_network;
    if (apply_wallet_changes())
      settings_set_network(new_network);
  }
}

static void permissive_signing_cb(lv_event_t *e) {
  lv_obj_t *target = lv_event_get_target(e);
  settings_set_permissive_signing(lv_obj_has_state(target, LV_STATE_CHECKED));
}

static void expected_owned_signing_cb(lv_event_t *e) {
  lv_obj_t *target = lv_event_get_target(e);
  settings_set_expected_owned_signing(
      lv_obj_has_state(target, LV_STATE_CHECKED));
}

static void partial_signing_cb(lv_event_t *e) {
  lv_obj_t *target = lv_event_get_target(e);
  settings_set_partial_signing(lv_obj_has_state(target, LV_STATE_CHECKED));
}

static void refresh_fingerprint_display(void) {
  if (!title_cont)
    return;

  lv_obj_clean(title_cont);
  ui_fingerprint_create(title_cont, highlight_color());
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

  apply_wallet_changes();
  refresh_fingerprint_display();
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

/* Share the column's leftover height across the items instead of
 * leaving it pooled under the last row. Growing also gives each row a
 * resolved height, which is what makes its widget centre vertically —
 * LVGL top-aligns the track of a LV_SIZE_CONTENT row. */
static void distribute_item(lv_obj_t *item) {
  if (!item)
    return;
  lv_obj_set_flex_grow(item, 1);
  lv_obj_set_style_max_height(item, theme_min_touch_size() * 2, 0);
}

void wallet_settings_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded() || !wallet_is_initialized())
    return;

  return_callback = return_cb;
  selected_network = wallet_get_network();

  // Get current mnemonic for later use
  if (!key_get_mnemonic(&mnemonic_content)) {
    dialog_show_error_timeout("Failed to get mnemonic", return_callback, 0);
    return;
  }

  // Main screen
  wallet_settings_screen = lv_obj_create(parent);
  lv_obj_set_size(wallet_settings_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(wallet_settings_screen);
  lv_obj_clear_flag(wallet_settings_screen, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_pad_all(wallet_settings_screen, theme_default_padding(), 0);
  lv_obj_set_style_pad_top(wallet_settings_screen, theme_small_padding(), 0);
  lv_obj_set_style_pad_bottom(wallet_settings_screen, theme_small_padding(), 0);
  lv_obj_set_flex_flow(wallet_settings_screen, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(wallet_settings_screen, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(wallet_settings_screen, theme_small_padding(), 0);

  // Top nav bar: fingerprint centered in the corner-button band so it
  // aligns with the back button.
  lv_obj_t *nav_bar = lv_obj_create(wallet_settings_screen);
  lv_obj_set_size(nav_bar, LV_PCT(100), theme_corner_button_height());
  theme_apply_transparent_container(nav_bar);
  lv_obj_set_flex_flow(nav_bar, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(nav_bar, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(nav_bar, LV_OBJ_FLAG_SCROLLABLE);

  // Container for the fingerprint
  title_cont = theme_create_flex_row(nav_bar);
  lv_obj_set_style_pad_column(title_cont, 8, 0);
  refresh_fingerprint_display();

  // Content below the nav bar — scrollable column of settings rows.
  lv_obj_t *content = lv_obj_create(wallet_settings_screen);
  lv_obj_set_width(content, LV_PCT(100));
  lv_obj_set_flex_grow(content, 1);
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
  lv_obj_set_style_pad_gap(content, theme_small_padding(), 0);

  /* Uniform single-column layout: every row is `[Label] [Item] [?]`
   * (toggle/dropdown rows) or `[Label] [>]` (action rows). The
   * settings_row_* helpers handle the row container, label, item
   * widget, and trailing button — the per-row hand-rolled flex
   * containers that lived here previously are gone. */

  distribute_item(
      settings_row_action(content, "Passphrase", passphrase_btn_cb));
  distribute_item(
      settings_row_action(content, "Descriptors", descriptor_btn_cb));

  lv_obj_t *net_row = settings_row_dropdown(
      content, "Network", "Mainnet\nTestnet",
      (selected_network == WALLET_NETWORK_MAINNET) ? 0 : 1, network_dropdown_cb,
      "Network", NETWORK_HELP);
  distribute_item(net_row);
  network_dropdown = settings_row_get_widget(net_row);

  distribute_item(settings_row_toggle(
      content, "Permissive signing", settings_get_permissive_signing(),
      permissive_signing_cb, "Permissive signing", PERMISSIVE_HELP));

  distribute_item(settings_row_toggle(
      content, "Partial signing", settings_get_partial_signing(),
      partial_signing_cb, "Partial signing", PARTIAL_HELP));

  distribute_item(settings_row_toggle(
      content, "Expected-owned signing", settings_get_expected_owned_signing(),
      expected_owned_signing_cb, "Expected-owned signing",
      EXPECTED_OWNED_HELP));

  /* Session Descriptors moved into the Descriptors sub-page
   * (descriptor_manager_page). This page is one level shallower. */

  // Back button (on parent for absolute positioning)
  back_button = ui_create_back_button(parent, back_btn_cb);
}

void wallet_settings_page_show(void) {
  if (wallet_settings_screen)
    lv_obj_clear_flag(wallet_settings_screen, LV_OBJ_FLAG_HIDDEN);
  // Back button is parented to the screen, not wallet_settings_screen, so its
  // visibility has to be toggled alongside the page.
  if (back_button)
    lv_obj_clear_flag(back_button, LV_OBJ_FLAG_HIDDEN);
}

void wallet_settings_page_hide(void) {
  if (wallet_settings_screen)
    lv_obj_add_flag(wallet_settings_screen, LV_OBJ_FLAG_HIDDEN);
  if (back_button)
    lv_obj_add_flag(back_button, LV_OBJ_FLAG_HIDDEN);
}

void wallet_settings_page_destroy(void) {
  SECURE_FREE_STRING(stored_passphrase);
  SECURE_FREE_STRING(mnemonic_content);

  if (wallet_settings_screen) {
    lv_obj_del(wallet_settings_screen);
    wallet_settings_screen = NULL;
  }

  // Back button lives on the parent screen, not wallet_settings_screen, so
  // deleting the screen above doesn't take it down — delete it explicitly.
  if (back_button) {
    lv_obj_del(back_button);
    back_button = NULL;
  }

  network_dropdown = NULL;
  title_cont = NULL;
  return_callback = NULL;
  selected_network = WALLET_NETWORK_DEFAULT;
}
