// Addresses Page - Displays receive and change addresses

#include "addresses.h"
#include "../../core/storage.h"
#include "../../core/wallet.h"
#include "../../qr/scanner.h"
#include "../../ui/assets/icons_36.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/theme.h"
#include "../load_descriptor_storage.h"
#include "../settings/wallet_settings.h"
#include "../shared/descriptor_loader.h"
#include <lvgl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_core.h>

#define NUM_ADDRESSES 8

static lv_obj_t *addresses_screen = NULL;
static lv_obj_t *type_button = NULL;
static lv_obj_t *prev_button = NULL;
static lv_obj_t *next_button = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *settings_button = NULL;
static lv_obj_t *address_list_container = NULL;
static lv_obj_t *load_descriptor_btn = NULL;
static lv_obj_t *btn_cont = NULL;
static lv_obj_t *detail_container = NULL;
static lv_obj_t *detail_back_button = NULL;
static void (*return_callback)(void) = NULL;

static bool show_change = false;
static uint32_t address_offset = 0;

static char stored_addresses[NUM_ADDRESSES][128];
static uint32_t stored_indices[NUM_ADDRESSES];
static int stored_count = 0;

static lv_obj_t *scan_button = NULL;
static char *scanned_address = NULL;
static uint32_t scan_search_start = 0;
static uint32_t scan_search_limit = 50;

static void refresh_address_list(void);
static void scan_button_cb(lv_event_t *e);
static void return_from_scan_cb(void);
static void perform_address_sweep(void);

// Format address as 4-char blocks with alternating main/highlight colors
static void format_address_colored_blocks(char *dest, size_t dest_size,
                                          const char *address) {
  lv_color32_t c1 = lv_color_to_32(main_color(), LV_OPA_COVER);
  lv_color32_t c2 = lv_color_to_32(highlight_color(), LV_OPA_COVER);
  uint32_t hex1 = (c1.red << 16) | (c1.green << 8) | c1.blue;
  uint32_t hex2 = (c2.red << 16) | (c2.green << 8) | c2.blue;

  size_t len = strlen(address);
  size_t written = 0;
  dest[0] = '\0';

  for (size_t pos = 0; pos < len; pos += 4) {
    uint32_t color = ((pos / 4) % 2 == 0) ? hex1 : hex2;
    size_t chunk = (len - pos < 4) ? (len - pos) : 4;
    int n = snprintf(dest + written, dest_size - written, "%s#%06X %.*s#",
                     (pos > 0) ? " " : "", (unsigned)color, (int)chunk,
                     address + pos);
    if (n < 0 || (size_t)n >= dest_size - written)
      break;
    written += n;
  }
}

static void show_address_detail(int index);

static void back_button_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

static void return_from_wallet_settings_cb(void) {
  wallet_settings_page_destroy();
  // Save callback before destroy clears it
  void (*saved_callback)(void) = return_callback;
  // Recreate page to refresh with updated key/wallet data
  addresses_page_destroy();
  addresses_page_create(lv_screen_active(), saved_callback);
  addresses_page_show();
}

static void settings_button_cb(lv_event_t *e) {
  (void)e;
  addresses_page_hide();
  wallet_settings_page_create(lv_screen_active(),
                              return_from_wallet_settings_cb);
  wallet_settings_page_show();
}

static void type_button_cb(lv_event_t *e) {
  (void)e;
  show_change = !show_change;
  address_offset = 0;
  lv_label_set_text(lv_obj_get_child(type_button, 0),
                    show_change ? "Change" : "Receive");
  refresh_address_list();
}

static void prev_button_cb(lv_event_t *e) {
  (void)e;
  if (address_offset >= NUM_ADDRESSES) {
    address_offset -= NUM_ADDRESSES;
    refresh_address_list();
  }
}

static void next_button_cb(lv_event_t *e) {
  (void)e;
  address_offset += NUM_ADDRESSES;
  refresh_address_list();
}

static void on_descriptor_loaded(void) {
  if (load_descriptor_btn)
    lv_obj_add_flag(load_descriptor_btn, LV_OBJ_FLAG_HIDDEN);
  if (btn_cont)
    lv_obj_clear_flag(btn_cont, LV_OBJ_FLAG_HIDDEN);
  refresh_address_list();
}

static void descriptor_validation_cb(descriptor_validation_result_t result,
                                     void *user_data) {
  (void)user_data;

  if (result == VALIDATION_SUCCESS) {
    on_descriptor_loaded();
    return;
  }

  descriptor_loader_show_error(result);
}

static void return_from_descriptor_scanner_cb(void) {
  descriptor_loader_process_scanner(descriptor_validation_cb, NULL, NULL);
  addresses_page_show();
}

static void return_from_descriptor_storage(void) {
  load_descriptor_storage_page_destroy();
  addresses_page_show();
}

static void success_from_descriptor_storage(void) {
  load_descriptor_storage_page_destroy();
  addresses_page_show();
  on_descriptor_loaded();
}

static void load_desc_qr_cb(void) {
  descriptor_loader_destroy_source_menu();
  addresses_page_hide();
  qr_scanner_page_create(NULL, return_from_descriptor_scanner_cb);
  qr_scanner_page_show();
}

static void load_desc_flash_cb(void) {
  descriptor_loader_destroy_source_menu();
  addresses_page_hide();
  load_descriptor_storage_page_create(
      lv_screen_active(), return_from_descriptor_storage,
      success_from_descriptor_storage, STORAGE_FLASH);
  load_descriptor_storage_page_show();
}

static void load_desc_sd_cb(void) {
  descriptor_loader_destroy_source_menu();
  addresses_page_hide();
  load_descriptor_storage_page_create(
      lv_screen_active(), return_from_descriptor_storage,
      success_from_descriptor_storage, STORAGE_SD);
  load_descriptor_storage_page_show();
}

static void load_desc_source_back_cb(void) {
  descriptor_loader_destroy_source_menu();
  addresses_page_show();
}

static void load_descriptor_btn_cb(lv_event_t *e) {
  (void)e;
  addresses_page_hide();
  descriptor_loader_show_source_menu(lv_screen_active(), load_desc_qr_cb,
                                     load_desc_flash_cb, load_desc_sd_cb,
                                     load_desc_source_back_cb);
}

static void truncate_address_middle(char *dest, size_t dest_size,
                                    const char *address, int prefix_len,
                                    int suffix_len) {
  size_t addr_len = strlen(address);
  size_t needed = (size_t)(prefix_len + 3 + suffix_len + 1);
  if (addr_len <= needed || dest_size < needed) {
    snprintf(dest, dest_size, "%s", address);
    return;
  }
  snprintf(dest, dest_size, "%.*s...%s", prefix_len, address,
           address + addr_len - suffix_len);
}

// Detail view back button callback
static void detail_back_cb(lv_event_t *e) {
  (void)e;
  if (detail_container)
    lv_obj_add_flag(detail_container, LV_OBJ_FLAG_HIDDEN);
  if (detail_back_button) {
    lv_obj_del(detail_back_button);
    detail_back_button = NULL;
  }
  if (addresses_screen)
    lv_obj_clear_flag(addresses_screen, LV_OBJ_FLAG_HIDDEN);
  if (back_button)
    lv_obj_clear_flag(back_button, LV_OBJ_FLAG_HIDDEN);
  if (settings_button)
    lv_obj_clear_flag(settings_button, LV_OBJ_FLAG_HIDDEN);
}

static void show_address_detail(int index) {
  if (index < 0 || index >= stored_count)
    return;

  const char *address = stored_addresses[index];
  uint32_t addr_idx = stored_indices[index];

  // Hide main screen and buttons
  if (addresses_screen)
    lv_obj_add_flag(addresses_screen, LV_OBJ_FLAG_HIDDEN);
  if (back_button)
    lv_obj_add_flag(back_button, LV_OBJ_FLAG_HIDDEN);
  if (settings_button)
    lv_obj_add_flag(settings_button, LV_OBJ_FLAG_HIDDEN);

  // Recreate detail container each time
  if (detail_container) {
    lv_obj_del(detail_container);
    detail_container = NULL;
  }

  lv_obj_t *parent = lv_screen_active();

  detail_container = lv_obj_create(parent);
  lv_obj_set_size(detail_container, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(detail_container);
  lv_obj_set_style_pad_all(detail_container, theme_get_default_padding(), 0);
  lv_obj_set_flex_flow(detail_container, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(detail_container, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(detail_container, theme_get_default_padding(), 0);

  // Title
  char title[32];
  snprintf(title, sizeof(title), "%s #%u", show_change ? "Change" : "Receive",
           addr_idx);
  lv_obj_t *title_label = theme_create_label(detail_container, title, false);
  lv_obj_set_style_text_align(title_label, LV_TEXT_ALIGN_CENTER, 0);

  // QR code in white container
  int32_t square_size = lv_disp_get_hor_res(NULL) * 55 / 100;

  lv_obj_t *qr_container = lv_obj_create(detail_container);
  lv_obj_set_size(qr_container, square_size, square_size);
  lv_obj_set_style_bg_color(qr_container, lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_bg_opa(qr_container, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(qr_container, 0, 0);
  lv_obj_set_style_pad_all(qr_container, 15, 0);
  lv_obj_set_style_radius(qr_container, 0, 0);
  lv_obj_clear_flag(qr_container, LV_OBJ_FLAG_SCROLLABLE);

  int32_t qr_size = square_size - 30; // 15px padding each side

  lv_obj_t *qr = lv_qrcode_create(qr_container);
  lv_qrcode_set_size(qr, qr_size);
  lv_qrcode_update(qr, address, strlen(address));
  lv_obj_center(qr);

  // Full address text with alternating colored 4-char blocks
  char colored_addr[512];
  format_address_colored_blocks(colored_addr, sizeof(colored_addr), address);
  lv_obj_t *addr_label = lv_label_create(detail_container);
  lv_label_set_recolor(addr_label, true);
  lv_label_set_text(addr_label, colored_addr);
  lv_obj_set_width(addr_label, LV_PCT(95));
  lv_label_set_long_mode(addr_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(addr_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(addr_label, theme_font_medium(), 0);

  // Back button
  detail_back_button = ui_create_back_button(parent, detail_back_cb);
}

// Address button click handler
static void address_button_cb(lv_event_t *e) {
  int index = (int)(intptr_t)lv_event_get_user_data(e);
  show_address_detail(index);
}

static void refresh_address_list(void) {
  if (!address_list_container)
    return;

  lv_obj_clean(address_list_container);
  stored_count = 0;

  wallet_policy_t policy = wallet_get_policy();

  // For multisig without descriptor, show message
  if (policy == WALLET_POLICY_MULTISIG && !wallet_has_descriptor()) {
    lv_obj_t *msg = theme_create_label(
        address_list_container,
        "Multisig addresses require a wallet descriptor.\n\n"
        "Scan your wallet descriptor QR code to view addresses.",
        false);
    lv_obj_set_width(msg, LV_PCT(100));
    lv_obj_set_style_text_align(msg, LV_TEXT_ALIGN_CENTER, 0);
    return;
  }

  if (address_offset == 0)
    lv_obj_add_state(prev_button, LV_STATE_DISABLED);
  else
    lv_obj_clear_state(prev_button, LV_STATE_DISABLED);

  for (uint32_t i = 0; i < NUM_ADDRESSES; i++) {
    uint32_t idx = address_offset + i;
    char *address = NULL;
    bool success;

    if (policy == WALLET_POLICY_MULTISIG) {
      success = show_change
                    ? wallet_get_multisig_change_address(idx, &address)
                    : wallet_get_multisig_receive_address(idx, &address);
    } else {
      success = show_change ? wallet_get_change_address(idx, &address)
                            : wallet_get_receive_address(idx, &address);
    }

    if (!success || !address)
      continue;

    // Store address for detail view access
    int si = stored_count;
    snprintf(stored_addresses[si], sizeof(stored_addresses[si]), "%s", address);
    stored_indices[si] = idx;
    stored_count++;

    // Create truncated display text
    char truncated[64];
    truncate_address_middle(truncated, sizeof(truncated), address, 14, 10);

    char btn_text[80];
    snprintf(btn_text, sizeof(btn_text), "%u: %s", idx, truncated);

    wally_free_string(address);

    // Create clickable button
    lv_obj_t *btn = lv_btn_create(address_list_container);
    lv_obj_set_size(btn, LV_PCT(100), LV_SIZE_CONTENT);
    theme_apply_touch_button(btn, false);
    lv_obj_set_flex_grow(btn, 1);

    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, btn_text);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_align(label, LV_ALIGN_LEFT_MID);
    theme_apply_button_label(label, false);

    lv_obj_add_event_cb(btn, address_button_cb, LV_EVENT_CLICKED,
                        (void *)(intptr_t)si);
  }
}

static lv_obj_t *create_nav_button(lv_obj_t *parent, const char *text,
                                   lv_coord_t width, lv_event_cb_t cb) {
  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, width, LV_SIZE_CONTENT);
  theme_apply_touch_button(btn, false);
  lv_obj_t *label = lv_label_create(btn);
  lv_label_set_text(label, text);
  lv_obj_center(label);
  theme_apply_button_label(label, false);
  lv_obj_add_event_cb(btn, cb, LV_EVENT_CLICKED, NULL);
  return btn;
}

// --- Scan address flow ---

static void scan_found_cb(void *user_data) {
  (void)user_data;
  free(scanned_address);
  scanned_address = NULL;
  addresses_page_show();
}

static void scan_not_found_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed) {
    scan_search_start = scan_search_limit;
    scan_search_limit += 50;
    perform_address_sweep();
    return;
  }
  free(scanned_address);
  scanned_address = NULL;
  addresses_page_show();
}

static void perform_address_sweep(void) {
  wallet_policy_t policy = wallet_get_policy();

  // Search receive addresses
  for (uint32_t i = scan_search_start; i < scan_search_limit; i++) {
    char *address = NULL;
    bool success;

    if (policy == WALLET_POLICY_MULTISIG)
      success = wallet_get_multisig_receive_address(i, &address);
    else
      success = wallet_get_receive_address(i, &address);

    if (!success || !address)
      continue;

    if (strcmp(address, scanned_address) == 0) {
      wally_free_string(address);
      char msg[64];
      snprintf(msg, sizeof(msg), "Receive #%u", i);
      dialog_show_info("Address Verified", msg, scan_found_cb, NULL,
                       DIALOG_STYLE_FULLSCREEN);
      return;
    }
    wally_free_string(address);
  }

  // Search change addresses
  for (uint32_t i = scan_search_start; i < scan_search_limit; i++) {
    char *address = NULL;
    bool success;

    if (policy == WALLET_POLICY_MULTISIG)
      success = wallet_get_multisig_change_address(i, &address);
    else
      success = wallet_get_change_address(i, &address);

    if (!success || !address)
      continue;

    if (strcmp(address, scanned_address) == 0) {
      wally_free_string(address);
      char msg[64];
      snprintf(msg, sizeof(msg), "Change #%u", i);
      dialog_show_info("Address Verified", msg, scan_found_cb, NULL,
                       DIALOG_STYLE_FULLSCREEN);
      return;
    }
    wally_free_string(address);
  }

  // Not found
  char msg[192];
  snprintf(msg, sizeof(msg),
           "Address not found in first %u addresses.\n\n"
           "(Check if loaded wallet settings match coordinator's)\n\n"
           "Search 50 more?",
           scan_search_limit);
  dialog_show_confirm(msg, scan_not_found_cb, NULL, DIALOG_STYLE_FULLSCREEN);
}

static void return_from_scan_cb(void) {
  char *content = qr_scanner_get_completed_content();
  qr_scanner_page_destroy();

  if (!content) {
    addresses_page_show();
    return;
  }

  // Validate address using libwally
  const char *hrp =
      (wallet_get_network() == WALLET_NETWORK_MAINNET) ? "bc" : "tb";
  uint32_t wally_net = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                           ? WALLY_NETWORK_BITCOIN_MAINNET
                           : WALLY_NETWORK_BITCOIN_TESTNET;
  unsigned char script[128];
  size_t written = 0;
  bool valid =
      (wally_addr_segwit_to_bytes(content, hrp, 0, script, sizeof(script),
                                  &written) == WALLY_OK) ||
      (wally_address_to_scriptpubkey(content, wally_net, script, sizeof(script),
                                     &written) == WALLY_OK);
  if (!valid) {
    free(content);
    dialog_show_error("Invalid address", NULL, 0);
    addresses_page_show();
    return;
  }

  if (scanned_address)
    free(scanned_address);
  scanned_address = content;
  scan_search_start = 0;
  scan_search_limit = 50;
  perform_address_sweep();
}

static void scan_button_cb(lv_event_t *e) {
  (void)e;
  addresses_page_hide();
  qr_scanner_page_create(NULL, return_from_scan_cb);
  qr_scanner_page_show();
}

void addresses_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !wallet_is_initialized())
    return;

  return_callback = return_cb;
  show_change = false;
  address_offset = 0;

  // Main screen
  addresses_screen = lv_obj_create(parent);
  lv_obj_set_size(addresses_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(addresses_screen);
  lv_obj_set_style_pad_all(addresses_screen, theme_get_default_padding(), 0);
  lv_obj_set_flex_flow(addresses_screen, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(addresses_screen, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(addresses_screen, theme_get_default_padding(), 0);

  // Key info header
  ui_key_info_create(addresses_screen);

  wallet_policy_t policy = wallet_get_policy();
  bool needs_descriptor =
      (policy == WALLET_POLICY_MULTISIG && !wallet_has_descriptor());

  // Load Descriptor button (for multisig without descriptor)
  load_descriptor_btn = lv_btn_create(addresses_screen);
  lv_obj_set_size(load_descriptor_btn, LV_PCT(70), LV_SIZE_CONTENT);
  theme_apply_touch_button(load_descriptor_btn, false);
  lv_obj_t *load_label = lv_label_create(load_descriptor_btn);
  lv_label_set_text(load_label, "Load Descriptor");
  lv_obj_center(load_label);
  theme_apply_button_label(load_label, false);
  lv_obj_add_event_cb(load_descriptor_btn, load_descriptor_btn_cb,
                      LV_EVENT_CLICKED, NULL);
  if (!needs_descriptor) {
    lv_obj_add_flag(load_descriptor_btn, LV_OBJ_FLAG_HIDDEN);
  }

  // Button container
  btn_cont = lv_obj_create(addresses_screen);
  lv_obj_set_size(btn_cont, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(btn_cont);
  lv_obj_set_flex_flow(btn_cont, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(btn_cont, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  type_button =
      create_nav_button(btn_cont, "Receive", LV_PCT(40), type_button_cb);
  prev_button = create_nav_button(btn_cont, "<", LV_PCT(15), prev_button_cb);
  next_button = create_nav_button(btn_cont, ">", LV_PCT(15), next_button_cb);
  lv_obj_add_state(prev_button, LV_STATE_DISABLED);

  // Scan address button with QR icon
  scan_button = lv_btn_create(btn_cont);
  lv_obj_set_size(scan_button, LV_PCT(22), LV_SIZE_CONTENT);
  theme_apply_touch_button(scan_button, false);
  lv_obj_t *scan_label = lv_label_create(scan_button);
  lv_label_set_text(scan_label, ICON_QRCODE_36);
  lv_obj_set_style_text_font(scan_label, &icons_36, 0);
  lv_obj_center(scan_label);
  lv_obj_add_event_cb(scan_button, scan_button_cb, LV_EVENT_CLICKED, NULL);

  // Hide navigation buttons if multisig without descriptor
  if (needs_descriptor) {
    lv_obj_add_flag(btn_cont, LV_OBJ_FLAG_HIDDEN);
  }

  // Address list container
  address_list_container = lv_obj_create(addresses_screen);
  lv_obj_set_size(address_list_container, LV_PCT(100), LV_PCT(100));
  theme_apply_transparent_container(address_list_container);
  lv_obj_set_flex_flow(address_list_container, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(address_list_container, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_flex_grow(address_list_container, 1);

  refresh_address_list();

  // Back button (on parent for absolute positioning)
  back_button = ui_create_back_button(parent, back_button_cb);

  // Settings button at top-right
  settings_button = ui_create_settings_button(parent, settings_button_cb);
}

void addresses_page_show(void) {
  if (addresses_screen)
    lv_obj_clear_flag(addresses_screen, LV_OBJ_FLAG_HIDDEN);
}

void addresses_page_hide(void) {
  if (addresses_screen)
    lv_obj_add_flag(addresses_screen, LV_OBJ_FLAG_HIDDEN);
}

void addresses_page_destroy(void) {
  load_descriptor_storage_page_destroy();
  descriptor_loader_destroy_source_menu();

  if (detail_back_button) {
    lv_obj_del(detail_back_button);
    detail_back_button = NULL;
  }
  if (detail_container) {
    lv_obj_del(detail_container);
    detail_container = NULL;
  }
  if (back_button) {
    lv_obj_del(back_button);
    back_button = NULL;
  }
  if (settings_button) {
    lv_obj_del(settings_button);
    settings_button = NULL;
  }
  if (addresses_screen) {
    lv_obj_del(addresses_screen);
    addresses_screen = NULL;
  }
  type_button = NULL;
  prev_button = NULL;
  next_button = NULL;
  scan_button = NULL;
  load_descriptor_btn = NULL;
  btn_cont = NULL;
  address_list_container = NULL;
  return_callback = NULL;
  show_change = false;
  address_offset = 0;
  stored_count = 0;
  if (scanned_address) {
    free(scanned_address);
    scanned_address = NULL;
  }
  scan_search_start = 0;
  scan_search_limit = 50;
}
