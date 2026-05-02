// Addresses Page - Displays receive and change addresses

#include "addresses.h"
#include "../../core/registry.h"
#include "../../core/ss_whitelist.h"
#include "../../core/storage.h"
#include "../../core/wallet.h"
#include "../../qr/scanner.h"
#include "../../ui/assets/icons_36.h"
#include "../../ui/battery.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/theme.h"
#include "../settings/wallet_settings.h"
#include "../shared/address_checker.h"
#include <lvgl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_core.h>

#define NUM_ADDRESSES 8

static lv_obj_t *addresses_screen = NULL;
static lv_obj_t *source_dropdown = NULL;
static lv_obj_t *prev_button = NULL;
static lv_obj_t *next_button = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *settings_button = NULL;
static lv_obj_t *address_list_container = NULL;
static lv_obj_t *detail_container = NULL;
static lv_obj_t *detail_back_button = NULL;
static void (*return_callback)(void) = NULL;

static bool show_change = false;
static uint32_t address_offset = 0;
static uint32_t current_account = 0;

static char stored_addresses[NUM_ADDRESSES][128];
static uint32_t stored_indices[NUM_ADDRESSES];
static int stored_count = 0;

static lv_obj_t *scan_button = NULL;

static lv_obj_t *account_btn = NULL;
static lv_obj_t *account_value_label = NULL;
static lv_obj_t *account_overlay = NULL;
static lv_obj_t *account_numpad = NULL;
static lv_obj_t *account_input_label = NULL;
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

static void refresh_address_list(void);
static void scan_button_cb(lv_event_t *e);
static void return_from_scan_cb(void);

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

static void update_account_button_visibility(void) {
  if (!account_btn)
    return;
  uint16_t sel = lv_dropdown_get_selected(source_dropdown);
  if (sel >= 4)
    lv_obj_add_flag(account_btn, LV_OBJ_FLAG_HIDDEN);
  else
    lv_obj_clear_flag(account_btn, LV_OBJ_FLAG_HIDDEN);
}

static void source_dropdown_cb(lv_event_t *e) {
  (void)e;
  address_offset = 0;
  update_account_button_visibility();
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
  int32_t square_size = theme_get_screen_width() * 55 / 100;

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

  if (address_offset == 0)
    lv_obj_add_state(prev_button, LV_STATE_DISABLED);
  else
    lv_obj_clear_state(prev_button, LV_STATE_DISABLED);

  uint16_t sel = lv_dropdown_get_selected(source_dropdown);
  bool is_testnet = (wallet_get_network() == WALLET_NETWORK_TESTNET);
  uint32_t account = current_account;
  uint32_t chain = show_change ? 1 : 0;

  static const ss_script_type_t script_map[4] = {
      SS_SCRIPT_P2WPKH,      /* 0 Native SegWit  */
      SS_SCRIPT_P2TR,        /* 1 Taproot        */
      SS_SCRIPT_P2PKH,       /* 2 Legacy         */
      SS_SCRIPT_P2SH_P2WPKH, /* 3 Nested SegWit */
  };

  const registry_entry_t *reg_entry = NULL;
  if (sel >= 4) {
    reg_entry = registry_get((size_t)(sel - 4));
    if (!reg_entry)
      return;
  }

  for (uint32_t i = 0; i < NUM_ADDRESSES; i++) {
    uint32_t idx = address_offset + i;
    char addr_buf[SS_ADDRESS_MAX_LEN];
    char *dynamic_addr = NULL;
    bool success = false;

    if (reg_entry) {
      uint32_t mp = (reg_entry->num_paths <= 1) ? 0 : chain;
      int ret = wally_descriptor_to_address(reg_entry->desc, 0, mp, idx, 0,
                                            &dynamic_addr);
      success = (ret == WALLY_OK) && dynamic_addr;
    } else {
      success = ss_address(script_map[sel], account, chain, idx, is_testnet,
                           addr_buf, sizeof(addr_buf));
    }

    if (!success)
      continue;

    /* Store address for detail view */
    int si = stored_count;
    snprintf(stored_addresses[si], sizeof(stored_addresses[si]), "%s",
             dynamic_addr ? dynamic_addr : addr_buf);
    stored_indices[si] = idx;
    stored_count++;

    if (dynamic_addr) {
      wally_free_string(dynamic_addr);
      dynamic_addr = NULL;
    }

    /* Build truncated display label from the stored copy */
    const lv_font_t *font = theme_font_small();
    int avg_char_w = lv_font_get_glyph_width(font, '0', '0');
    int32_t usable_w =
        theme_get_screen_width() - 2 * theme_get_default_padding();
    int max_chars = usable_w / avg_char_w - 4;
    int prefix = max_chars * 55 / 100;
    int suffix = max_chars - prefix - 3;
    if (prefix < 6)
      prefix = 6;
    if (suffix < 4)
      suffix = 4;
    char truncated[64];
    truncate_address_middle(truncated, sizeof(truncated), stored_addresses[si],
                            prefix, suffix);

    char btn_text[80];
    snprintf(btn_text, sizeof(btn_text), "%u: %s", idx, truncated);

    /* Create clickable button */
    lv_obj_t *btn = lv_btn_create(address_list_container);
    lv_obj_set_size(btn, LV_PCT(100), LV_SIZE_CONTENT);
    theme_apply_touch_button(btn, false);
    lv_obj_set_flex_grow(btn, 1);

    lv_obj_t *label = lv_label_create(btn);
    lv_label_set_text(label, btn_text);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_LEFT, 0);
    lv_obj_set_align(label, LV_ALIGN_LEFT_MID);
    lv_obj_set_style_text_font(label, theme_font_small(), 0);
    lv_obj_set_style_text_color(label, main_color(), 0);

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

static void scan_found_cb(void) {
  address_checker_destroy();
  addresses_page_show();
}

static void scan_not_found_cb(void) {
  address_checker_destroy();
  addresses_page_show();
}

static void return_from_scan_cb(void) {
  char *content = qr_scanner_get_completed_content();
  qr_scanner_page_destroy();

  if (!content) {
    addresses_page_show();
    return;
  }

  address_checker_check(content, scan_found_cb, scan_not_found_cb);
  free(content);
}

static void scan_button_cb(lv_event_t *e) {
  (void)e;
  addresses_page_hide();
  qr_scanner_page_create(NULL, return_from_scan_cb);
  qr_scanner_page_show();
}

// --- Account numpad overlay ---

static void update_account_display(void) {
  if (!account_value_label)
    return;
  char buf[16];
  snprintf(buf, sizeof(buf), "acc:%u", current_account);
  lv_label_set_text(account_value_label, buf);
}

static void update_account_input_display(void) {
  if (!account_input_label)
    return;
  char display[14];
  if (account_input_len == 0)
    snprintf(display, sizeof(display), "_");
  else
    snprintf(display, sizeof(display), "%s_", account_input_buffer);
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

static void account_numpad_event_cb(lv_event_t *e) {
  lv_obj_t *btnm = lv_event_get_target(e);
  uint32_t btn_id = lv_btnmatrix_get_selected_btn(btnm);
  const char *txt = lv_btnmatrix_get_btn_text(btnm, btn_id);

  if (strcmp(txt, LV_SYMBOL_OK) == 0) {
    if (account_input_len > 0) {
      unsigned long val = strtoul(account_input_buffer, NULL, 10);
      if (val < SS_MAX_ACCOUNT) {
        current_account = (uint32_t)val;
        update_account_display();
        address_offset = 0;
        refresh_address_list();
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
               current_account);

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
  lv_obj_add_event_cb(account_numpad, account_numpad_event_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);

  update_numpad_buttons();
}

static void account_btn_cb(lv_event_t *e) {
  (void)e;
  show_account_overlay();
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
  lv_obj_t *header = ui_key_info_create(addresses_screen);
  ui_battery_create(header);

  // Top row: script/source dropdown + account button (shared concept with
  // public-key page — keep widths/order in sync if/when extracted).
  lv_obj_t *top_row = lv_obj_create(addresses_screen);
  lv_obj_set_size(top_row, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(top_row);
  lv_obj_set_flex_flow(top_row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(top_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  char source_opts[600];
  size_t written =
      (size_t)snprintf(source_opts, sizeof(source_opts),
                       "Native SegWit\nTaproot\nLegacy\nNested SegWit");
  size_t reg_count = registry_count();
  for (size_t ri = 0; ri < reg_count && written < sizeof(source_opts) - 1;
       ri++) {
    const registry_entry_t *entry = registry_get(ri);
    int n = snprintf(source_opts + written, sizeof(source_opts) - written,
                     "\n%s", entry->id);
    if (n > 0)
      written += (size_t)n;
  }
  source_dropdown = theme_create_dropdown(top_row, source_opts);
  lv_obj_set_width(source_dropdown, LV_PCT(72));
  lv_obj_add_event_cb(source_dropdown, source_dropdown_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);

  account_btn = lv_btn_create(top_row);
  lv_obj_set_size(account_btn, LV_PCT(25), LV_SIZE_CONTENT);
  theme_apply_touch_button(account_btn, false);
  account_value_label = lv_label_create(account_btn);
  lv_obj_set_style_text_font(account_value_label, theme_font_small(), 0);
  lv_obj_center(account_value_label);
  lv_obj_add_event_cb(account_btn, account_btn_cb, LV_EVENT_CLICKED, NULL);
  update_account_display();
  update_account_button_visibility();

  // Bottom row: prev / next / scan — actions specific to the address list.
  lv_obj_t *nav_row = lv_obj_create(addresses_screen);
  lv_obj_set_size(nav_row, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(nav_row);
  lv_obj_set_flex_flow(nav_row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(nav_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  prev_button = create_nav_button(nav_row, "<", LV_PCT(30), prev_button_cb);
  next_button = create_nav_button(nav_row, ">", LV_PCT(30), next_button_cb);
  lv_obj_add_state(prev_button, LV_STATE_DISABLED);

  scan_button = lv_btn_create(nav_row);
  lv_obj_set_size(scan_button, LV_PCT(30), LV_SIZE_CONTENT);
  theme_apply_touch_button(scan_button, false);
  lv_obj_t *scan_label = lv_label_create(scan_button);
  lv_label_set_text(scan_label, ICON_QRCODE_36);
  lv_obj_set_style_text_font(scan_label, theme_font_medium(), 0);
  lv_obj_center(scan_label);
  lv_obj_add_event_cb(scan_button, scan_button_cb, LV_EVENT_CLICKED, NULL);

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
  if (account_overlay) {
    lv_obj_del(account_overlay);
    account_overlay = NULL;
    account_numpad = NULL;
    account_input_label = NULL;
  }

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
  source_dropdown = NULL;
  prev_button = NULL;
  next_button = NULL;
  scan_button = NULL;
  address_list_container = NULL;
  account_btn = NULL;
  account_value_label = NULL;
  account_numpad = NULL;
  account_input_label = NULL;
  account_input_len = 0;
  return_callback = NULL;
  show_change = false;
  address_offset = 0;
  stored_count = 0;
  address_checker_destroy();
}
