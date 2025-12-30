// Addresses Page - Displays receive and change addresses

#include "addresses.h"
#include "../../ui_components/theme.h"
#include "../../ui_components/ui_input_helpers.h"
#include "../../ui_components/ui_key_info.h"
#include "../../wallet/wallet.h"
#include "wallet_settings.h"
#include <lvgl.h>
#include <wally_core.h>

#define NUM_ADDRESSES 10

static lv_obj_t *addresses_screen = NULL;
static lv_obj_t *type_button = NULL;
static lv_obj_t *prev_button = NULL;
static lv_obj_t *next_button = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *settings_button = NULL;
static lv_obj_t *address_list_container = NULL;
static void (*return_callback)(void) = NULL;

static bool show_change = false;
static uint32_t address_offset = 0;

static void refresh_address_list(void);

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

static void refresh_address_list(void) {
  if (!address_list_container)
    return;

  lv_obj_clean(address_list_container);

  if (address_offset == 0)
    lv_obj_add_state(prev_button, LV_STATE_DISABLED);
  else
    lv_obj_clear_state(prev_button, LV_STATE_DISABLED);

  char all_addresses[2048] = "";
  size_t offset = 0;

  for (uint32_t i = 0; i < NUM_ADDRESSES; i++) {
    uint32_t idx = address_offset + i;
    char *address = NULL;

    bool success = show_change ? wallet_get_change_address(idx, &address)
                               : wallet_get_receive_address(idx, &address);

    if (!success || !address)
      continue;

    int written =
        snprintf(all_addresses + offset, sizeof(all_addresses) - offset,
                 "%s%u: %s", (i > 0) ? "\n\n" : "", idx, address);
    if (written > 0)
      offset += written;

    wally_free_string(address);
  }

  lv_obj_t *label =
      theme_create_label(address_list_container, all_addresses, false);
  lv_obj_set_width(label, LV_PCT(100));
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
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

  // Button container
  lv_obj_t *btn_cont = lv_obj_create(addresses_screen);
  lv_obj_set_size(btn_cont, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(btn_cont);
  lv_obj_set_flex_flow(btn_cont, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(btn_cont, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  type_button =
      create_nav_button(btn_cont, "Receive", LV_PCT(60), type_button_cb);
  prev_button = create_nav_button(btn_cont, "<", LV_PCT(15), prev_button_cb);
  next_button = create_nav_button(btn_cont, ">", LV_PCT(15), next_button_cb);
  lv_obj_add_state(prev_button, LV_STATE_DISABLED);

  // Address list container
  address_list_container = lv_obj_create(addresses_screen);
  lv_obj_set_size(address_list_container, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(address_list_container);
  lv_obj_set_flex_flow(address_list_container, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(address_list_container, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER);

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
  address_list_container = NULL;
  return_callback = NULL;
  show_change = false;
  address_offset = 0;
}
