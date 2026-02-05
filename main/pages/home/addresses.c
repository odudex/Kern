// Addresses Page - Displays receive and change addresses

#include "addresses.h"
#include "../../core/wallet.h"
#include "../../qr/scanner.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/theme.h"
#include "../descriptor_loader.h"
#include "../settings/wallet_settings.h"
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
static lv_obj_t *load_descriptor_btn = NULL;
static lv_obj_t *btn_cont = NULL;
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

static void descriptor_validation_cb(descriptor_validation_result_t result,
                                     void *user_data) {
  (void)user_data;

  if (result == VALIDATION_SUCCESS) {
    if (load_descriptor_btn)
      lv_obj_add_flag(load_descriptor_btn, LV_OBJ_FLAG_HIDDEN);
    if (btn_cont)
      lv_obj_clear_flag(btn_cont, LV_OBJ_FLAG_HIDDEN);
    refresh_address_list();
    return;
  }

  descriptor_loader_show_error(result);
}

static void return_from_descriptor_scanner_cb(void) {
  descriptor_loader_process_scanner(descriptor_validation_cb, NULL, NULL);
  addresses_page_show();
}

static void load_descriptor_btn_cb(lv_event_t *e) {
  (void)e;
  addresses_page_hide();
  qr_scanner_page_create(NULL, return_from_descriptor_scanner_cb);
  qr_scanner_page_show();
}

static void refresh_address_list(void) {
  if (!address_list_container)
    return;

  lv_obj_clean(address_list_container);

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

  char all_addresses[2048] = "";
  size_t offset = 0;

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
      create_nav_button(btn_cont, "Receive", LV_PCT(60), type_button_cb);
  prev_button = create_nav_button(btn_cont, "<", LV_PCT(15), prev_button_cb);
  next_button = create_nav_button(btn_cont, ">", LV_PCT(15), next_button_cb);
  lv_obj_add_state(prev_button, LV_STATE_DISABLED);

  // Hide navigation buttons if multisig without descriptor
  if (needs_descriptor) {
    lv_obj_add_flag(btn_cont, LV_OBJ_FLAG_HIDDEN);
  }

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
  load_descriptor_btn = NULL;
  btn_cont = NULL;
  address_list_container = NULL;
  return_callback = NULL;
  show_change = false;
  address_offset = 0;
}
