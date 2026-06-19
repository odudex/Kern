// Session Descriptors sub-page — list, view, and remove registry entries

#include "registered_descriptors.h"
#include "../../core/descriptor_checksum.h"
#include "../../core/key.h"
#include "../../core/miniscript_policy.h"
#include "../../core/registry.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "../shared/descriptor_loader.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_descriptor.h>

static lv_obj_t *rd_screen = NULL;
static ui_menu_t *rd_menu = NULL;
static ui_menu_t *action_menu = NULL;
static lv_obj_t *detail_screen = NULL;
static void (*return_callback)(void) = NULL;
static registered_descriptor_action_cb_t action_callback = NULL;
static int pending_remove_index = -1;
static int selected_descriptor_index = -1;

static void build_rd_menu(void);

static void disabled_entry_cb(void) {}

// Letters ('A' + key index) of descriptor keys whose origin fingerprint
// matches the loaded wallet key. out must hold MINISCRIPT_POLICY_MAX_KEYS + 1
// bytes.
static void our_key_letters(const struct wally_descriptor *desc, char *out) {
  size_t n = 0;
  unsigned char my_fp[BIP32_KEY_FINGERPRINT_LEN];
  uint32_t num_keys = 0;
  if (key_get_fingerprint(my_fp) &&
      wally_descriptor_get_num_keys(desc, &num_keys) == WALLY_OK) {
    if (num_keys > MINISCRIPT_POLICY_MAX_KEYS)
      num_keys = MINISCRIPT_POLICY_MAX_KEYS;
    for (uint32_t i = 0; i < num_keys; i++) {
      unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
      if (wally_descriptor_get_key_origin_fingerprint(desc, i, fp,
                                                      sizeof(fp)) == WALLY_OK &&
          memcmp(fp, my_fp, sizeof(fp)) == 0)
        out[n++] = (char)('A' + i);
    }
  }
  out[n] = '\0';
}

static void detail_back_cb(lv_event_t *e) {
  (void)e;
  if (detail_screen) {
    lv_obj_del(detail_screen);
    detail_screen = NULL;
  }
  if (action_menu)
    ui_menu_show(action_menu);
}

static void view_descriptor_cb(void) {
  int idx = selected_descriptor_index;
  if (idx < 0)
    return;
  const registry_entry_t *entry = registry_get((size_t)idx);
  if (!entry)
    return;
  char *desc_str = NULL;
  if (!descriptor_string_from_descriptor(entry->desc, &desc_str))
    return;

  if (action_menu)
    ui_menu_hide(action_menu);
  if (detail_screen) {
    lv_obj_del(detail_screen);
    detail_screen = NULL;
  }

  detail_screen = theme_create_page_container(rd_screen);
  if (!detail_screen) {
    free(desc_str);
    return;
  }

  ui_create_back_button(detail_screen, detail_back_cb);

  const char *title = entry->label[0] ? entry->label : entry->id;
  lv_obj_t *title_label = theme_create_label(detail_screen, title, false);
  lv_obj_set_width(title_label, LV_PCT(72));
  lv_label_set_long_mode(title_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(title_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(title_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(title_label, highlight_color(), 0);
  lv_obj_align(title_label, LV_ALIGN_TOP_MID, 0, theme_default_padding());

  int32_t top_h = theme_corner_button_height() + theme_default_padding();
  lv_obj_t *body = theme_create_page_container(detail_screen);
  lv_obj_set_size(body, LV_PCT(100), theme_screen_height() - top_h);
  lv_obj_align(body, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_style_pad_all(body, theme_default_padding(), 0);
  lv_obj_set_style_pad_gap(body, theme_small_padding(), 0);
  lv_obj_set_flex_flow(body, LV_FLEX_FLOW_COLUMN);
  lv_obj_add_flag(body, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_scrollbar_mode(body, LV_SCROLLBAR_MODE_AUTO);

  // Miniscript: indented policy view above the raw descriptor
  if (miniscript_policy_is_miniscript(entry->desc)) {
    char *policy = miniscript_policy_string(entry->desc);
    if (policy) {
      char ours[MINISCRIPT_POLICY_MAX_KEYS + 1];
      our_key_letters(entry->desc, ours);
      descriptor_policy_view_create(body, policy, ours);
      free(policy);
    }
  }

  lv_obj_t *desc_label = theme_create_label(body, desc_str, false);
  lv_obj_set_width(desc_label, LV_PCT(100));
  lv_label_set_long_mode(desc_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(desc_label, LV_TEXT_ALIGN_LEFT, 0);
  lv_obj_set_style_text_color(desc_label, primary_color(), 0);

  free(desc_str);
}

static void action_menu_back_cb(void) {
  if (detail_screen) {
    lv_obj_del(detail_screen);
    detail_screen = NULL;
  }
  if (action_menu) {
    ui_menu_destroy(action_menu);
    action_menu = NULL;
  }
  if (rd_menu)
    ui_menu_show(rd_menu);
}

static void emit_action(registered_descriptor_action_t action) {
  if (selected_descriptor_index < 0 || !action_callback)
    return;
  action_callback((size_t)selected_descriptor_index, action);
}

static void export_qr_cb(void) {
  emit_action(REGISTERED_DESCRIPTOR_ACTION_EXPORT_QR);
}

static void save_flash_cb(void) {
  emit_action(REGISTERED_DESCRIPTOR_ACTION_SAVE_FLASH);
}

static void save_sd_cb(void) {
  emit_action(REGISTERED_DESCRIPTOR_ACTION_SAVE_SD);
}

static void remove_confirmed_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed || pending_remove_index < 0)
    return;
  const registry_entry_t *entry = registry_get((size_t)pending_remove_index);
  if (entry)
    registry_remove(entry->id);
  pending_remove_index = -1;
  selected_descriptor_index = -1;
  if (action_menu) {
    ui_menu_destroy(action_menu);
    action_menu = NULL;
  }
  if (detail_screen) {
    lv_obj_del(detail_screen);
    detail_screen = NULL;
  }
  build_rd_menu();
}

static void remove_action_cb(void) {
  pending_remove_index = selected_descriptor_index;
  dialog_show_danger_confirm("Remove this session descriptor?",
                             remove_confirmed_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static void show_action_menu(void) {
  int idx = ui_menu_get_selected(rd_menu);
  if (idx < 0)
    return;

  const registry_entry_t *entry = registry_get((size_t)idx);
  if (!entry)
    return;

  selected_descriptor_index = idx;
  ui_menu_hide(rd_menu);
  if (action_menu) {
    ui_menu_destroy(action_menu);
    action_menu = NULL;
  }

  action_menu =
      ui_menu_create(rd_screen, entry->label[0] ? entry->label : entry->id,
                     action_menu_back_cb);
  if (!action_menu)
    return;

  ui_menu_add_entry(action_menu, "View Descriptor", view_descriptor_cb);
  ui_menu_add_entry(action_menu, "Export QR Code", export_qr_cb);
  ui_menu_add_entry(action_menu, "Save to Flash", save_flash_cb);
  ui_menu_add_entry(action_menu, "Save to SD Card", save_sd_cb);
  ui_menu_add_entry(action_menu, "Remove from Session", remove_action_cb);
  ui_menu_show(action_menu);
}

static void rd_back_cb(void) {
  if (return_callback)
    return_callback();
}

static void build_rd_menu(void) {
  if (detail_screen) {
    lv_obj_del(detail_screen);
    detail_screen = NULL;
  }
  if (action_menu) {
    ui_menu_destroy(action_menu);
    action_menu = NULL;
  }
  if (rd_menu) {
    ui_menu_destroy(rd_menu);
    rd_menu = NULL;
  }
  rd_menu = ui_menu_create(rd_screen, "Session Descriptors", rd_back_cb);
  if (!rd_menu)
    return;

  size_t count = registry_count();
  if (count == 0) {
    ui_menu_add_entry(rd_menu, "(no session descriptors)", disabled_entry_cb);
    ui_menu_set_entry_enabled(rd_menu, 0, false);
  } else {
    for (size_t i = 0; i < count; i++) {
      const registry_entry_t *entry = registry_get(i);
      if (!entry)
        continue;
      ui_menu_add_entry(rd_menu, entry->label[0] ? entry->label : entry->id,
                        show_action_menu);
    }
  }
  ui_menu_show(rd_menu);
}

void registered_descriptors_page_create(
    lv_obj_t *parent, void (*return_cb)(void),
    registered_descriptor_action_cb_t action_cb) {
  if (!parent)
    return;
  return_callback = return_cb;
  action_callback = action_cb;
  rd_screen = theme_create_page_container(parent);
  build_rd_menu();
}

void registered_descriptors_page_show(void) {
  if (rd_screen)
    lv_obj_clear_flag(rd_screen, LV_OBJ_FLAG_HIDDEN);
  if (detail_screen)
    lv_obj_clear_flag(detail_screen, LV_OBJ_FLAG_HIDDEN);
  else if (action_menu)
    ui_menu_show(action_menu);
  else if (rd_menu)
    ui_menu_show(rd_menu);
}

void registered_descriptors_page_hide(void) {
  if (rd_screen)
    lv_obj_add_flag(rd_screen, LV_OBJ_FLAG_HIDDEN);
  if (detail_screen)
    lv_obj_add_flag(detail_screen, LV_OBJ_FLAG_HIDDEN);
  if (action_menu)
    ui_menu_hide(action_menu);
  if (rd_menu)
    ui_menu_hide(rd_menu);
}

void registered_descriptors_page_destroy(void) {
  if (detail_screen) {
    lv_obj_del(detail_screen);
    detail_screen = NULL;
  }
  if (action_menu) {
    ui_menu_destroy(action_menu);
    action_menu = NULL;
  }
  if (rd_menu) {
    ui_menu_destroy(rd_menu);
    rd_menu = NULL;
  }
  if (rd_screen) {
    lv_obj_del(rd_screen);
    rd_screen = NULL;
  }
  pending_remove_index = -1;
  selected_descriptor_index = -1;
  return_callback = NULL;
  action_callback = NULL;
}
