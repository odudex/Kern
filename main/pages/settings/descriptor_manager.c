// Descriptor Manager — menu-based hub for load/save/export/delete

#include "descriptor_manager.h"
#include "../../core/storage.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../qr/scanner.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/menu.h"
#include "../../ui/theme.h"
#include "../load_descriptor_storage.h"
#include "../shared/descriptor_loader.h"
#include "../store_descriptor.h"
#include <bbqr.h>
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>
#include <types/output.h>
#include <ur_encoder.h>

#define MAX_QR_CHARS_PER_FRAME 400
#define ANIMATION_INTERVAL_MS 250
#define UR_MAX_FRAGMENT_LEN ((MAX_QR_CHARS_PER_FRAME - 30) / 2)

typedef enum {
  FORMAT_PLAINTEXT_DESC,
  FORMAT_BBQR_DESC,
  FORMAT_UR_DESC,
} descriptor_qr_format_t;

/* Main screen and menu */
static lv_obj_t *manager_screen = NULL;
static ui_menu_t *main_menu = NULL;
static void (*return_callback)(void) = NULL;

/* QR export child view */
static lv_obj_t *qr_export_screen = NULL;
static lv_obj_t *qr_export_back_btn = NULL;
static lv_obj_t *qr_type_dropdown = NULL;
static lv_obj_t *qr_code = NULL;
static lv_obj_t *qr_container = NULL;

static char *descriptor_string = NULL;
static descriptor_qr_format_t current_format = FORMAT_PLAINTEXT_DESC;

/* QR animation state */
static BBQrParts *bbqr_parts = NULL;
static char **ur_parts = NULL;
static int ur_parts_count = 0;
static lv_timer_t *animation_timer = NULL;
static int current_part_index = 0;

/* Save type selection menu */
static ui_menu_t *save_type_menu = NULL;
static storage_location_t pending_save_location;

/* Menu entry indices (set during build) */
static int idx_load = -1;
static int idx_save_flash = -1;
static int idx_save_sd = -1;
static int idx_export_qr = -1;

/* Forward declarations */
static void build_main_menu(void);
static void refresh_menu_visibility(void);

/* ---------- QR state cleanup ---------- */

static void cleanup_ur(void) {
  for (int i = 0; i < ur_parts_count; i++)
    free(ur_parts[i]);
  free(ur_parts);
  ur_parts = NULL;
  ur_parts_count = 0;
}

static void cleanup_qr_state(void) {
  if (animation_timer) {
    lv_timer_del(animation_timer);
    animation_timer = NULL;
  }
  if (bbqr_parts) {
    bbqr_parts_free(bbqr_parts);
    bbqr_parts = NULL;
  }
  cleanup_ur();
  current_part_index = 0;
}

/* ---------- QR export view ---------- */

static void animation_timer_cb(lv_timer_t *timer) {
  (void)timer;
  if (!qr_code)
    return;

  if (bbqr_parts && bbqr_parts->count > 1) {
    current_part_index = (current_part_index + 1) % bbqr_parts->count;
    qr_update_optimal(qr_code, bbqr_parts->parts[current_part_index], NULL);
  } else if (ur_parts && ur_parts_count > 1) {
    current_part_index = (current_part_index + 1) % ur_parts_count;
    qr_update_optimal(qr_code, ur_parts[current_part_index], NULL);
  }
}

static void update_qr_display(void) {
  if (!qr_code || !descriptor_string)
    return;

  cleanup_qr_state();

  if (current_format == FORMAT_PLAINTEXT_DESC) {
    qr_update_optimal(qr_code, descriptor_string, NULL);
    return;
  }

  if (current_format == FORMAT_BBQR_DESC) {
    bbqr_parts = bbqr_encode((const uint8_t *)descriptor_string,
                             strlen(descriptor_string), BBQR_TYPE_UNICODE,
                             MAX_QR_CHARS_PER_FRAME);
    if (!bbqr_parts)
      return;

    qr_update_optimal(qr_code, bbqr_parts->parts[0], NULL);

    if (bbqr_parts->count > 1) {
      animation_timer =
          lv_timer_create(animation_timer_cb, ANIMATION_INTERVAL_MS, NULL);
    }
    return;
  }

  output_data_t *output = output_from_descriptor_string(descriptor_string);
  if (!output)
    return;

  size_t cbor_len = 0;
  uint8_t *cbor_data = output_to_cbor(output, &cbor_len);
  output_free(output);
  if (!cbor_data)
    return;

  ur_encoder_t *encoder = ur_encoder_new("crypto-output", cbor_data, cbor_len,
                                         UR_MAX_FRAGMENT_LEN, 0, 10);
  free(cbor_data);
  if (!encoder)
    return;

  size_t seq_len = ur_encoder_seq_len(encoder);
  size_t parts_count = ur_encoder_is_single_part(encoder)
                           ? 1
                           : (seq_len * 2 > 100 ? 100 : seq_len * 2);

  ur_parts = malloc(parts_count * sizeof(char *));
  if (!ur_parts) {
    ur_encoder_free(encoder);
    return;
  }

  for (size_t i = 0; i < parts_count; i++) {
    if (!ur_encoder_next_part(encoder, &ur_parts[i])) {
      for (size_t j = 0; j < i; j++)
        free(ur_parts[j]);
      free(ur_parts);
      ur_parts = NULL;
      ur_encoder_free(encoder);
      return;
    }
  }
  ur_parts_count = (int)parts_count;
  ur_encoder_free(encoder);

  qr_update_optimal(qr_code, ur_parts[0], NULL);

  if (ur_parts_count > 1) {
    animation_timer =
        lv_timer_create(animation_timer_cb, ANIMATION_INTERVAL_MS, NULL);
  }
}

static void dropdown_cb(lv_event_t *e) {
  uint32_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  descriptor_qr_format_t new_format = (descriptor_qr_format_t)sel;
  if (new_format != current_format) {
    current_format = new_format;
    update_qr_display();
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

static void qr_export_back_cb(lv_event_t *e) {
  (void)e;
  cleanup_qr_state();

  if (qr_export_back_btn) {
    lv_obj_del(qr_export_back_btn);
    qr_export_back_btn = NULL;
  }
  if (qr_export_screen) {
    lv_obj_del(qr_export_screen);
    qr_export_screen = NULL;
  }
  qr_type_dropdown = NULL;
  qr_code = NULL;
  qr_container = NULL;
  current_format = FORMAT_PLAINTEXT_DESC;

  descriptor_manager_page_show();
}

static void show_qr_export(void) {
  if (!descriptor_string)
    return;

  descriptor_manager_page_hide();

  lv_obj_t *parent = lv_screen_active();

  qr_export_screen = lv_obj_create(parent);
  lv_obj_set_size(qr_export_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(qr_export_screen);
  lv_obj_clear_flag(qr_export_screen, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(qr_export_screen, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(qr_export_screen, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(qr_export_screen, theme_get_default_padding(), 0);
  lv_obj_set_style_pad_gap(qr_export_screen, theme_get_default_padding(), 0);

  /* Top bar with format dropdown */
  lv_obj_t *top_bar = lv_obj_create(qr_export_screen);
  lv_obj_set_size(top_bar, LV_PCT(100), 60);
  lv_obj_set_style_bg_opa(top_bar, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(top_bar, 0, 0);
  lv_obj_set_style_pad_all(top_bar, 0, 0);
  lv_obj_clear_flag(top_bar, LV_OBJ_FLAG_SCROLLABLE);

  qr_type_dropdown = lv_dropdown_create(top_bar);
  lv_dropdown_set_options(qr_type_dropdown, "Plaintext\nBBQr\nUR");
  lv_obj_set_width(qr_type_dropdown, LV_PCT(40));
  lv_obj_align(qr_type_dropdown, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_style_bg_color(qr_type_dropdown, disabled_color(), 0);
  lv_obj_set_style_text_color(qr_type_dropdown, main_color(), 0);
  lv_obj_set_style_text_font(qr_type_dropdown, theme_font_small(), 0);
  lv_obj_set_style_border_color(qr_type_dropdown, highlight_color(), 0);
  lv_obj_add_event_cb(qr_type_dropdown, dropdown_open_cb, LV_EVENT_READY, NULL);
  lv_obj_add_event_cb(qr_type_dropdown, dropdown_cb, LV_EVENT_VALUE_CHANGED,
                      NULL);

  /* QR content area */
  lv_obj_t *content_area = lv_obj_create(qr_export_screen);
  lv_obj_set_size(content_area, LV_PCT(100), LV_SIZE_CONTENT);
  lv_obj_set_style_bg_opa(content_area, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(content_area, 0, 0);
  lv_obj_set_style_pad_all(content_area, 0, 0);
  lv_obj_set_flex_grow(content_area, 1);
  lv_obj_clear_flag(content_area, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(content_area, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content_area, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  lv_obj_update_layout(content_area);
  int32_t w = lv_obj_get_content_width(content_area);
  int32_t h = lv_obj_get_content_height(content_area);
  int32_t container_size = (w < h ? w : h) * 80 / 100;

  qr_container = lv_obj_create(content_area);
  lv_obj_set_size(qr_container, container_size, container_size);
  lv_obj_set_style_bg_color(qr_container, lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_bg_opa(qr_container, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(qr_container, 0, 0);
  lv_obj_set_style_pad_all(qr_container, 10, 0);
  lv_obj_set_style_radius(qr_container, 0, 0);
  lv_obj_clear_flag(qr_container, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_update_layout(qr_container);
  int32_t qr_widget_size = lv_obj_get_content_width(qr_container);

  qr_code = lv_qrcode_create(qr_container);
  lv_qrcode_set_size(qr_code, qr_widget_size);
  lv_obj_center(qr_code);

  current_format = FORMAT_PLAINTEXT_DESC;
  update_qr_display();

  qr_export_back_btn = ui_create_back_button(parent, qr_export_back_cb);
}

/* ---------- Load descriptor callbacks ---------- */

static void descriptor_validation_cb(descriptor_validation_result_t result,
                                     void *user_data) {
  (void)user_data;

  if (result == VALIDATION_SUCCESS) {
    if (descriptor_string) {
      free(descriptor_string);
      descriptor_string = NULL;
    }
    wallet_get_descriptor_string(&descriptor_string);
    refresh_menu_visibility();
    return;
  }

  descriptor_loader_show_error(result);
}

static void return_from_scanner_cb(void) {
  descriptor_loader_process_scanner(descriptor_validation_cb, NULL, NULL);
  descriptor_manager_page_show();
}

static void load_from_qr_cb(void) {
  descriptor_loader_destroy_source_menu();
  descriptor_manager_page_hide();
  qr_scanner_page_create(NULL, return_from_scanner_cb);
  qr_scanner_page_show();
}

static void return_from_load_storage(void) {
  load_descriptor_storage_page_destroy();
  descriptor_manager_page_show();
}

static void success_from_load_storage(void) {
  load_descriptor_storage_page_destroy();
  if (descriptor_string) {
    free(descriptor_string);
    descriptor_string = NULL;
  }
  wallet_get_descriptor_string(&descriptor_string);
  descriptor_manager_page_show();
  refresh_menu_visibility();
}

static void load_from_flash_cb(void) {
  descriptor_loader_destroy_source_menu();
  descriptor_manager_page_hide();
  load_descriptor_storage_page_create(lv_screen_active(),
                                      return_from_load_storage,
                                      success_from_load_storage, STORAGE_FLASH);
  load_descriptor_storage_page_show();
}

static void load_from_sd_cb(void) {
  descriptor_loader_destroy_source_menu();
  descriptor_manager_page_hide();
  load_descriptor_storage_page_create(lv_screen_active(),
                                      return_from_load_storage,
                                      success_from_load_storage, STORAGE_SD);
  load_descriptor_storage_page_show();
}

static void load_source_back_cb(void) {
  descriptor_loader_destroy_source_menu();
}

static void load_descriptor_cb(void) {
  descriptor_loader_show_source_menu(manager_screen, load_from_qr_cb,
                                     load_from_flash_cb, load_from_sd_cb,
                                     load_source_back_cb);
}

/* ---------- Save callbacks ---------- */

static void return_from_store_descriptor(void) {
  store_descriptor_page_destroy();
  descriptor_manager_page_show();
}

static void save_encrypted_cb(void) {
  if (save_type_menu) {
    ui_menu_destroy(save_type_menu);
    save_type_menu = NULL;
  }
  descriptor_manager_page_hide();
  store_descriptor_page_create(lv_screen_active(), return_from_store_descriptor,
                               pending_save_location, true);
  store_descriptor_page_show();
}

static void save_plaintext_cb(void) {
  if (save_type_menu) {
    ui_menu_destroy(save_type_menu);
    save_type_menu = NULL;
  }
  descriptor_manager_page_hide();
  store_descriptor_page_create(lv_screen_active(), return_from_store_descriptor,
                               pending_save_location, false);
  store_descriptor_page_show();
}

static void save_type_back_cb(void) {
  if (save_type_menu) {
    ui_menu_destroy(save_type_menu);
    save_type_menu = NULL;
  }
}

static void show_save_type_menu(storage_location_t loc) {
  pending_save_location = loc;
  const char *title =
      (loc == STORAGE_FLASH) ? "Save to Flash" : "Save to SD Card";

  save_type_menu = ui_menu_create(manager_screen, title, save_type_back_cb);
  if (!save_type_menu)
    return;

  ui_menu_add_entry(save_type_menu, "Encrypted (KEF)", save_encrypted_cb);
  ui_menu_add_entry(save_type_menu, "Plaintext", save_plaintext_cb);
  ui_menu_show(save_type_menu);
}

static void save_to_flash_cb(void) { show_save_type_menu(STORAGE_FLASH); }

static void save_to_sd_cb(void) { show_save_type_menu(STORAGE_SD); }

/* ---------- Export QR callback ---------- */

static void export_qr_cb(void) { show_qr_export(); }

/* ---------- Main menu ---------- */

static void main_menu_back_cb(void) {
  if (return_callback)
    return_callback();
}

static void build_main_menu(void) {
  if (main_menu) {
    ui_menu_destroy(main_menu);
    main_menu = NULL;
  }

  main_menu =
      ui_menu_create(manager_screen, "Descriptor Manager", main_menu_back_cb);
  if (!main_menu)
    return;

  bool has_desc = wallet_has_descriptor();

  ui_menu_add_entry(main_menu,
                    has_desc ? "Load Other Descriptor" : "Load Descriptor",
                    load_descriptor_cb);
  idx_load = 0;

  ui_menu_add_entry(main_menu, "Save to Flash", save_to_flash_cb);
  idx_save_flash = 1;

  ui_menu_add_entry(main_menu, "Save to SD Card", save_to_sd_cb);
  idx_save_sd = 2;

  ui_menu_add_entry(main_menu, "Export QR Code", export_qr_cb);
  idx_export_qr = 3;

  /* Hide save/export entries when no descriptor is loaded */
  if (!has_desc) {
    ui_menu_set_entry_enabled(main_menu, idx_save_flash, false);
    ui_menu_set_entry_enabled(main_menu, idx_save_sd, false);
    ui_menu_set_entry_enabled(main_menu, idx_export_qr, false);
  }

  ui_menu_show(main_menu);
}

static void refresh_menu_visibility(void) {
  bool has_desc = wallet_has_descriptor();

  if (main_menu) {
    /* Update Load entry label */
    if (idx_load >= 0 && main_menu->buttons[idx_load]) {
      lv_obj_t *label = lv_obj_get_child(main_menu->buttons[idx_load], 0);
      if (label)
        lv_label_set_text(label, has_desc ? "Load Other Descriptor"
                                          : "Load Descriptor");
    }

    /* Toggle save/export visibility */
    ui_menu_set_entry_enabled(main_menu, idx_save_flash, has_desc);
    ui_menu_set_entry_enabled(main_menu, idx_save_sd, has_desc);
    ui_menu_set_entry_enabled(main_menu, idx_export_qr, has_desc);
  }
}

/* ---------- Page lifecycle ---------- */

void descriptor_manager_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;
  current_format = FORMAT_PLAINTEXT_DESC;

  if (wallet_has_descriptor())
    wallet_get_descriptor_string(&descriptor_string);

  manager_screen = theme_create_page_container(parent);

  build_main_menu();
}

void descriptor_manager_page_show(void) {
  if (manager_screen)
    lv_obj_clear_flag(manager_screen, LV_OBJ_FLAG_HIDDEN);
  if (main_menu)
    ui_menu_show(main_menu);
}

void descriptor_manager_page_hide(void) {
  if (manager_screen)
    lv_obj_add_flag(manager_screen, LV_OBJ_FLAG_HIDDEN);
  if (main_menu)
    ui_menu_hide(main_menu);
}

void descriptor_manager_page_destroy(void) {
  cleanup_qr_state();
  descriptor_loader_destroy_source_menu();

  if (save_type_menu) {
    ui_menu_destroy(save_type_menu);
    save_type_menu = NULL;
  }

  if (descriptor_string) {
    free(descriptor_string);
    descriptor_string = NULL;
  }

  if (qr_export_back_btn) {
    lv_obj_del(qr_export_back_btn);
    qr_export_back_btn = NULL;
  }
  if (qr_export_screen) {
    lv_obj_del(qr_export_screen);
    qr_export_screen = NULL;
  }
  qr_type_dropdown = NULL;
  qr_code = NULL;
  qr_container = NULL;

  if (main_menu) {
    ui_menu_destroy(main_menu);
    main_menu = NULL;
  }

  if (manager_screen) {
    lv_obj_del(manager_screen);
    manager_screen = NULL;
  }

  idx_load = -1;
  idx_save_flash = -1;
  idx_save_sd = -1;
  idx_export_qr = -1;
  return_callback = NULL;
  current_format = FORMAT_PLAINTEXT_DESC;
}
