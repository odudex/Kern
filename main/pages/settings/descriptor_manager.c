#include "descriptor_manager.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../qr/scanner.h"
#include "../../ui/input_helpers.h"
#include "../../ui/theme.h"
#include "../descriptor_loader.h"
#include <bbqr.h>
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>
#include <types/output.h>
#include <ur_encoder.h>
#include <wally_core.h>

#define MAX_QR_CHARS_PER_FRAME 400
#define ANIMATION_INTERVAL_MS 250

#define UR_MAX_FRAGMENT_LEN ((MAX_QR_CHARS_PER_FRAME - 30) / 2)

typedef enum {
  FORMAT_PLAINTEXT,
  FORMAT_BBQR_DESC,
  FORMAT_UR_DESC,
} descriptor_qr_format_t;

static lv_obj_t *descriptor_screen = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *qr_type_dropdown = NULL;
static lv_obj_t *qr_code = NULL;
static lv_obj_t *qr_container = NULL;
static lv_obj_t *content_area = NULL;
static lv_obj_t *load_btn = NULL;
static lv_obj_t *no_descriptor_label = NULL;
static void (*return_callback)(void) = NULL;

static char *descriptor_string = NULL;
static descriptor_qr_format_t current_format = FORMAT_PLAINTEXT;

static BBQrParts *bbqr_parts = NULL;
static char **ur_parts = NULL;
static int ur_parts_count = 0;
static lv_timer_t *animation_timer = NULL;
static int current_part_index = 0;

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

  if (current_format == FORMAT_PLAINTEXT) {
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
      for (size_t j = 0; j < i; j++) {
        free(ur_parts[j]);
      }
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

static void show_qr_elements(void) {
  if (qr_container)
    lv_obj_clear_flag(qr_container, LV_OBJ_FLAG_HIDDEN);
  if (qr_type_dropdown)
    lv_obj_clear_flag(qr_type_dropdown, LV_OBJ_FLAG_HIDDEN);
  if (no_descriptor_label)
    lv_obj_add_flag(no_descriptor_label, LV_OBJ_FLAG_HIDDEN);
}

static void hide_qr_elements(void) {
  if (qr_container)
    lv_obj_add_flag(qr_container, LV_OBJ_FLAG_HIDDEN);
  if (qr_type_dropdown)
    lv_obj_add_flag(qr_type_dropdown, LV_OBJ_FLAG_HIDDEN);
  if (no_descriptor_label)
    lv_obj_clear_flag(no_descriptor_label, LV_OBJ_FLAG_HIDDEN);
}

static void descriptor_validation_cb(descriptor_validation_result_t result,
                                     void *user_data) {
  (void)user_data;

  if (result == VALIDATION_SUCCESS) {
    if (descriptor_string) {
      wally_free_string(descriptor_string);
      descriptor_string = NULL;
    }
    if (wallet_get_descriptor_string(&descriptor_string)) {
      show_qr_elements();
      update_qr_display();
    }
    if (load_btn) {
      lv_obj_t *label = lv_obj_get_child(load_btn, 0);
      if (label)
        lv_label_set_text(label, "Load Other Descriptor");
    }
    return;
  }

  descriptor_loader_show_error(result);
}

static void return_from_scanner_cb(void) {
  descriptor_loader_process_scanner(descriptor_validation_cb, NULL, NULL);
  descriptor_manager_page_show();
}

static void load_descriptor_btn_cb(lv_event_t *e) {
  (void)e;
  descriptor_manager_page_hide();
  qr_scanner_page_create(NULL, return_from_scanner_cb);
  qr_scanner_page_show();
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

void descriptor_manager_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;
  current_format = FORMAT_PLAINTEXT;

  if (wallet_has_descriptor()) {
    wallet_get_descriptor_string(&descriptor_string);
  }

  bool has_descriptor = (descriptor_string != NULL);

  descriptor_screen = lv_obj_create(parent);
  lv_obj_set_size(descriptor_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(descriptor_screen);
  lv_obj_clear_flag(descriptor_screen, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(descriptor_screen, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(descriptor_screen, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(descriptor_screen, theme_get_default_padding(), 0);
  lv_obj_set_style_pad_gap(descriptor_screen, theme_get_default_padding(), 0);

  lv_obj_t *top_bar = lv_obj_create(descriptor_screen);
  lv_obj_set_size(top_bar, LV_PCT(100), 60);
  lv_obj_set_style_bg_opa(top_bar, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(top_bar, 0, 0);
  lv_obj_set_style_pad_all(top_bar, 0, 0);
  lv_obj_clear_flag(top_bar, LV_OBJ_FLAG_SCROLLABLE);

  back_button = ui_create_back_button(parent, back_btn_cb);

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

  content_area = lv_obj_create(descriptor_screen);
  lv_obj_set_size(content_area, LV_PCT(100), LV_SIZE_CONTENT);
  lv_obj_set_style_bg_opa(content_area, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(content_area, 0, 0);
  lv_obj_set_style_pad_all(content_area, 0, 0);
  lv_obj_set_flex_grow(content_area, 1);
  lv_obj_clear_flag(content_area, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(content_area, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content_area, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  no_descriptor_label = theme_create_label(
      content_area,
      "No descriptor loaded.\n\nScan a wallet descriptor\nto "
      "view it here.",
      false);
  lv_obj_set_style_text_align(no_descriptor_label, LV_TEXT_ALIGN_CENTER, 0);

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

  load_btn = lv_btn_create(descriptor_screen);
  lv_obj_set_size(load_btn, LV_PCT(80), 50);
  theme_apply_touch_button(load_btn, false);
  lv_obj_add_event_cb(load_btn, load_descriptor_btn_cb, LV_EVENT_CLICKED, NULL);

  lv_obj_t *load_label = lv_label_create(load_btn);
  lv_label_set_text(load_label, has_descriptor ? "Load Other Descriptor"
                                               : "Load Descriptor");
  lv_obj_set_style_text_font(load_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(load_label, main_color(), 0);
  lv_obj_center(load_label);

  if (has_descriptor) {
    show_qr_elements();
    update_qr_display();
  } else {
    hide_qr_elements();
  }
}

void descriptor_manager_page_show(void) {
  if (descriptor_screen)
    lv_obj_clear_flag(descriptor_screen, LV_OBJ_FLAG_HIDDEN);
}

void descriptor_manager_page_hide(void) {
  if (descriptor_screen)
    lv_obj_add_flag(descriptor_screen, LV_OBJ_FLAG_HIDDEN);
}

void descriptor_manager_page_destroy(void) {
  cleanup_qr_state();

  if (descriptor_string) {
    wally_free_string(descriptor_string);
    descriptor_string = NULL;
  }

  if (back_button) {
    lv_obj_del(back_button);
    back_button = NULL;
  }

  if (descriptor_screen) {
    lv_obj_del(descriptor_screen);
    descriptor_screen = NULL;
  }

  qr_type_dropdown = NULL;
  qr_code = NULL;
  qr_container = NULL;
  content_area = NULL;
  load_btn = NULL;
  no_descriptor_label = NULL;
  return_callback = NULL;
  current_format = FORMAT_PLAINTEXT;
}
