// Mnemonic QR Code Backup Page

#include "mnemonic_qr.h"
#include "../../../core/base43.h"
#include "../../../core/kef.h"
#include "../../../core/key.h"
#include "../../../qr/encoder.h"
#include "../../../ui/dialog.h"
#include "../../../ui/input_helpers.h"
#include "../../../ui/theme.h"
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/idf_additions.h>
#include <freertos/task.h>
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>

#include "../../../utils/secure_mem.h"

#define GRID_INTERVAL_DEFAULT 5
#define GRID_INTERVAL_21 7
#define LEGEND_SIZE 28
#define LABEL_PAD 6
#define SHADE_OPACITY LV_OPA_70

#define KEF_ITERATIONS 100000
#define ENCRYPT_TASK_STACK_SIZE 8192

static int get_grid_interval(int modules) {
  return (modules == 21) ? GRID_INTERVAL_21 : GRID_INTERVAL_DEFAULT;
}

typedef enum {
  QR_TYPE_PLAINTEXT = 0,
  QR_TYPE_SEEDQR = 1,
  QR_TYPE_COMPACT_SEEDQR = 2,
  QR_TYPE_ENCRYPTED = 3
} qr_type_t;

static lv_obj_t *mnemonic_qr_screen = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *qr_type_dropdown = NULL;
static lv_obj_t *grid_btn = NULL;
static lv_obj_t *qr_code = NULL;
static lv_obj_t *qr_container = NULL;
static lv_obj_t *grid_overlay = NULL;
static lv_obj_t *content_area = NULL;
static lv_obj_t *shade_overlay = NULL;
static lv_obj_t **col_labels = NULL;
static lv_obj_t **row_labels = NULL;
static void (*return_callback)(void) = NULL;
static char *mnemonic_data = NULL;
static char *seedqr_data = NULL;
static unsigned char *compact_seedqr_data = NULL;
static size_t compact_seedqr_len = 0;
static qr_type_t current_qr_type = QR_TYPE_PLAINTEXT;
static bool grid_visible = false;
static bool shade_mode_active = false;
static int32_t qr_widget_size = 0;
static int shade_region_index = 0;
static int grid_divisions = 0;
static qr_encode_result_t last_qr_result = {0, 0};

/* Encrypted QR state */
static char *encrypted_qr_data = NULL;
static qr_type_t previous_qr_type = QR_TYPE_PLAINTEXT;
static char encrypt_kef_id[64] = {0};

/* Keyboard overlay for encryption */
static lv_obj_t *encrypt_screen = NULL;
static lv_obj_t *encrypt_textarea = NULL;
static lv_obj_t *encrypt_keyboard = NULL;
static lv_obj_t *encrypt_loading_label = NULL;
static lv_group_t *encrypt_input_group = NULL;

/* Background encryption task */
static TaskHandle_t encrypt_task_handle = NULL;
static lv_timer_t *encrypt_poll_timer = NULL;
static volatile bool encrypt_done = false;
static kef_error_t encrypt_result = KEF_OK;

/* Key material for encryption task */
static uint8_t *encrypt_key_copy = NULL;
static size_t encrypt_key_copy_len = 0;
static uint8_t *encrypt_envelope = NULL;
static size_t encrypt_envelope_len = 0;

/* Forward declaration */
static void update_qr_code(void);

static void back_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

static void destroy_grid_overlay(void) {
  if (grid_overlay) {
    lv_obj_del(grid_overlay);
    grid_overlay = NULL;
  }
  free(col_labels);
  col_labels = NULL;
  free(row_labels);
  row_labels = NULL;
  grid_divisions = 0;
}

static void update_grid_label_highlight(int highlight_row, int highlight_col) {
  if (!col_labels || !row_labels || grid_divisions == 0)
    return;

  lv_color_t normal_color = highlight_color();
  lv_color_t active_color = lv_color_hex(0xFFFFFF);

  for (int i = 0; i < grid_divisions; i++) {
    if (col_labels[i])
      lv_obj_set_style_text_color(
          col_labels[i], (i == highlight_col) ? active_color : normal_color, 0);
    if (row_labels[i])
      lv_obj_set_style_text_color(
          row_labels[i], (i == highlight_row) ? active_color : normal_color, 0);
  }
}

static void destroy_shade_overlay(void) {
  if (shade_overlay) {
    lv_obj_del(shade_overlay);
    shade_overlay = NULL;
  }
}

static void reset_shade_mode(void) {
  update_grid_label_highlight(-1, -1);
  destroy_shade_overlay();
  shade_mode_active = false;
  shade_region_index = 0;
}

static void add_shade_rect(int32_t x, int32_t y, int32_t w, int32_t h) {
  lv_obj_t *rect = lv_obj_create(shade_overlay);
  lv_obj_remove_style_all(rect);
  lv_obj_clear_flag(rect, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_set_pos(rect, x, y);
  lv_obj_set_size(rect, w, h);
  lv_obj_set_style_bg_color(rect, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(rect, SHADE_OPACITY, 0);
}

static void create_shade_overlay(void) {
  destroy_shade_overlay();

  int modules = last_qr_result.modules;
  int32_t scale = last_qr_result.scale;
  if (modules == 0 || scale == 0)
    return;

  int grid_interval = get_grid_interval(modules);
  int divisions = (modules + grid_interval - 1) / grid_interval;
  int row = shade_region_index / divisions;
  int col = shade_region_index % divisions;

  int32_t content_size = modules * scale;
  int32_t margin = (qr_widget_size - content_size) / 2;
  int32_t cell_px = scale * grid_interval;

  lv_obj_update_layout(qr_code);
  lv_area_t qr_coords, container_coords, content_coords;
  lv_obj_get_coords(qr_code, &qr_coords);
  lv_obj_get_coords(qr_container, &container_coords);
  lv_obj_get_coords(content_area, &content_coords);

  int32_t qr_x = qr_coords.x1 - content_coords.x1 + margin;
  int32_t qr_y = qr_coords.y1 - content_coords.y1 + margin;
  int32_t cont_x = container_coords.x1 - content_coords.x1;
  int32_t cont_y = container_coords.y1 - content_coords.y1;
  int32_t cont_size = lv_obj_get_width(qr_container);

  int32_t win_x = qr_x + col * cell_px;
  int32_t win_y = qr_y + row * cell_px;
  int32_t win_w = cell_px;
  int32_t win_h = cell_px;

  if (win_x + win_w > qr_x + content_size)
    win_w = qr_x + content_size - win_x;
  if (win_y + win_h > qr_y + content_size)
    win_h = qr_y + content_size - win_y;

  shade_overlay = lv_obj_create(content_area);
  lv_obj_remove_style_all(shade_overlay);
  lv_obj_set_size(shade_overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_clear_flag(shade_overlay,
                    LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_flag(shade_overlay, LV_OBJ_FLAG_IGNORE_LAYOUT);

  if (grid_overlay)
    lv_obj_move_foreground(grid_overlay);

  if (win_y > cont_y)
    add_shade_rect(cont_x, cont_y, cont_size, win_y - cont_y);

  int32_t bottom_y = win_y + win_h;
  if (bottom_y < cont_y + cont_size)
    add_shade_rect(cont_x, bottom_y, cont_size, cont_y + cont_size - bottom_y);

  if (win_x > cont_x)
    add_shade_rect(cont_x, win_y, win_x - cont_x, win_h);

  int32_t right_x = win_x + win_w;
  if (right_x < cont_x + cont_size)
    add_shade_rect(right_x, win_y, cont_x + cont_size - right_x, win_h);

  shade_mode_active = true;
  update_grid_label_highlight(row, col);
}

static void qr_area_tap_cb(lv_event_t *e) {
  (void)e;
  if (!grid_visible)
    return;

  int modules = last_qr_result.modules;
  int grid_interval = get_grid_interval(modules);
  int divisions = (modules + grid_interval - 1) / grid_interval;
  int total_regions = divisions * divisions;

  if (!shade_mode_active) {
    shade_region_index = 0;
    create_shade_overlay();
  } else {
    shade_region_index++;
    if (shade_region_index >= total_regions)
      reset_shade_mode();
    else
      create_shade_overlay();
  }
}

static void create_grid_overlay(void) {
  destroy_grid_overlay();

  int modules = last_qr_result.modules;
  int32_t scale = last_qr_result.scale;
  if (modules == 0 || scale == 0)
    return;

  int32_t content_size = modules * scale;
  int32_t margin = (qr_widget_size - content_size) / 2;

  lv_obj_update_layout(qr_code);
  lv_area_t qr_coords, content_coords;
  lv_obj_get_coords(qr_code, &qr_coords);
  lv_obj_get_coords(content_area, &content_coords);

  int32_t qr_x = qr_coords.x1 - content_coords.x1 + margin;
  int32_t qr_y = qr_coords.y1 - content_coords.y1 + margin;

  grid_overlay = lv_obj_create(content_area);
  lv_obj_remove_style_all(grid_overlay);
  lv_obj_set_size(grid_overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_clear_flag(grid_overlay,
                    LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_flag(grid_overlay, LV_OBJ_FLAG_IGNORE_LAYOUT);

  lv_color_t color = highlight_color();
  int grid_interval = get_grid_interval(modules);
  int divisions = (modules + grid_interval - 1) / grid_interval;
  int32_t cell_px = scale * grid_interval;

  grid_divisions = divisions;
  col_labels = calloc(divisions, sizeof(lv_obj_t *));
  row_labels = calloc(divisions, sizeof(lv_obj_t *));

  for (int c = 0; c <= divisions; c++) {
    int32_t mod = (c * grid_interval > modules) ? modules : c * grid_interval;
    int32_t x = qr_x + mod * scale;

    lv_obj_t *line = lv_obj_create(grid_overlay);
    lv_obj_remove_style_all(line);
    lv_obj_set_size(line, 2, content_size);
    lv_obj_set_pos(line, x - 1, qr_y);
    lv_obj_set_style_bg_color(line, color, 0);
    lv_obj_set_style_bg_opa(line, LV_OPA_COVER, 0);

    if (c < divisions) {
      char txt[4];
      snprintf(txt, sizeof(txt), "%d", c);
      lv_obj_t *lbl = lv_label_create(grid_overlay);
      lv_label_set_text(lbl, txt);
      lv_obj_set_style_text_color(lbl, color, 0);
      lv_obj_set_style_text_font(lbl, theme_font_small(), 0);
      lv_obj_update_layout(lbl);
      lv_obj_set_pos(lbl, x + (cell_px - lv_obj_get_width(lbl)) / 2,
                     qr_y - LABEL_PAD - lv_obj_get_height(lbl));
      if (col_labels)
        col_labels[c] = lbl;
    }
  }

  for (int r = 0; r <= divisions; r++) {
    int32_t mod = (r * grid_interval > modules) ? modules : r * grid_interval;
    int32_t y = qr_y + mod * scale;

    lv_obj_t *line = lv_obj_create(grid_overlay);
    lv_obj_remove_style_all(line);
    lv_obj_set_size(line, content_size, 2);
    lv_obj_set_pos(line, qr_x, y - 1);
    lv_obj_set_style_bg_color(line, color, 0);
    lv_obj_set_style_bg_opa(line, LV_OPA_COVER, 0);

    if (r < divisions) {
      char txt[2] = {(char)('A' + r), '\0'};
      lv_obj_t *lbl = lv_label_create(grid_overlay);
      lv_label_set_text(lbl, txt);
      lv_obj_set_style_text_color(lbl, color, 0);
      lv_obj_set_style_text_font(lbl, theme_font_small(), 0);
      lv_obj_update_layout(lbl);
      lv_obj_set_pos(lbl, qr_x - LABEL_PAD - lv_obj_get_width(lbl),
                     y + (cell_px - lv_obj_get_height(lbl)) / 2);
      if (row_labels)
        row_labels[r] = lbl;
    }
  }
}

static void grid_btn_cb(lv_event_t *e) {
  (void)e;
  grid_visible = !grid_visible;
  if (grid_visible) {
    create_grid_overlay();
  } else {
    reset_shade_mode();
    destroy_grid_overlay();
  }
}

/* ---------- Encrypted QR flow ---------- */

static void destroy_encrypt_overlay(void) {
  if (encrypt_task_handle) {
    vTaskDelete(encrypt_task_handle);
    encrypt_task_handle = NULL;
  }
  if (encrypt_poll_timer) {
    lv_timer_del(encrypt_poll_timer);
    encrypt_poll_timer = NULL;
  }
  encrypt_done = false;
  if (encrypt_input_group) {
    lv_group_del(encrypt_input_group);
    encrypt_input_group = NULL;
  }
  if (encrypt_keyboard) {
    lv_obj_del(encrypt_keyboard);
    encrypt_keyboard = NULL;
  }
  if (encrypt_screen) {
    lv_obj_del(encrypt_screen);
    encrypt_screen = NULL;
  }
  encrypt_textarea = NULL;
  encrypt_loading_label = NULL;

  SECURE_FREE_BUFFER(encrypt_key_copy, encrypt_key_copy_len);
  encrypt_key_copy_len = 0;
  SECURE_FREE_BUFFER(encrypt_envelope, encrypt_envelope_len);
  encrypt_envelope_len = 0;
}

static void show_encrypt_input(void) {
  if (encrypt_textarea)
    lv_obj_clear_flag(encrypt_textarea, LV_OBJ_FLAG_HIDDEN);
  if (encrypt_keyboard)
    lv_obj_clear_flag(encrypt_keyboard, LV_OBJ_FLAG_HIDDEN);
  if (encrypt_loading_label)
    lv_obj_add_flag(encrypt_loading_label, LV_OBJ_FLAG_HIDDEN);
}

static void show_encrypt_loading(void) {
  if (encrypt_textarea)
    lv_obj_add_flag(encrypt_textarea, LV_OBJ_FLAG_HIDDEN);
  if (encrypt_keyboard)
    lv_obj_add_flag(encrypt_keyboard, LV_OBJ_FLAG_HIDDEN);
  if (encrypt_loading_label)
    lv_obj_clear_flag(encrypt_loading_label, LV_OBJ_FLAG_HIDDEN);
}

/* Runs on CPU 1 — does NOT touch LVGL */
static void encrypt_task(void *arg) {
  (void)arg;

  TaskHandle_t idle1 = xTaskGetIdleTaskHandleForCore(1);
  esp_task_wdt_delete(idle1);

  if (encrypt_envelope) {
    SECURE_FREE_BUFFER(encrypt_envelope, encrypt_envelope_len);
    encrypt_envelope_len = 0;
  }

  encrypt_result = kef_encrypt(
      (const uint8_t *)encrypt_kef_id, strlen(encrypt_kef_id), KEF_V20_GCM_E4,
      encrypt_key_copy, encrypt_key_copy_len, KEF_ITERATIONS,
      compact_seedqr_data, compact_seedqr_len, &encrypt_envelope,
      &encrypt_envelope_len);

  SECURE_FREE_BUFFER(encrypt_key_copy, encrypt_key_copy_len);
  encrypt_key_copy_len = 0;

  esp_task_wdt_add(idle1);

  encrypt_done = true;
  vTaskDelete(NULL);
}

static void encrypt_poll_timer_cb(lv_timer_t *timer) {
  (void)timer;
  if (!encrypt_done)
    return;

  lv_timer_del(encrypt_poll_timer);
  encrypt_poll_timer = NULL;
  encrypt_task_handle = NULL;

  if (encrypt_result == KEF_OK) {
    char *b43 = NULL;
    size_t b43_len = 0;
    if (!base43_encode(encrypt_envelope, encrypt_envelope_len, &b43, &b43_len)) {
      destroy_encrypt_overlay();
      dialog_show_error("Encoding failed", NULL, 0);
      current_qr_type = previous_qr_type;
      lv_dropdown_set_selected(qr_type_dropdown, (uint32_t)current_qr_type);
      return;
    }

    SECURE_FREE_BUFFER(encrypt_envelope, encrypt_envelope_len);
    encrypt_envelope_len = 0;
    SECURE_FREE_STRING(encrypted_qr_data);
    encrypted_qr_data = b43;

    destroy_encrypt_overlay();
    current_qr_type = QR_TYPE_ENCRYPTED;
    lv_dropdown_set_selected(qr_type_dropdown, 3);
    update_qr_code();
    return;
  }

  /* Error — show keyboard for retry */
  show_encrypt_input();
  if (encrypt_textarea)
    lv_textarea_set_text(encrypt_textarea, "");
  dialog_show_error(kef_error_str(encrypt_result), NULL, 0);
}

static void encrypt_keyboard_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(encrypt_textarea);
  if (!text || text[0] == '\0')
    return;

  encrypt_key_copy_len = strlen(text);
  encrypt_key_copy = malloc(encrypt_key_copy_len);
  if (!encrypt_key_copy)
    return;
  memcpy(encrypt_key_copy, text, encrypt_key_copy_len);

  lv_textarea_set_text(encrypt_textarea, "");
  show_encrypt_loading();

  encrypt_done = false;
  if (xTaskCreatePinnedToCore(encrypt_task, "kef_enc", ENCRYPT_TASK_STACK_SIZE,
                              NULL, 5, &encrypt_task_handle, 1) != pdPASS) {
    SECURE_FREE_BUFFER(encrypt_key_copy, encrypt_key_copy_len);
    encrypt_key_copy_len = 0;
    show_encrypt_input();
    dialog_show_error("Task creation failed", NULL, 0);
    return;
  }

  encrypt_poll_timer = lv_timer_create(encrypt_poll_timer_cb, 100, NULL);
}

static void cancel_encrypt_flow(lv_event_t *e) {
  (void)e;
  destroy_encrypt_overlay();
  current_qr_type = previous_qr_type;
  lv_dropdown_set_selected(qr_type_dropdown, (uint32_t)current_qr_type);
}

static void create_encrypt_keyboard_overlay(const char *title,
                                            const char *placeholder,
                                            bool password_mode,
                                            bool with_loading,
                                            lv_event_cb_t ready_cb) {
  encrypt_screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(encrypt_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(encrypt_screen);
  lv_obj_clear_flag(encrypt_screen, LV_OBJ_FLAG_SCROLLABLE);

  theme_create_page_title(encrypt_screen, title);
  ui_create_back_button(encrypt_screen, cancel_encrypt_flow);

  encrypt_textarea = lv_textarea_create(encrypt_screen);
  lv_obj_set_size(encrypt_textarea, LV_PCT(90), 50);
  lv_obj_align(encrypt_textarea, LV_ALIGN_TOP_MID, 0, 140);
  lv_textarea_set_one_line(encrypt_textarea, true);
  lv_textarea_set_password_mode(encrypt_textarea, password_mode);
  lv_textarea_set_placeholder_text(encrypt_textarea, placeholder);
  lv_obj_set_style_text_font(encrypt_textarea, theme_font_small(), 0);
  lv_obj_set_style_bg_color(encrypt_textarea, panel_color(), 0);
  lv_obj_set_style_text_color(encrypt_textarea, main_color(), 0);
  lv_obj_set_style_border_color(encrypt_textarea, secondary_color(), 0);
  lv_obj_set_style_border_width(encrypt_textarea, 1, 0);
  lv_obj_set_style_bg_color(encrypt_textarea, highlight_color(), LV_PART_CURSOR);
  lv_obj_set_style_bg_opa(encrypt_textarea, LV_OPA_COVER, LV_PART_CURSOR);

  encrypt_input_group = lv_group_create();
  lv_group_add_obj(encrypt_input_group, encrypt_textarea);
  lv_group_focus_obj(encrypt_textarea);

  if (with_loading) {
    encrypt_loading_label = lv_label_create(encrypt_screen);
    lv_label_set_text(encrypt_loading_label, "Encrypting...");
    lv_obj_set_style_text_font(encrypt_loading_label, theme_font_small(), 0);
    lv_obj_set_style_text_color(encrypt_loading_label, main_color(), 0);
    lv_obj_align(encrypt_loading_label, LV_ALIGN_CENTER, 0, 0);
    lv_obj_add_flag(encrypt_loading_label, LV_OBJ_FLAG_HIDDEN);
  }

  encrypt_keyboard = lv_keyboard_create(lv_screen_active());
  lv_obj_set_size(encrypt_keyboard, LV_HOR_RES, LV_VER_RES * 55 / 100);
  lv_obj_align(encrypt_keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_keyboard_set_textarea(encrypt_keyboard, encrypt_textarea);
  lv_keyboard_set_mode(encrypt_keyboard, LV_KEYBOARD_MODE_TEXT_LOWER);
  lv_obj_add_event_cb(encrypt_keyboard, ready_cb, LV_EVENT_READY, NULL);

  lv_obj_set_style_bg_color(encrypt_keyboard, lv_color_black(), 0);
  lv_obj_set_style_border_width(encrypt_keyboard, 0, 0);
  lv_obj_set_style_pad_all(encrypt_keyboard, 4, 0);
  lv_obj_set_style_pad_gap(encrypt_keyboard, 6, 0);
  lv_obj_set_style_bg_color(encrypt_keyboard, disabled_color(), LV_PART_ITEMS);
  lv_obj_set_style_text_color(encrypt_keyboard, main_color(), LV_PART_ITEMS);
  lv_obj_set_style_text_font(encrypt_keyboard, theme_font_small(),
                             LV_PART_ITEMS);
  lv_obj_set_style_border_width(encrypt_keyboard, 0, LV_PART_ITEMS);
  lv_obj_set_style_radius(encrypt_keyboard, 6, LV_PART_ITEMS);
  lv_obj_set_style_bg_color(encrypt_keyboard, highlight_color(),
                            LV_PART_ITEMS | LV_STATE_PRESSED);
  lv_obj_set_style_bg_color(encrypt_keyboard, highlight_color(),
                            LV_PART_ITEMS | LV_STATE_CHECKED);
}

static void id_keyboard_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(encrypt_textarea);
  if (!text || text[0] == '\0')
    return;

  size_t len = strlen(text);
  if (len >= sizeof(encrypt_kef_id))
    len = sizeof(encrypt_kef_id) - 1;
  memcpy(encrypt_kef_id, text, len);
  encrypt_kef_id[len] = '\0';

  destroy_encrypt_overlay();
  create_encrypt_keyboard_overlay("Encryption Key", "key", true, true,
                                  encrypt_keyboard_ready_cb);
}

static void encrypt_id_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed) {
    /* Use fingerprint as ID — already stored in encrypt_kef_id */
    create_encrypt_keyboard_overlay("Encryption Key", "key", true, true,
                                    encrypt_keyboard_ready_cb);
  } else {
    /* Show keyboard for custom ID */
    create_encrypt_keyboard_overlay("Custom ID", "ID", false, false,
                                    id_keyboard_ready_cb);
  }
}

static void start_encrypted_flow(void) {
  previous_qr_type = current_qr_type;

  char fp_hex[9] = {0};
  if (!key_get_fingerprint_hex(fp_hex)) {
    dialog_show_error("Failed to get fingerprint", NULL, 0);
    return;
  }
  snprintf(encrypt_kef_id, sizeof(encrypt_kef_id), "%s", fp_hex);

  char msg[80];
  snprintf(msg, sizeof(msg), "Use fingerprint %s as backup ID?", fp_hex);
  dialog_show_confirm(msg, encrypt_id_confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
}

/* ---------- End Encrypted QR flow ---------- */

static void update_qr_code(void) {
  if (!qr_code)
    return;

  if (current_qr_type == QR_TYPE_COMPACT_SEEDQR) {
    if (compact_seedqr_data && compact_seedqr_len > 0)
      qr_update_binary(qr_code, compact_seedqr_data, compact_seedqr_len,
                       &last_qr_result);
  } else if (current_qr_type == QR_TYPE_ENCRYPTED) {
    if (encrypted_qr_data)
      qr_update_optimal(qr_code, encrypted_qr_data, &last_qr_result);
  } else {
    const char *data = (current_qr_type == QR_TYPE_PLAINTEXT) ? mnemonic_data
                       : (current_qr_type == QR_TYPE_SEEDQR)  ? seedqr_data
                                                              : NULL;
    if (data)
      qr_update_optimal(qr_code, data, &last_qr_result);
  }

  reset_shade_mode();
  if (grid_visible)
    create_grid_overlay();
}

static void dropdown_cb(lv_event_t *e) {
  uint32_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  if (sel == 3) {
    /* Encrypted: always trigger fresh flow (new GCM IV each time) */
    start_encrypted_flow();
    return;
  }
  qr_type_t new_type = (sel == 0)   ? QR_TYPE_PLAINTEXT
                       : (sel == 1) ? QR_TYPE_SEEDQR
                                    : QR_TYPE_COMPACT_SEEDQR;
  if (new_type != current_qr_type) {
    current_qr_type = new_type;
    update_qr_code();
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

void mnemonic_qr_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded())
    return;

  return_callback = return_cb;

  if (!key_get_mnemonic(&mnemonic_data) || !mnemonic_data)
    return;

  seedqr_data = mnemonic_to_seedqr(mnemonic_data);
  compact_seedqr_data =
      mnemonic_to_compact_seedqr(mnemonic_data, &compact_seedqr_len);
  if (!seedqr_data || !compact_seedqr_data) {
    secure_memzero(mnemonic_data, strlen(mnemonic_data));
    wally_free_string(mnemonic_data);
    mnemonic_data = NULL;
    SECURE_FREE_STRING(seedqr_data);
    SECURE_FREE_BUFFER(compact_seedqr_data, compact_seedqr_len);
    compact_seedqr_len = 0;
    return;
  }

  current_qr_type = QR_TYPE_PLAINTEXT;
  grid_visible = false;

  mnemonic_qr_screen = lv_obj_create(parent);
  lv_obj_set_size(mnemonic_qr_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(mnemonic_qr_screen);
  lv_obj_clear_flag(mnemonic_qr_screen, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(mnemonic_qr_screen, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(mnemonic_qr_screen, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(mnemonic_qr_screen, theme_get_default_padding(), 0);
  lv_obj_set_style_pad_gap(mnemonic_qr_screen, theme_get_default_padding(), 0);

  lv_obj_t *top_bar = lv_obj_create(mnemonic_qr_screen);
  lv_obj_set_size(top_bar, LV_PCT(100), 60);
  lv_obj_set_style_bg_opa(top_bar, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(top_bar, 0, 0);
  lv_obj_set_style_pad_all(top_bar, 0, 0);
  lv_obj_clear_flag(top_bar, LV_OBJ_FLAG_SCROLLABLE);

  back_button = ui_create_back_button(parent, back_cb);

  qr_type_dropdown = lv_dropdown_create(top_bar);
  lv_dropdown_set_options(qr_type_dropdown,
                          "Plaintext\nSeedQR\nCompact SeedQR\nEncrypted");
  lv_obj_set_width(qr_type_dropdown, LV_PCT(40));
  lv_obj_align(qr_type_dropdown, LV_ALIGN_CENTER, -30, 0);
  lv_obj_set_style_bg_color(qr_type_dropdown, disabled_color(), 0);
  lv_obj_set_style_text_color(qr_type_dropdown, main_color(), 0);
  lv_obj_set_style_text_font(qr_type_dropdown, theme_font_small(), 0);
  lv_obj_set_style_border_color(qr_type_dropdown, highlight_color(), 0);
  lv_obj_add_event_cb(qr_type_dropdown, dropdown_open_cb, LV_EVENT_READY, NULL);
  lv_obj_add_event_cb(qr_type_dropdown, dropdown_cb, LV_EVENT_VALUE_CHANGED,
                      NULL);

  grid_btn = lv_btn_create(top_bar);
  lv_obj_set_size(grid_btn, 80, 120);
  lv_obj_align_to(grid_btn, qr_type_dropdown, LV_ALIGN_OUT_RIGHT_MID, 10, 0);
  theme_apply_touch_button(grid_btn, false);
  lv_obj_add_event_cb(grid_btn, grid_btn_cb, LV_EVENT_CLICKED, NULL);

  lv_obj_t *grid_label = lv_label_create(grid_btn);
  lv_label_set_text(grid_label, "#");
  lv_obj_set_style_text_font(grid_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(grid_label, main_color(), 0);
  lv_obj_center(grid_label);

  content_area = lv_obj_create(mnemonic_qr_screen);
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
  int32_t avail_w = lv_obj_get_content_width(content_area);
  int32_t avail_h = lv_obj_get_content_height(content_area);
  int32_t container_size = (avail_w < avail_h) ? avail_w : avail_h;

  qr_container = lv_obj_create(content_area);
  lv_obj_set_size(qr_container, container_size, container_size);
  lv_obj_set_style_bg_color(qr_container, lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_bg_opa(qr_container, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(qr_container, 0, 0);
  lv_obj_set_style_pad_all(qr_container, LEGEND_SIZE, 0);
  lv_obj_set_style_radius(qr_container, 0, 0);
  lv_obj_clear_flag(qr_container, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_update_layout(qr_container);
  qr_widget_size = lv_obj_get_content_width(qr_container);

  qr_code = lv_qrcode_create(qr_container);
  lv_qrcode_set_size(qr_code, qr_widget_size);
  lv_obj_center(qr_code);

  lv_obj_add_flag(qr_container, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(qr_container, qr_area_tap_cb, LV_EVENT_CLICKED, NULL);

  update_qr_code();
}

void mnemonic_qr_page_show(void) {
  if (mnemonic_qr_screen)
    lv_obj_clear_flag(mnemonic_qr_screen, LV_OBJ_FLAG_HIDDEN);
}

void mnemonic_qr_page_hide(void) {
  if (mnemonic_qr_screen)
    lv_obj_add_flag(mnemonic_qr_screen, LV_OBJ_FLAG_HIDDEN);
}

void mnemonic_qr_page_destroy(void) {
  destroy_encrypt_overlay();

  reset_shade_mode();
  destroy_grid_overlay();

  if (mnemonic_data) {
    secure_memzero(mnemonic_data, strlen(mnemonic_data));
    wally_free_string(mnemonic_data);
    mnemonic_data = NULL;
  }

  SECURE_FREE_STRING(seedqr_data);
  SECURE_FREE_BUFFER(compact_seedqr_data, compact_seedqr_len);
  compact_seedqr_len = 0;
  SECURE_FREE_STRING(encrypted_qr_data);

  if (back_button) {
    lv_obj_del(back_button);
    back_button = NULL;
  }

  if (mnemonic_qr_screen) {
    lv_obj_del(mnemonic_qr_screen);
    mnemonic_qr_screen = NULL;
  }

  qr_type_dropdown = NULL;
  grid_btn = NULL;
  qr_code = NULL;
  qr_container = NULL;
  content_area = NULL;
  return_callback = NULL;
  current_qr_type = QR_TYPE_PLAINTEXT;
  grid_visible = false;
  qr_widget_size = 0;
  last_qr_result = (qr_encode_result_t){0, 0};
  secure_memzero(encrypt_kef_id, sizeof(encrypt_kef_id));
}
