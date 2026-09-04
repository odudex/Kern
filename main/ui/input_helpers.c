// UI Input Helpers - Shared components for input pages

#include "input_helpers.h"
#include "assets/icons.h"
#include "theme_widgets.h"
#include <string.h>

// Compact keyboard maps shared by all boards.
// Trade fewer keys per row for wider touch targets.

// Ctrl-map roles. Only KB_ACTION carries CTRL_CHECKED, which is what the theme
// renders as a filled action key. Mode switches deliberately drop it so the
// fill keeps meaning "backspace/OK". KB_BACKSPACE omits NO_REPEAT so it still
// repeats when held.
#define KB_KEY 1
#define KB_SPACE 5
#define KB_MODE                                                                \
  (LV_BUTTONMATRIX_CTRL_NO_REPEAT | LV_BUTTONMATRIX_CTRL_CLICK_TRIG | 2)
#define KB_BACKSPACE (LV_BUTTONMATRIX_CTRL_CHECKED | 2)
#define KB_ACTION (LV_KEYBOARD_CTRL_BUTTON_FLAGS | 2)

// LVGL keeps one global map table for every keyboard, so a scan-capable and a
// plain variant of each mode must both stay static, and create() always
// re-installs the plain ones.
#define KB_SCAN KB_MODE

#define KB_ROWS_LC                                                             \
  "q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "\n", "a", "s", "d", "f",  \
      "g", "h", "j", "k", "l", "\n", "ABC", "z", "x", "c", "v", "b", "n", "m", \
      LV_SYMBOL_BACKSPACE, "\n", "1#", ",", " ", "."

#define KB_ROWS_UC                                                             \
  "Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "\n", "A", "S", "D", "F",  \
      "G", "H", "J", "K", "L", "\n", "abc", "Z", "X", "C", "V", "B", "N", "M", \
      LV_SYMBOL_BACKSPACE, "\n", "1#", ",", " ", "."

// Five rows covering every printable ASCII symbol (',' and '.' live on the
// letter pages) so any externally created passphrase or KEF key can be typed.
#define KB_ROWS_SPEC                                                           \
  "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "\n", "@", "#", "$", "%",  \
      "&", "*", "+", "-", "=", "/", "\n", "(", ")", "[", "]", "{", "}", "<",   \
      ">", "\"", "'", "\n", "abc", "!", "?", ";", ":", "_", "\\", "|",         \
      LV_SYMBOL_BACKSPACE, "\n", "~", "^", "`", " "

// q w e r t y u i o p / a s d f g h j k l / ABC z x c v b n m <- / 1# , _ .
#define KB_CTRL_LETTERS                                                        \
  KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY,      \
      KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY,  \
      KB_KEY, KB_MODE, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, \
      KB_BACKSPACE, KB_MODE, KB_KEY, KB_SPACE, KB_KEY

// 1..0 / @ # $ % & * + - = / / ( ) [ ] { } < > " ' / abc ! ? ; : _ \ | <- / ~ ^
// ` _
#define KB_CTRL_SPEC                                                           \
  KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY,      \
      KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY,  \
      KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY,  \
      KB_KEY, KB_KEY, KB_KEY, KB_MODE, KB_KEY, KB_KEY, KB_KEY, KB_KEY, KB_KEY, \
      KB_KEY, KB_KEY, KB_BACKSPACE, KB_KEY, KB_KEY, KB_KEY, KB_SPACE

static const char *const compact_kb_map_lc[] = {KB_ROWS_LC, LV_SYMBOL_OK, ""};
static const char *const compact_kb_map_uc[] = {KB_ROWS_UC, LV_SYMBOL_OK, ""};
static const char *const compact_kb_map_spec[] = {KB_ROWS_SPEC, LV_SYMBOL_OK,
                                                  ""};
static const lv_buttonmatrix_ctrl_t compact_kb_ctrl_letters[] = {
    KB_CTRL_LETTERS, KB_ACTION};
static const lv_buttonmatrix_ctrl_t compact_kb_ctrl_spec[] = {KB_CTRL_SPEC,
                                                              KB_ACTION};

static const char *const compact_kb_map_lc_scan[] = {KB_ROWS_LC, ICON_QR_CODE,
                                                     LV_SYMBOL_OK, ""};
static const char *const compact_kb_map_uc_scan[] = {KB_ROWS_UC, ICON_QR_CODE,
                                                     LV_SYMBOL_OK, ""};
static const char *const compact_kb_map_spec_scan[] = {
    KB_ROWS_SPEC, ICON_QR_CODE, LV_SYMBOL_OK, ""};
static const lv_buttonmatrix_ctrl_t compact_kb_ctrl_letters_scan[] = {
    KB_CTRL_LETTERS, KB_SCAN, KB_ACTION};
static const lv_buttonmatrix_ctrl_t compact_kb_ctrl_spec_scan[] = {
    KB_CTRL_SPEC, KB_SCAN, KB_ACTION};

// Corner buttons (back/power top-left, settings top-right) all share the
// secondary grey style so they read as one consistent control class.
static lv_obj_t *create_corner_button(lv_obj_t *parent, lv_align_t align,
                                      const char *symbol,
                                      lv_event_cb_t event_cb) {
  if (!parent)
    return NULL;

  // Offsets are measured from the parent's border rather than its content
  // area, so the button lands at the same screen position on padded
  // containers as on standard zero-padding pages.
  int32_t pad = theme_small_padding();
  int32_t y_ofs = pad - lv_obj_get_style_pad_top(parent, 0);
  int32_t x_ofs = align == LV_ALIGN_TOP_RIGHT
                      ? lv_obj_get_style_pad_right(parent, 0) - pad
                      : pad - lv_obj_get_style_pad_left(parent, 0);

  lv_obj_t *btn = lv_btn_create(parent);
  theme_apply_touch_button(btn, false);
  lv_obj_set_size(btn, theme_corner_button_width(),
                  theme_corner_button_height());
  lv_obj_align(btn, align, x_ofs, y_ofs);

  lv_obj_t *label = lv_label_create(btn);
  lv_label_set_text(label, symbol);
  lv_obj_set_style_text_color(label, highlight_color(), 0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  lv_obj_center(label);

  if (event_cb)
    lv_obj_add_event_cb(btn, event_cb, LV_EVENT_CLICKED, NULL);

  return btn;
}

lv_obj_t *ui_create_back_button(lv_obj_t *parent, lv_event_cb_t event_cb) {
  return create_corner_button(parent, LV_ALIGN_TOP_LEFT, LV_SYMBOL_LEFT,
                              event_cb);
}

lv_obj_t *ui_create_power_button(lv_obj_t *parent, lv_event_cb_t event_cb) {
  return create_corner_button(parent, LV_ALIGN_TOP_LEFT, LV_SYMBOL_POWER,
                              event_cb);
}

lv_obj_t *ui_create_settings_button(lv_obj_t *parent, lv_event_cb_t event_cb) {
  return create_corner_button(parent, LV_ALIGN_TOP_RIGHT, LV_SYMBOL_SETTINGS,
                              event_cb);
}

lv_obj_t *ui_create_info_button(lv_obj_t *parent, lv_event_cb_t event_cb) {
  return create_corner_button(parent, LV_ALIGN_TOP_RIGHT, ICON_INFO, event_cb);
}

// Swipe and tap travel scale with the touch target, so a gesture spans the same
// share of the panel on a 320 px board as on a 1024 px one.
static int32_t swipe_min_distance(void) {
  return theme_min_touch_size() * 5 / 6;
}

// Travel past which the touch is not a tap.
static int32_t tap_slop(void) { return theme_min_touch_size() / 6; }

static lv_point_t touch_origin;
static bool not_tap;
static bool dragging;

// Travel is measured against the press point rather than read from LVGL's
// gesture accumulator, which zeroes itself on any input read slower than its
// velocity floor.
static void touch_track_cb(lv_event_t *e) {
  ui_drag_cb_t drag_cb = (ui_drag_cb_t)lv_event_get_user_data(e);
  lv_event_code_t code = lv_event_get_code(e);
  lv_point_t p;
  lv_indev_get_point(lv_event_get_indev(e), &p);
  if (code == LV_EVENT_PRESSED) {
    touch_origin = p;
    not_tap = false;
    dragging = false;
    return;
  }

  int32_t dx = p.x - touch_origin.x;
  int32_t dy = p.y - touch_origin.y;

  switch (code) {
  case LV_EVENT_PRESSING: {
    if (!dragging) {
      int32_t slop = tap_slop();
      if (LV_ABS(dx) <= slop && LV_ABS(dy) <= slop)
        break;
      not_tap = true;
      dragging = true;
    }
    if (drag_cb)
      drag_cb(dx, dy, false);
    break;
  }
  // The finger sliding off the object ends the drag there: the release lands
  // on whatever it moved onto and never reaches this callback.
  case LV_EVENT_RELEASED:
  case LV_EVENT_PRESS_LOST:
    if (dragging) {
      dragging = false;
      if (drag_cb)
        drag_cb(dx, dy, true);
    }
    break;
  default:
    break;
  }
}

// A touch that moved but never became a swipe still ends in a click. Drop it
// here so no caller has to remember to.
static void tap_filter_cb(lv_event_t *e) {
  if (not_tap)
    return;
  ((lv_event_cb_t)lv_event_get_user_data(e))(e);
}

void ui_enable_tap_drag(lv_obj_t *obj, lv_event_cb_t tap_cb,
                        ui_drag_cb_t drag_cb) {
  if (!obj)
    return;

  // Both a tap and a drag need the object to be the one under the finger.
  lv_obj_add_flag(obj, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_add_event_cb(obj, touch_track_cb, LV_EVENT_PRESSED, drag_cb);
  lv_obj_add_event_cb(obj, touch_track_cb, LV_EVENT_PRESSING, drag_cb);
  lv_obj_add_event_cb(obj, touch_track_cb, LV_EVENT_RELEASED, drag_cb);
  lv_obj_add_event_cb(obj, touch_track_cb, LV_EVENT_PRESS_LOST, drag_cb);
  if (tap_cb)
    lv_obj_add_event_cb(obj, tap_filter_cb, LV_EVENT_CLICKED, tap_cb);
}

bool ui_drag_is_swipe(int32_t dx, int32_t dy, lv_dir_t *dir) {
  int32_t abs_x = LV_ABS(dx);
  int32_t abs_y = LV_ABS(dy);
  bool horizontal = abs_x >= abs_y;
  if ((horizontal ? abs_x : abs_y) < swipe_min_distance())
    return false;

  if (horizontal)
    *dir = dx < 0 ? LV_DIR_LEFT : LV_DIR_RIGHT;
  else
    *dir = dy < 0 ? LV_DIR_TOP : LV_DIR_BOTTOM;
  return true;
}

/* ---------- Shared text input component ---------- */

static void ui_text_input_eye_cb(lv_event_t *e) {
  ui_text_input_t *input = lv_event_get_user_data(e);
  if (!input || !input->textarea || !input->eye_label)
    return;
  bool hidden = lv_textarea_get_password_mode(input->textarea);
  lv_textarea_set_password_mode(input->textarea, !hidden);
  lv_label_set_text(input->eye_label,
                    hidden ? LV_SYMBOL_EYE_CLOSE : LV_SYMBOL_EYE_OPEN);
}

void ui_text_input_create(ui_text_input_t *input, lv_obj_t *parent,
                          const char *placeholder, bool password_mode,
                          lv_event_cb_t ready_cb) {
  /* Textarea below the corner-button/title zone */
  const int32_t ta_h = 50;
  const int32_t ta_y = theme_small_padding() + theme_corner_button_height() +
                       theme_default_padding();
  input->textarea = lv_textarea_create(parent);
  lv_obj_set_size(input->textarea, password_mode ? LV_PCT(80) : LV_PCT(90),
                  ta_h);
  if (password_mode)
    lv_obj_align(input->textarea, LV_ALIGN_TOP_LEFT, LV_HOR_RES * 5 / 100,
                 ta_y);
  else
    lv_obj_align(input->textarea, LV_ALIGN_TOP_MID, 0, ta_y);
  lv_textarea_set_one_line(input->textarea, true);
  lv_textarea_set_password_mode(input->textarea, password_mode);
  lv_textarea_set_placeholder_text(input->textarea, placeholder);
  lv_obj_set_style_text_font(input->textarea, theme_font_small(), 0);
  lv_obj_set_style_bg_color(input->textarea, panel_color(), 0);
  lv_obj_set_style_text_color(input->textarea, primary_color(), 0);
  lv_obj_set_style_border_color(input->textarea, highlight_color(), 0);
  lv_obj_set_style_border_width(input->textarea, 1, 0);
  lv_obj_set_style_bg_color(input->textarea, highlight_color(), LV_PART_CURSOR);
  lv_obj_set_style_bg_opa(input->textarea, LV_OPA_COVER, LV_PART_CURSOR);

  /* Eye toggle (password mode only) */
  if (password_mode) {
    input->eye_btn = lv_btn_create(parent);
    lv_obj_set_size(input->eye_btn, theme_min_touch_size(),
                    theme_min_touch_size());
    lv_obj_align_to(input->eye_btn, input->textarea, LV_ALIGN_OUT_RIGHT_MID, 5,
                    0);
    lv_obj_set_style_bg_opa(input->eye_btn, LV_OPA_TRANSP, 0);
    lv_obj_set_style_shadow_width(input->eye_btn, 0, 0);
    lv_obj_set_style_border_width(input->eye_btn, 0, 0);
    lv_obj_add_event_cb(input->eye_btn, ui_text_input_eye_cb, LV_EVENT_CLICKED,
                        input);

    input->eye_label = lv_label_create(input->eye_btn);
    lv_label_set_text(input->eye_label, LV_SYMBOL_EYE_OPEN);
    lv_obj_set_style_text_color(input->eye_label, secondary_color(), 0);
    lv_obj_set_style_text_font(input->eye_label, theme_font_small(), 0);
    lv_obj_center(input->eye_label);
  } else {
    input->eye_btn = NULL;
    input->eye_label = NULL;
  }

  /* Input group */
  input->input_group = lv_group_create();
  lv_group_add_obj(input->input_group, input->textarea);
  lv_group_focus_obj(input->textarea);

  /* Keyboard on active screen: fill the space below the textarea, capped at
   * screen width so tall displays keep a sane key aspect ratio */
  int32_t kb_h = LV_VER_RES - (ta_y + ta_h + theme_default_padding());
  if (kb_h > LV_HOR_RES)
    kb_h = LV_HOR_RES;
  input->keyboard = lv_keyboard_create(lv_screen_active());
  lv_obj_set_size(input->keyboard, LV_HOR_RES, kb_h);
  lv_obj_align(input->keyboard, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_keyboard_set_textarea(input->keyboard, input->textarea);
  lv_keyboard_set_mode(input->keyboard, LV_KEYBOARD_MODE_TEXT_LOWER);
  lv_obj_add_event_cb(input->keyboard, ready_cb, LV_EVENT_READY, NULL);

  lv_keyboard_set_map(input->keyboard, LV_KEYBOARD_MODE_TEXT_LOWER,
                      compact_kb_map_lc, compact_kb_ctrl_letters);
  lv_keyboard_set_map(input->keyboard, LV_KEYBOARD_MODE_TEXT_UPPER,
                      compact_kb_map_uc, compact_kb_ctrl_letters);
  lv_keyboard_set_map(input->keyboard, LV_KEYBOARD_MODE_SPECIAL,
                      compact_kb_map_spec, compact_kb_ctrl_spec);

  theme_apply_btnmatrix_styles(input->keyboard);
  input->scan_cb = NULL;
  input->scan_user_data = NULL;
}

// Replaces LVGL's default key handler so the scan key reaches the page instead
// of being typed into the textarea.
static void scan_kb_event_cb(lv_event_t *e) {
  ui_text_input_t *input = lv_event_get_user_data(e);
  lv_obj_t *kb = lv_event_get_current_target(e);
  const char *txt = lv_buttonmatrix_get_button_text(
      kb, lv_buttonmatrix_get_selected_button(kb));
  if (txt && strcmp(txt, ICON_QR_CODE) == 0) {
    if (input->scan_cb)
      input->scan_cb(input->scan_user_data);
    return;
  }
  lv_keyboard_def_event_cb(e);
}

void ui_text_input_enable_scan(ui_text_input_t *input,
                               ui_text_input_scan_cb_t cb, void *user_data) {
  if (!input || !input->keyboard)
    return;
  input->scan_cb = cb;
  input->scan_user_data = user_data;
  lv_obj_remove_event_cb(input->keyboard, lv_keyboard_def_event_cb);
  lv_obj_add_event_cb(input->keyboard, scan_kb_event_cb, LV_EVENT_VALUE_CHANGED,
                      input);
  lv_keyboard_set_map(input->keyboard, LV_KEYBOARD_MODE_TEXT_LOWER,
                      compact_kb_map_lc_scan, compact_kb_ctrl_letters_scan);
  lv_keyboard_set_map(input->keyboard, LV_KEYBOARD_MODE_TEXT_UPPER,
                      compact_kb_map_uc_scan, compact_kb_ctrl_letters_scan);
  lv_keyboard_set_map(input->keyboard, LV_KEYBOARD_MODE_SPECIAL,
                      compact_kb_map_spec_scan, compact_kb_ctrl_spec_scan);
}

void ui_text_input_show(ui_text_input_t *input) {
  if (input->textarea)
    lv_obj_clear_flag(input->textarea, LV_OBJ_FLAG_HIDDEN);
  if (input->eye_btn)
    lv_obj_clear_flag(input->eye_btn, LV_OBJ_FLAG_HIDDEN);
  if (input->keyboard)
    lv_obj_clear_flag(input->keyboard, LV_OBJ_FLAG_HIDDEN);
}

void ui_text_input_hide(ui_text_input_t *input) {
  if (input->textarea)
    lv_obj_add_flag(input->textarea, LV_OBJ_FLAG_HIDDEN);
  if (input->eye_btn)
    lv_obj_add_flag(input->eye_btn, LV_OBJ_FLAG_HIDDEN);
  if (input->keyboard)
    lv_obj_add_flag(input->keyboard, LV_OBJ_FLAG_HIDDEN);
}

void ui_text_input_destroy(ui_text_input_t *input) {
  if (input->input_group) {
    lv_group_del(input->input_group);
    input->input_group = NULL;
  }
  if (input->keyboard) {
    lv_obj_del(input->keyboard);
    input->keyboard = NULL;
  }
  input->textarea = NULL;
  input->eye_btn = NULL;
  input->eye_label = NULL;
  input->scan_cb = NULL;
  input->scan_user_data = NULL;
}
