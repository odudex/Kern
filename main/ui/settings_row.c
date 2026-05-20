#include "settings_row.h"

#include "assets/icons_24.h"
#include "dialog.h"
#include "theme.h"

#include <lvgl.h>

/* Help-button click handler: pulls (title, message) from the button's
 * user_data and shows them in an overlay info dialog. */
typedef struct {
  const char *title;
  const char *msg;
} help_text_t;

static void help_btn_cb(lv_event_t *e) {
  help_text_t *ht = (help_text_t *)lv_event_get_user_data(e);
  if (!ht)
    return;
  dialog_show_info(ht->title, ht->msg, NULL, NULL, DIALOG_STYLE_OVERLAY);
}

/* Common row container: full-width flex row with label + (item slot)
 * + trailing button. Returns the row. The label is left-aligned and
 * flex-grows; the item slot is fixed-width. */
static lv_obj_t *make_row(lv_obj_t *parent) {
  lv_obj_t *row = lv_obj_create(parent);
  lv_obj_set_size(row, LV_PCT(100), LV_SIZE_CONTENT);
  lv_obj_set_style_min_height(row, theme_get_min_touch_size(), 0);
  theme_apply_transparent_container(row);
  lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(row, 8, 0);
  lv_obj_set_style_pad_hor(row, 8, 0);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
  return row;
}

static lv_obj_t *make_label(lv_obj_t *parent, const char *text) {
  lv_obj_t *lbl = lv_label_create(parent);
  lv_label_set_text(lbl, text);
  lv_obj_set_style_text_font(lbl, theme_font_medium(), 0);
  lv_obj_set_style_text_color(lbl, main_color(), 0);
  lv_obj_set_flex_grow(lbl, 1);
  return lbl;
}

/* Renders a single-glyph clickable label at a fixed cell width
 * (theme_get_min_touch_size()), used for both the trailing `?` (help)
 * and `>` (chevron) markers. Same widget type + same width keeps
 * trailing edges of toggle/dropdown rows visually aligned with action
 * rows. The trailing icon is a label (not lv_btn) to avoid
 * theme_apply_touch_button's pad_all=15 which clips the glyph. */
static lv_obj_t *make_trailing_icon(lv_obj_t *parent, const char *glyph,
                                    lv_event_cb_t on_click, void *user_data) {
  lv_obj_t *lbl = lv_label_create(parent);
  lv_label_set_text(lbl, glyph);
  lv_obj_set_style_text_font(lbl, theme_font_medium(), 0);
  lv_obj_set_style_text_color(lbl, main_color(), 0);
  lv_obj_set_width(lbl, theme_get_min_touch_size());
  lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, 0);
  if (on_click) {
    lv_obj_add_flag(lbl, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_add_event_cb(lbl, on_click, LV_EVENT_CLICKED, user_data);
  }
  return lbl;
}

static lv_obj_t *make_help_icon(lv_obj_t *parent, const char *title,
                                const char *msg) {
  /* Stash (title, msg) on the icon so the click handler can pull them.
   * Both are expected to be string literals — we don't own this alloc. */
  help_text_t *ht = lv_malloc(sizeof(*ht));
  ht->title = title;
  ht->msg = msg;
  return make_trailing_icon(parent, ICON_HELP, help_btn_cb, ht);
}

lv_obj_t *settings_row_toggle(lv_obj_t *parent, const char *label, bool initial,
                              lv_event_cb_t on_change, const char *help_title,
                              const char *help_msg) {
  lv_obj_t *row = make_row(parent);
  make_label(row, label);

  lv_obj_t *sw = lv_switch_create(row);
  if (initial)
    lv_obj_add_state(sw, LV_STATE_CHECKED);
  else
    lv_obj_clear_state(sw, LV_STATE_CHECKED);
  if (on_change)
    lv_obj_add_event_cb(sw, on_change, LV_EVENT_VALUE_CHANGED, NULL);

  make_help_icon(row, help_title, help_msg);
  lv_obj_set_user_data(row, sw);
  return row;
}

lv_obj_t *settings_row_dropdown(lv_obj_t *parent, const char *label,
                                const char *options, uint16_t selected,
                                lv_event_cb_t on_change, const char *help_title,
                                const char *help_msg) {
  lv_obj_t *row = make_row(parent);
  make_label(row, label);

  lv_obj_t *dd = theme_create_dropdown(row, options);
  lv_dropdown_set_selected(dd, selected);
  /* Width sized to fit longest option + arrow without overlap. The
   * default lv_dropdown sizes to text only, leaving the arrow on top
   * of the selection. Cap at ~40% of row to leave label room. */
  lv_obj_set_width(dd, LV_PCT(40));
  if (on_change)
    lv_obj_add_event_cb(dd, on_change, LV_EVENT_VALUE_CHANGED, NULL);

  make_help_icon(row, help_title, help_msg);
  lv_obj_set_user_data(row, dd);
  return row;
}

lv_obj_t *settings_row_action(lv_obj_t *parent, const char *label,
                              lv_event_cb_t on_click) {
  lv_obj_t *row = make_row(parent);
  /* Whole row clickable so tapping the label fires on_click too. */
  lv_obj_add_flag(row, LV_OBJ_FLAG_CLICKABLE);
  if (on_click)
    lv_obj_add_event_cb(row, on_click, LV_EVENT_CLICKED, NULL);

  make_label(row, label);

  /* `>` rendered via the same trailing-icon helper as `?` so the
   * trailing edges of action and toggle/dropdown rows line up. */
  make_trailing_icon(row, LV_SYMBOL_RIGHT, NULL, NULL);

  lv_obj_set_user_data(row, NULL);
  return row;
}

lv_obj_t *settings_row_get_widget(lv_obj_t *row) {
  return (lv_obj_t *)lv_obj_get_user_data(row);
}
