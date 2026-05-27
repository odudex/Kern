// UI Menu Component - Touch menu for LVGL

#include "menu.h"
#include "input_helpers.h"
#include "theme.h"
#include <stdint.h>
#include <stdlib.h>

#define UI_MENU_PORTRAIT_COLUMNS 1
#define UI_MENU_LANDSCAPE_COLUMNS 2

typedef struct {
  ui_menu_callback_t callback;
  ui_menu_action_callback_t action_callback;
  bool enabled;
} ui_menu_entry_t;

typedef struct {
  ui_menu_entry_t entries[UI_MENU_MAX_ENTRIES];
  int entry_count;
  int selected_index;
} ui_menu_config_t;

struct ui_menu_t {
  ui_menu_config_t config;
  lv_obj_t *container;
  lv_obj_t *nav_bar;
  lv_obj_t *title_label;
  lv_obj_t *list;
  lv_obj_t *buttons[UI_MENU_MAX_ENTRIES];
  lv_obj_t *back_btn;
  ui_menu_callback_t back_callback;
};

static int menu_column_count(void) {
  return theme_is_landscape() ? UI_MENU_LANDSCAPE_COLUMNS
                              : UI_MENU_PORTRAIT_COLUMNS;
}

static int menu_row_count(ui_menu_t *menu) {
  int count = menu ? menu->config.entry_count : 0;
  int columns = menu_column_count();
  return count > 0 ? (count + columns - 1) / columns : 1;
}

static void apply_list_layout(ui_menu_t *menu) {
  if (!menu || !menu->list)
    return;

  lv_obj_set_flex_flow(menu->list, LV_FLEX_FLOW_ROW_WRAP);
  lv_obj_set_flex_align(menu->list, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_START);
}

static lv_obj_t *entry_label(ui_menu_t *menu, int index) {
  if (!menu || index < 0 || index >= menu->config.entry_count ||
      !menu->buttons[index])
    return NULL;

  return lv_obj_get_child(menu->buttons[index], 0);
}

static void apply_entry_label_layout(ui_menu_t *menu, int index) {
  lv_obj_t *label = entry_label(menu, index);
  if (!label)
    return;

  lv_obj_t *btn = menu->buttons[index];
  int32_t width = lv_obj_get_width(btn);
  width -=
      lv_obj_get_style_pad_left(btn, 0) + lv_obj_get_style_pad_right(btn, 0);

  if (lv_obj_get_child_count(btn) > 1)
    width -= theme_get_min_touch_size();

  width = LV_MAX(width, 1);
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(label, width);
  lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);

  if (lv_obj_get_child_count(btn) == 1)
    lv_obj_center(label);
}

static void apply_entry_layout(ui_menu_t *menu, int index) {
  if (!menu || index < 0 || index >= UI_MENU_MAX_ENTRIES ||
      !menu->buttons[index])
    return;

  int columns = menu_column_count();
  int rows = menu_row_count(menu);
  int count = menu->config.entry_count;
  int32_t gap = theme_get_default_padding();

  lv_obj_update_layout(menu->container);
  int32_t width = lv_obj_get_content_width(menu->list);
  int32_t height = lv_obj_get_content_height(menu->list);

  bool span_row = columns == UI_MENU_LANDSCAPE_COLUMNS &&
                  count % columns == 1 && index == count - 1;
  if (!span_row)
    width = (width - gap * (columns - 1)) / columns;
  height = (height - gap * (rows - 1)) / rows;
  lv_obj_set_size(menu->buttons[index],
                  LV_MAX(width, theme_get_min_touch_size()),
                  LV_MAX(height, theme_get_min_touch_size()));
  lv_obj_set_flex_grow(menu->buttons[index], 0);
  apply_entry_label_layout(menu, index);
}

static void refresh_menu_layout(ui_menu_t *menu) {
  apply_list_layout(menu);
  for (int i = 0; menu && i < menu->config.entry_count; i++)
    apply_entry_layout(menu, i);
}

static void menu_button_event_cb(lv_event_t *e) {
  lv_obj_t *btn = lv_event_get_target(e);
  ui_menu_t *menu = (ui_menu_t *)lv_event_get_user_data(e);

  for (int i = 0; i < menu->config.entry_count; i++) {
    if (menu->buttons[i] == btn) {
      menu->config.selected_index = i;
      if (menu->config.entries[i].enabled && menu->config.entries[i].callback)
        menu->config.entries[i].callback();
      break;
    }
  }
}

static void menu_back_button_event_cb(lv_event_t *e) {
  ui_menu_t *menu = (ui_menu_t *)lv_event_get_user_data(e);
  if (menu && menu->back_callback)
    menu->back_callback();
}

ui_menu_t *ui_menu_create(lv_obj_t *parent, const char *title,
                          ui_menu_callback_t back_cb) {
  if (!parent || !title)
    return NULL;

  ui_menu_t *menu = calloc(1, sizeof(ui_menu_t));
  if (!menu)
    return NULL;

  menu->container = lv_obj_create(parent);
  lv_obj_set_size(menu->container, LV_PCT(100), LV_PCT(100));
  lv_obj_set_flex_flow(menu->container, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(menu->container, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(menu->container, theme_get_default_padding(), 0);
  lv_obj_set_style_pad_top(menu->container, theme_get_small_padding(), 0);
  lv_obj_set_style_pad_gap(menu->container, theme_get_default_padding(), 0);
  lv_obj_clear_flag(menu->container, LV_OBJ_FLAG_SCROLLABLE);
  theme_apply_screen(menu->container);

  /* Top nav bar: a band the height of the corner button, so the centered
     title sits beside (vertically aligned with) the back/power button rather
     than above it. The button list then flows below this band. */
  menu->nav_bar = lv_obj_create(menu->container);
  lv_obj_set_size(menu->nav_bar, LV_PCT(100), theme_get_corner_button_height());
  theme_apply_transparent_container(menu->nav_bar);
  lv_obj_set_flex_flow(menu->nav_bar, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(menu->nav_bar, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(menu->nav_bar, LV_OBJ_FLAG_SCROLLABLE);

  menu->title_label = lv_label_create(menu->nav_bar);
  lv_label_set_text(menu->title_label, title);
  lv_obj_set_style_text_font(menu->title_label, theme_font_small(), 0);
  theme_apply_label(menu->title_label, true);

  menu->list = lv_obj_create(menu->container);
  lv_obj_set_size(menu->list, LV_PCT(100), LV_PCT(100));
  theme_apply_transparent_container(menu->list);
  apply_list_layout(menu);
  lv_obj_set_flex_grow(menu->list, 1);
  lv_obj_set_style_pad_row(menu->list, theme_get_default_padding(), 0);
  lv_obj_set_style_pad_column(menu->list, theme_get_default_padding(), 0);
  lv_obj_set_style_outline_width(menu->list, 0, 0);

  menu->back_callback = back_cb;

  if (back_cb) {
    menu->back_btn = ui_create_back_button(parent, NULL);
    if (menu->back_btn) {
      lv_obj_remove_event_cb(menu->back_btn, NULL);
      lv_obj_add_event_cb(menu->back_btn, menu_back_button_event_cb,
                          LV_EVENT_CLICKED, menu);
    }
  }

  return menu;
}

bool ui_menu_add_entry(ui_menu_t *menu, const char *name,
                       ui_menu_callback_t callback) {
  if (!menu || !name || !callback ||
      menu->config.entry_count >= UI_MENU_MAX_ENTRIES)
    return false;

  int idx = menu->config.entry_count;
  menu->config.entries[idx].callback = callback;
  menu->config.entries[idx].enabled = true;

  menu->buttons[idx] = lv_btn_create(menu->list);
  lv_obj_add_event_cb(menu->buttons[idx], menu_button_event_cb,
                      LV_EVENT_CLICKED, menu);
  theme_apply_touch_button(menu->buttons[idx], true);

  lv_obj_t *label = lv_label_create(menu->buttons[idx]);
  lv_label_set_text(label, name);
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_pad_ver(label, 15, 0);
  lv_obj_center(label);
  theme_apply_button_label(label, false);

  menu->config.entry_count++;
  refresh_menu_layout(menu);
  return true;
}

static void action_button_event_cb(lv_event_t *e) {
  ui_menu_t *menu = (ui_menu_t *)lv_event_get_user_data(e);
  lv_obj_t *btn = lv_event_get_target(e);
  int idx = (int)(intptr_t)lv_obj_get_user_data(btn);
  if (idx >= 0 && idx < menu->config.entry_count &&
      menu->config.entries[idx].action_callback)
    menu->config.entries[idx].action_callback(idx);
}

bool ui_menu_add_entry_with_action(ui_menu_t *menu, const char *name,
                                   ui_menu_callback_t callback,
                                   const char *action_icon,
                                   ui_menu_action_callback_t action_cb) {
  if (!menu || !name || !callback || !action_icon || !action_cb ||
      menu->config.entry_count >= UI_MENU_MAX_ENTRIES)
    return false;

  int idx = menu->config.entry_count;
  menu->config.entries[idx].callback = callback;
  menu->config.entries[idx].action_callback = action_cb;
  menu->config.entries[idx].enabled = true;

  /* Main button — row layout */
  menu->buttons[idx] = lv_btn_create(menu->list);
  lv_obj_set_flex_flow(menu->buttons[idx], LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(menu->buttons[idx], LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(menu->buttons[idx], 0, 0);
  /* Flush the action icon to the right edge of the row */
  lv_obj_set_style_pad_right(menu->buttons[idx], 0, 0);
  lv_obj_add_event_cb(menu->buttons[idx], menu_button_event_cb,
                      LV_EVENT_CLICKED, menu);
  theme_apply_touch_button(menu->buttons[idx], true);

  /* Label on the left */
  lv_obj_t *label = lv_label_create(menu->buttons[idx]);
  lv_label_set_text(label, name);
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_obj_set_flex_grow(label, 1);
  lv_obj_set_style_pad_ver(label, 15, 0);
  lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
  theme_apply_button_label(label, false);

  /* Action icon button on the right. It stretches vertically because menu
     buttons have explicit row heights in both portrait and landscape. */
  lv_obj_t *icon_btn = lv_btn_create(menu->buttons[idx]);
  lv_obj_set_size(icon_btn, theme_get_min_touch_size(), LV_PCT(100));
  lv_obj_set_style_bg_color(icon_btn, disabled_color(), 0);
  lv_obj_set_style_bg_opa(icon_btn, LV_OPA_COVER, 0);
  lv_obj_set_style_shadow_width(icon_btn, 0, 0);
  lv_obj_set_style_border_width(icon_btn, 0, 0);
  lv_obj_set_style_pad_hor(icon_btn, 0, 0);
  lv_obj_set_style_pad_ver(icon_btn, 15, 0);
  lv_obj_clear_flag(icon_btn, LV_OBJ_FLAG_EVENT_BUBBLE);
  lv_obj_set_user_data(icon_btn, (void *)(intptr_t)idx);
  lv_obj_add_event_cb(icon_btn, action_button_event_cb, LV_EVENT_CLICKED, menu);

  lv_obj_t *icon_label = lv_label_create(icon_btn);
  lv_label_set_text(icon_label, action_icon);
  lv_obj_center(icon_label);
  lv_obj_set_style_text_color(icon_label, error_color(), 0);

  menu->config.entry_count++;
  refresh_menu_layout(menu);
  return true;
}

bool ui_menu_set_entry_enabled(ui_menu_t *menu, int index, bool enabled) {
  if (!menu || index < 0 || index >= menu->config.entry_count)
    return false;

  menu->config.entries[index].enabled = enabled;
  if (enabled) {
    lv_obj_clear_state(menu->buttons[index], LV_STATE_DISABLED);
  } else {
    lv_obj_add_state(menu->buttons[index], LV_STATE_DISABLED);
  }

  /* Update label color to reflect enabled/disabled state */
  lv_obj_t *label = entry_label(menu, index);
  if (label) {
    lv_obj_set_style_text_color(label,
                                enabled ? main_color() : disabled_color(), 0);
  }
  return true;
}

bool ui_menu_set_entry_label(ui_menu_t *menu, int index, const char *name) {
  lv_obj_t *label = entry_label(menu, index);
  if (!label || !name)
    return false;

  lv_label_set_text(label, name);
  apply_entry_label_layout(menu, index);
  return true;
}

bool ui_menu_set_entry_text_color(ui_menu_t *menu, int index,
                                  lv_color_t color) {
  lv_obj_t *label = entry_label(menu, index);
  if (!label)
    return false;

  lv_obj_set_style_text_color(label, color, 0);
  return true;
}

int ui_menu_get_entry_count(const ui_menu_t *menu) {
  return menu ? menu->config.entry_count : 0;
}

int ui_menu_get_selected(ui_menu_t *menu) {
  return menu ? menu->config.selected_index : -1;
}

void ui_menu_set_title_visible(ui_menu_t *menu, bool visible) {
  if (!menu || !menu->title_label)
    return;

  if (visible) {
    lv_obj_clear_flag(menu->title_label,
                      LV_OBJ_FLAG_HIDDEN | LV_OBJ_FLAG_IGNORE_LAYOUT);
  } else {
    lv_obj_add_flag(menu->title_label,
                    LV_OBJ_FLAG_HIDDEN | LV_OBJ_FLAG_IGNORE_LAYOUT);
  }
}

lv_obj_t *ui_menu_get_container(ui_menu_t *menu) {
  return menu ? menu->container : NULL;
}

lv_obj_t *ui_menu_get_nav_bar(ui_menu_t *menu) {
  return menu ? menu->nav_bar : NULL;
}

void ui_menu_show(ui_menu_t *menu) {
  if (menu && menu->container)
    lv_obj_clear_flag(menu->container, LV_OBJ_FLAG_HIDDEN);
}

void ui_menu_hide(ui_menu_t *menu) {
  if (menu && menu->container)
    lv_obj_add_flag(menu->container, LV_OBJ_FLAG_HIDDEN);
}

void ui_menu_destroy(ui_menu_t *menu) {
  if (!menu)
    return;
  if (menu->back_btn)
    lv_obj_del(menu->back_btn);
  if (menu->container)
    lv_obj_del(menu->container);
  free(menu);
}
