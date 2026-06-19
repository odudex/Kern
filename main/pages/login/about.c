// About Page

#include "about.h"
#include "../../qr/encoder.h"
#include "../../ui/assets/kern_logo_lvgl.h"
#include "../../ui/theme_widgets.h"
#include <esp_app_desc.h>
#include <lvgl.h>
#include <stdio.h>
#include <string.h>

static lv_obj_t *about_screen = NULL;
static void (*return_callback)(void) = NULL;

static void about_screen_event_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

static void create_return_touch_layer(lv_obj_t *parent) {
  lv_obj_t *touch = lv_obj_create(parent);
  lv_obj_remove_style_all(touch);
  lv_obj_set_size(touch, LV_PCT(100), LV_PCT(100));
  lv_obj_add_flag(touch, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_clear_flag(touch, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(touch, about_screen_event_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_move_foreground(touch);
}

void about_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;

  int32_t pad = theme_default_padding();
  int32_t min_dim = theme_min_dim();
  int32_t font_h = lv_font_get_line_height(theme_font_small());
  bool landscape = theme_is_landscape();

  about_screen = theme_create_page_container(parent);

  // Title pinned at top
  theme_create_page_title(about_screen, "About");

  // Footer pinned at bottom
  lv_obj_t *footer = theme_create_label(about_screen, "Tap to return", true);
  lv_obj_align(footer, LV_ALIGN_BOTTOM_MID, 0, -pad);

  // Flex body between title and footer. Landscape lays out logo+version next to
  // the QR; portrait/square stacks them vertically.
  lv_obj_t *body = lv_obj_create(about_screen);
  lv_obj_remove_style_all(body);
  lv_obj_set_size(body, LV_PCT(100),
                  LV_MAX(1, theme_screen_height() - 2 * (font_h + 2 * pad)));
  lv_obj_align(body, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_flex_flow(body,
                       landscape ? LV_FLEX_FLOW_ROW : LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(body, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(body, LV_OBJ_FLAG_CLICKABLE);

  const esp_app_desc_t *app_desc = esp_app_get_description();
  char ver_text[48];
  snprintf(ver_text, sizeof(ver_text), "Version: %s", app_desc->version);

  // The body's main axis (width in landscape, height in portrait) is shared
  // between the logo block and the QR; the cross axis is free. Give each item
  // up to half the main axis so neither dominates.
  lv_obj_update_layout(body);
  int32_t main_extent = landscape ? lv_obj_get_content_width(body)
                                  : lv_obj_get_content_height(body);
  int32_t cross_extent = landscape ? lv_obj_get_content_height(body)
                                   : lv_obj_get_content_width(body);
  int32_t item_budget = (main_extent - 3 * pad) / 2;

  // Landscape stacks the logo + version in a column beside the QR; portrait
  // adds them straight into the vertical body flow.
  lv_obj_t *logo_parent = body;
  if (landscape) {
    logo_parent = lv_obj_create(body);
    lv_obj_remove_style_all(logo_parent);
    lv_obj_set_size(logo_parent, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(logo_parent, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(logo_parent, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_row(logo_parent, pad, 0);
  }

  // The inline logo block scales with its diameter. Build it at the default
  // size, measure its footprint on the shared axis, and rebuild it smaller if
  // it would exceed the per-item budget so it stays balanced with the QR.
  int32_t logo_sz = theme_logo_size() * 160 / 200;
  lv_obj_t *logo = kern_logo_with_text_inline_sized(logo_parent, logo_sz);
  lv_obj_update_layout(body);
  int32_t block_main =
      landscape ? lv_obj_get_width(logo) : lv_obj_get_height(logo);
  if (block_main > item_budget) {
    logo_sz = LV_MAX(logo_sz * item_budget / block_main, logo_sz / 3);
    lv_obj_del(logo);
    logo = kern_logo_with_text_inline_sized(logo_parent, logo_sz);
  }

  lv_obj_t *ver_label = theme_create_label(logo_parent, ver_text, true);
  lv_obj_update_layout(body);

  // QR takes the leftover main-axis space, capped by the cross axis so the
  // square always fits. Reserving 2*pad keeps a gap between the items.
  const int32_t qr_border = 10;
  int32_t used =
      landscape
          ? lv_obj_get_width(logo_parent)
          : (lv_obj_get_height(logo) + lv_obj_get_height(ver_label) + pad);
  int32_t qr_total = LV_MIN(main_extent - used - 2 * pad, cross_extent);
  qr_total = LV_CLAMP(min_dim / 6, qr_total, min_dim * 25 / 72); // <=250 @ 720

  lv_obj_t *qr = qr_create_optimal(body, LV_MAX(qr_total - 2 * qr_border, 1),
                                   "https://github.com/odudex/Kern");
  lv_obj_set_style_border_color(qr, lv_color_white(), 0);
  lv_obj_set_style_border_width(qr, qr_border, 0);

  create_return_touch_layer(about_screen);
}

void about_page_show(void) {
  if (about_screen)
    lv_obj_clear_flag(about_screen, LV_OBJ_FLAG_HIDDEN);
}

void about_page_hide(void) {
  if (about_screen)
    lv_obj_add_flag(about_screen, LV_OBJ_FLAG_HIDDEN);
}

void about_page_destroy(void) {
  if (about_screen) {
    lv_obj_del(about_screen);
    about_screen = NULL;
  }
  return_callback = NULL;
}
