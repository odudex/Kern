/**
 * Kern Logo - Minimal "Essential Point" Design
 * Creates a core point with subtle rings representing the "kernel/core"
 * concept.
 */

#include "../theme.h"
#include "kern_logo_font.h"
#include "lvgl.h"

#define INNER_RING_PCT 63
#define CORE_PCT 33
/* Gap between logo and text as percentage of logo diameter (matches branding)
 */
#define TEXT_GAP_PCT 21

static lv_obj_t *create_circle(lv_obj_t *parent, int32_t diameter,
                               int32_t border) {
  lv_obj_t *obj = lv_obj_create(parent);
  lv_obj_remove_style_all(obj);
  lv_obj_set_size(obj, diameter, diameter);
  lv_obj_center(obj);
  lv_obj_set_style_radius(obj, LV_RADIUS_CIRCLE, 0);
  if (border) {
    lv_obj_set_style_bg_opa(obj, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_color(obj, highlight_color(), 0);
    lv_obj_set_style_border_width(obj, border, 0);
  } else {
    lv_obj_set_style_bg_color(obj, highlight_color(), 0);
    lv_obj_set_style_bg_opa(obj, LV_OPA_COVER, 0);
  }
  return obj;
}

static lv_obj_t *create_label(lv_obj_t *parent) {
  lv_obj_t *label = lv_label_create(parent);
  lv_label_set_text(label, "KERN");
  lv_obj_set_style_text_font(label, &kern_logo_100, 0);
  lv_obj_set_style_text_color(label, main_color(), 0);
  lv_obj_set_style_text_letter_space(label, -1, 0);
  return label;
}

static lv_obj_t *create_flex_container(lv_obj_t *parent, lv_align_t align,
                                       int32_t gap) {
  lv_obj_t *c = lv_obj_create(parent);
  lv_obj_remove_style_all(c);
  lv_obj_set_size(c, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(c, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(c, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(c, gap, 0);
  lv_obj_align(c, align, 0, 0);
  return c;
}

static void anim_opa_cb(void *var, int32_t value) {
  lv_obj_set_style_opa((lv_obj_t *)var, (lv_opa_t)value, 0);
}

static void start_fade_anim(lv_obj_t *obj, uint32_t duration, uint32_t delay) {
  lv_obj_set_style_opa(obj, LV_OPA_TRANSP, 0);
  lv_anim_t anim;
  lv_anim_init(&anim);
  lv_anim_set_var(&anim, obj);
  lv_anim_set_exec_cb(&anim, anim_opa_cb);
  lv_anim_set_values(&anim, LV_OPA_TRANSP, LV_OPA_COVER);
  lv_anim_set_duration(&anim, duration);
  lv_anim_set_delay(&anim, delay);
  lv_anim_start(&anim);
}

/** Create logo symbol only */
lv_obj_t *kern_logo_create(lv_obj_t *parent, int32_t x, int32_t y,
                           int32_t size) {
  lv_obj_t *c = lv_obj_create(parent);
  lv_obj_remove_style_all(c);
  lv_obj_set_size(c, size, size);
  lv_obj_set_pos(c, x, y);

  int32_t t = LV_MAX(size / 200, 1);
  create_circle(c, size, t);
  create_circle(c, size * INNER_RING_PCT / 100, t * 2);
  create_circle(c, size * CORE_PCT / 100, 0);

  return c;
}

/** Create logo with text, horizontally centered at top */
lv_obj_t *kern_logo_with_text(lv_obj_t *parent, int32_t x, int32_t y) {
  int32_t logo_size = 160;
  lv_obj_t *c = create_flex_container(parent, LV_ALIGN_TOP_MID,
                                      logo_size * TEXT_GAP_PCT / 100);
  lv_obj_align(c, LV_ALIGN_TOP_MID, x, y);
  kern_logo_create(c, 0, 0, logo_size);
  create_label(c);
  return c;
}

/** Animated logo with text for boot screen, vertically centered */
void kern_logo_animated(lv_obj_t *parent) {
  int32_t size = 200;
  int32_t t = LV_MAX(size / 80, 1);

  lv_obj_t *c =
      create_flex_container(parent, LV_ALIGN_CENTER, size * TEXT_GAP_PCT / 100);

  lv_obj_t *logo = lv_obj_create(c);
  lv_obj_remove_style_all(logo);
  lv_obj_set_size(logo, size, size);

  lv_obj_t *label = create_label(c);

  lv_obj_t *outer = create_circle(logo, size, t);
  lv_obj_t *inner = create_circle(logo, size * INNER_RING_PCT / 100, t * 2);
  lv_obj_t *core = create_circle(logo, size * CORE_PCT / 100, 0);

  start_fade_anim(core, 1000, 0);
  start_fade_anim(inner, 1000, 500);
  start_fade_anim(outer, 1000, 700);
  start_fade_anim(label, 1000, 800);
}
