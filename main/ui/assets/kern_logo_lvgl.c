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

static int32_t scale_for_height(int32_t source_h, int32_t target_h) {
  return LV_MAX((target_h * LV_SCALE_NONE + source_h / 2) / source_h, 1);
}

static int32_t scale_value(int32_t value, int32_t scale) {
  return (value * scale + LV_SCALE_NONE - 1) / LV_SCALE_NONE;
}

/* Diameter for a ring of the given percentage that stays concentric with the
 * full-size container: (size - diameter) must be even so lv_obj_center places
 * it on the exact same pixel as the outer ring instead of 0.5px off. */
static int32_t ring_diameter(int32_t size, int32_t pct) {
  int32_t d = size * pct / 100;
  if ((size - d) & 1)
    d--;
  return d;
}

static lv_obj_t *create_circle(lv_obj_t *parent, int32_t diameter,
                               int32_t border) {
  lv_obj_t *obj = lv_obj_create(parent);
  lv_obj_remove_style_all(obj);
  lv_obj_clear_flag(obj, LV_OBJ_FLAG_CLICKABLE);
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

static lv_obj_t *create_label(lv_obj_t *parent, int32_t logo_size) {
  const lv_font_t *font = &kern_logo_100;
  int32_t target_h = logo_size * INNER_RING_PCT / 120;
  int32_t scale = scale_for_height(lv_font_get_line_height(font), target_h);

  lv_obj_t *label_box = lv_obj_create(parent);
  lv_obj_remove_style_all(label_box);
  lv_obj_clear_flag(label_box, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_flag(label_box, LV_OBJ_FLAG_OVERFLOW_VISIBLE);

  lv_obj_t *label = lv_label_create(label_box);
  lv_label_set_text(label, "KERN");
  lv_obj_set_style_text_font(label, font, 0);
  lv_obj_set_style_text_color(label, main_color(), 0);
  lv_obj_set_style_text_letter_space(label, -1, 0);
  lv_obj_update_layout(label);

  lv_obj_set_style_transform_pivot_x(label, 0, 0);
  lv_obj_set_style_transform_pivot_y(label, 0, 0);
  lv_obj_set_style_transform_scale(label, scale, 0);
  lv_obj_set_size(label_box, scale_value(lv_obj_get_width(label), scale),
                  target_h);

  return label_box;
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
  lv_obj_clear_flag(c, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_set_size(c, size, size);
  lv_obj_set_pos(c, x, y);
  // The outer ring fills the container exactly; without this its anti-aliased
  // edge is clipped on the right/bottom and the ring looks off-centre.
  lv_obj_add_flag(c, LV_OBJ_FLAG_OVERFLOW_VISIBLE);

  int32_t t = LV_MAX(size / 200, 1);
  create_circle(c, size, t);
  create_circle(c, ring_diameter(size, INNER_RING_PCT), t * 2);
  create_circle(c, ring_diameter(size, CORE_PCT), 0);

  return c;
}

/* Staggered ring fade shared by the screensaver and the in-place login pulse,
 * so both stay visually identical. */
#define LOGO_FADE 1500
#define LOGO_STAGGER 600
#define LOGO_HOLD 1500

static void fade_ring(lv_obj_t *ring, uint32_t delay, uint32_t playback_delay,
                      lv_anim_completed_cb_t done, void *user_data) {
  lv_anim_t a;
  lv_anim_init(&a);
  lv_anim_set_var(&a, ring);
  lv_anim_set_user_data(&a, user_data);
  lv_anim_set_exec_cb(&a, anim_opa_cb);
  lv_anim_set_values(&a, LV_OPA_TRANSP, LV_OPA_COVER);
  lv_anim_set_duration(&a, LOGO_FADE);
  lv_anim_set_delay(&a, delay);
  lv_anim_set_playback_duration(&a, LOGO_FADE);
  lv_anim_set_playback_delay(&a, playback_delay);
  if (done)
    lv_anim_set_completed_cb(&a, done);
  lv_anim_start(&a);
}

void kern_logo_fade_cycle(lv_obj_t *logo, lv_anim_completed_cb_t done_cb,
                          void *user_data) {
  // Pre-set transparent so the staggered (delayed) rings don't flash at full
  // opacity before their fade-in begins.
  for (int i = 0; i < 3; i++)
    lv_obj_set_style_opa(lv_obj_get_child(logo, i), LV_OPA_TRANSP, 0);
  // Children order from kern_logo_create: [0]=outer, [1]=inner, [2]=core.
  // Playback delay = time from a ring's fade-in end to its fade-out start; the
  // core fades out last so its done_cb marks the end of the whole cycle.
  fade_ring(lv_obj_get_child(logo, 2), 0, LOGO_HOLD + 4 * LOGO_STAGGER, done_cb,
            user_data);
  fade_ring(lv_obj_get_child(logo, 1), LOGO_STAGGER,
            LOGO_HOLD + 2 * LOGO_STAGGER, NULL, NULL);
  fade_ring(lv_obj_get_child(logo, 0), 2 * LOGO_STAGGER, LOGO_HOLD, NULL, NULL);
}

/* Stop a fade cycle by removing the opacity animations from the logo's three
 * rings, so nothing keeps invalidating (and forcing redraws) once the logo is
 * hidden or about to be destroyed. Safe on a logo that isn't animating. */
void kern_logo_stop_fade(lv_obj_t *logo) {
  if (!logo)
    return;
  for (int i = 0; i < 3; i++) {
    lv_obj_t *ring = lv_obj_get_child(logo, i);
    if (ring)
      lv_anim_delete(ring, anim_opa_cb);
  }
}

/** Logo + "KERN" wordmark as a flex-friendly child, with an explicit logo
 *  diameter so the caller can scale the whole block to fit a layout budget. */
lv_obj_t *kern_logo_with_text_inline_sized(lv_obj_t *parent, int32_t sz) {
  lv_obj_t *c = lv_obj_create(parent);
  lv_obj_remove_style_all(c);
  lv_obj_clear_flag(c, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_set_size(c, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(c, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(c, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(c, sz * TEXT_GAP_PCT / 100, 0);
  kern_logo_create(c, 0, 0, sz);
  create_label(c, sz);
  return c;
}

/** Animated logo with text for boot screen, vertically centered */
void kern_logo_animated(lv_obj_t *parent) {
  int32_t size = theme_get_logo_size();
  int32_t t = LV_MAX(size / 80, 1);

  lv_obj_t *c =
      create_flex_container(parent, LV_ALIGN_CENTER, size * TEXT_GAP_PCT / 100);

  lv_obj_t *logo = lv_obj_create(c);
  lv_obj_remove_style_all(logo);
  lv_obj_set_size(logo, size, size);

  lv_obj_t *label = create_label(c, size);

  lv_obj_t *outer = create_circle(logo, size, t);
  lv_obj_t *inner =
      create_circle(logo, ring_diameter(size, INNER_RING_PCT), t * 2);
  lv_obj_t *core = create_circle(logo, ring_diameter(size, CORE_PCT), 0);

  start_fade_anim(core, 1000, 0);
  start_fade_anim(inner, 1000, 500);
  start_fade_anim(outer, 1000, 700);
  start_fade_anim(label, 1000, 800);
}
