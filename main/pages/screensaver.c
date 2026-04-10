#include "screensaver.h"
#include "ui/assets/kern_logo_lvgl.h"
#include "ui/theme.h"
#include <esp_random.h>

#define FADE_IN 1500
#define STAGGER 600
#define HOLD 1500
#define FADE_OUT 1500

static lv_obj_t *scr_container;
static lv_obj_t *logo;
static lv_obj_t *core;
static lv_obj_t *inner;
static lv_obj_t *outer;
static lv_obj_t *touch_layer;
static screensaver_dismiss_cb_t dismiss_cb;
static bool active;

static void anim_opa_cb(void *var, int32_t value) {
  lv_obj_set_style_opa((lv_obj_t *)var, (lv_opa_t)value, 0);
}

static void start_cycle(void);

static void cycle_done_cb(lv_anim_t *anim) {
  if (!active)
    return;
  start_cycle();
}

static void start_anim(lv_obj_t *obj, uint32_t delay, uint32_t playback_delay,
                       lv_anim_completed_cb_t done_cb) {
  lv_anim_t a;
  lv_anim_init(&a);
  lv_anim_set_var(&a, obj);
  lv_anim_set_exec_cb(&a, anim_opa_cb);
  lv_anim_set_values(&a, LV_OPA_TRANSP, LV_OPA_COVER);
  lv_anim_set_duration(&a, FADE_IN);
  lv_anim_set_delay(&a, delay);
  lv_anim_set_playback_duration(&a, FADE_OUT);
  lv_anim_set_playback_delay(&a, playback_delay);
  if (done_cb)
    lv_anim_set_completed_cb(&a, done_cb);
  lv_anim_start(&a);
}

static void start_cycle(void) {
  int32_t scr_w = theme_get_screen_width();
  int32_t scr_h = theme_get_screen_height();
  int32_t logo_sz = lv_obj_get_width(logo);
  int32_t x = esp_random() % LV_MAX(scr_w - logo_sz, 1);
  int32_t y = esp_random() % LV_MAX(scr_h - logo_sz, 1);
  lv_obj_set_pos(logo, x, y);

  // Playback delay = time from this circle's fade-in end to its fade-out start
  start_anim(core, 0, HOLD + 4 * STAGGER, cycle_done_cb);
  start_anim(inner, STAGGER, HOLD + 2 * STAGGER, NULL);
  start_anim(outer, 2 * STAGGER, HOLD, NULL);
}

static void deferred_dismiss(void *user_data) {
  screensaver_dismiss_cb_t cb = dismiss_cb;
  screensaver_destroy();
  if (cb)
    cb();
}

static void touch_cb(lv_event_t *e) {
  if (!active)
    return;
  active = false;
  lv_async_call(deferred_dismiss, NULL);
}

void screensaver_create(lv_obj_t *parent, screensaver_dismiss_cb_t cb) {
  if (active)
    screensaver_destroy();

  dismiss_cb = cb;
  active = true;

  int32_t scr_w = theme_get_screen_width();
  int32_t scr_h = theme_get_screen_height();
  int32_t logo_sz = theme_get_logo_size();

  scr_container = lv_obj_create(parent);
  lv_obj_remove_style_all(scr_container);
  lv_obj_set_size(scr_container, scr_w, scr_h);
  theme_apply_screen(scr_container);

  // kern_logo_create children: [0]=outer ring, [1]=inner ring, [2]=core
  logo = kern_logo_create(scr_container, 0, 0, logo_sz);
  outer = lv_obj_get_child(logo, 0);
  inner = lv_obj_get_child(logo, 1);
  core = lv_obj_get_child(logo, 2);
  lv_obj_set_style_opa(outer, LV_OPA_TRANSP, 0);
  lv_obj_set_style_opa(inner, LV_OPA_TRANSP, 0);
  lv_obj_set_style_opa(core, LV_OPA_TRANSP, 0);

  touch_layer = lv_obj_create(scr_container);
  lv_obj_remove_style_all(touch_layer);
  lv_obj_set_size(touch_layer, scr_w, scr_h);
  lv_obj_add_flag(touch_layer, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(touch_layer, touch_cb, LV_EVENT_PRESSED, NULL);

  start_cycle();
}

void screensaver_destroy(void) {
  active = false;
  if (!scr_container)
    return;
  lv_anim_delete(core, anim_opa_cb);
  lv_anim_delete(inner, anim_opa_cb);
  lv_anim_delete(outer, anim_opa_cb);
  lv_obj_delete(scr_container);
  scr_container = NULL;
  logo = NULL;
  core = NULL;
  inner = NULL;
  outer = NULL;
  touch_layer = NULL;
  dismiss_cb = NULL;
}
