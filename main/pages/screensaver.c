#include "screensaver.h"
#include "ui/assets/kern_logo_lvgl.h"
#include "ui/theme_widgets.h"
#include <esp_random.h>

static lv_obj_t *scr_container;
static lv_obj_t *logo;
static lv_obj_t *lock_label;
static lv_obj_t *touch_layer;
static screensaver_dismiss_cb_t dismiss_cb;
static bool active;

static void start_cycle(void);

static void cycle_done_cb(lv_anim_t *anim) {
  (void)anim;
  if (active)
    start_cycle();
}

static void start_cycle(void) {
  int32_t scr_w = theme_screen_width();
  int32_t scr_h = theme_screen_height();
  int32_t logo_sz = lv_obj_get_width(logo);
  // The lock hint rides below the logo; keep both on screen.
  int32_t extra = lock_label ? lv_obj_get_height(lock_label) * 2 : 0;
  int32_t x = esp_random() % LV_MAX(scr_w - logo_sz, 1);
  int32_t y = esp_random() % LV_MAX(scr_h - logo_sz - extra, 1);
  lv_obj_set_pos(logo, x, y);
  if (lock_label)
    lv_obj_align_to(lock_label, logo, LV_ALIGN_OUT_BOTTOM_MID, 0, 0);
  kern_logo_fade_cycle(logo, cycle_done_cb, NULL);
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

void screensaver_create(lv_obj_t *parent, screensaver_dismiss_cb_t cb,
                        bool locked) {
  if (active)
    screensaver_destroy();

  dismiss_cb = cb;
  active = true;

  int32_t scr_w = theme_screen_width();
  int32_t scr_h = theme_screen_height();
  int32_t logo_sz = theme_logo_size();

  scr_container = lv_obj_create(parent);
  lv_obj_remove_style_all(scr_container);
  lv_obj_set_size(scr_container, scr_w, scr_h);
  theme_apply_screen(scr_container);

  logo = kern_logo_create(scr_container, 0, 0, logo_sz);

  if (locked) {
    lock_label = lv_label_create(scr_container);
    lv_label_set_text(lock_label, "Locked");
    lv_obj_set_style_text_font(lock_label, theme_font_small(), 0);
    lv_obj_set_style_text_color(lock_label, secondary_color(), 0);
    lv_obj_update_layout(lock_label);
  }

  touch_layer = lv_obj_create(scr_container);
  lv_obj_remove_style_all(touch_layer);
  lv_obj_set_size(touch_layer, scr_w, scr_h);
  lv_obj_add_flag(touch_layer, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(touch_layer, touch_cb, LV_EVENT_PRESSED, NULL);

  start_cycle();
}

bool screensaver_is_active(void) { return active; }

void screensaver_destroy(void) {
  active = false;
  if (!scr_container)
    return;
  // Stop the ring fade before teardown so no animation callback fires during
  // the async dismiss; deleting the container then cascades to the rings.
  kern_logo_stop_fade(logo);
  lv_obj_delete(scr_container);
  scr_container = NULL;
  logo = NULL;
  lock_label = NULL;
  touch_layer = NULL;
  dismiss_cb = NULL;
}
