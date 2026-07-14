// Inactivity monitoring — screensaver overlay and session lock

#include "session.h"
#include <lvgl.h>

static session_screensaver_cb_t screensaver_cb = NULL;
static session_expired_cb_t expired_cb = NULL;
static uint32_t screensaver_ms = 0;
static uint32_t session_ms = 0;
static bool expired_fired = false;
static bool screensaver_fired = false;

static void session_timer_cb(lv_timer_t *timer) {
  (void)timer;
  uint32_t inactive = lv_display_get_inactive_time(NULL);

  if (session_ms && expired_cb && inactive >= session_ms) {
    if (!expired_fired) {
      expired_fired = true;
      expired_cb();
    }
    return;
  }
  expired_fired = false;

  if (screensaver_ms && screensaver_cb && inactive >= screensaver_ms) {
    if (!screensaver_fired) {
      screensaver_fired = true;
      screensaver_cb();
    }
    return;
  }
  screensaver_fired = false;
}

void session_init(session_screensaver_cb_t saver_cb,
                  session_expired_cb_t exp_cb) {
  screensaver_cb = saver_cb;
  expired_cb = exp_cb;
  lv_timer_create(session_timer_cb, 1000, NULL);
}

void session_set_screensaver_timeout(uint16_t sec) {
  screensaver_ms = (uint32_t)sec * 1000;
  // A timeout change counts as activity so shrinking below the accrued
  // inactivity can't fire on the next tick.
  lv_display_trigger_activity(NULL);
}

void session_set_timeout(uint16_t sec) {
  session_ms = (uint32_t)sec * 1000;
  lv_display_trigger_activity(NULL);
}
