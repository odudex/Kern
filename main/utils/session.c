// Session timeout — locks device after user inactivity

#include "session.h"
#include <lvgl.h>

static lv_timer_t *session_timer = NULL;
static session_expired_cb_t expired_cb = NULL;
static uint32_t timeout_ms = 0;

static void session_timer_cb(lv_timer_t *timer) {
  (void)timer;
  if (timeout_ms == 0 || !expired_cb)
    return;

  uint32_t inactive = lv_display_get_inactive_time(NULL);
  if (inactive >= timeout_ms) {
    session_stop();
    expired_cb();
  }
}

void session_start(uint16_t timeout_sec) {
  session_stop();

  if (timeout_sec == 0)
    return;

  timeout_ms = (uint32_t)timeout_sec * 1000;
  session_timer = lv_timer_create(session_timer_cb, 1000, NULL);
}

void session_stop(void) {
  if (session_timer) {
    lv_timer_delete(session_timer);
    session_timer = NULL;
  }
  timeout_ms = 0;
}

void session_set_expired_callback(session_expired_cb_t cb) { expired_cb = cb; }
