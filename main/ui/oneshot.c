#include "oneshot.h"

static void oneshot_cb(lv_timer_t *timer) {
  ui_oneshot_t *s = lv_timer_get_user_data(timer);
  lv_timer_cb_t cb = s->cb;
  s->timer = NULL;
  s->cb = NULL;
  if (cb)
    cb(timer);
}

void ui_oneshot_start(ui_oneshot_t *s, lv_timer_cb_t cb, uint32_t delay_ms) {
  ui_oneshot_cancel(s);
  s->cb = cb;
  s->timer = lv_timer_create(oneshot_cb, delay_ms, s);
  lv_timer_set_repeat_count(s->timer, 1);
}

void ui_oneshot_cancel(ui_oneshot_t *s) {
  if (s->timer)
    lv_timer_delete(s->timer);
  s->timer = NULL;
  s->cb = NULL;
}
