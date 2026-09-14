#ifndef UI_ONESHOT_H
#define UI_ONESHOT_H

#include <lvgl.h>

/* One-shot LVGL timer that forgets its handle when it fires, so an owner can
 * cancel it at teardown without knowing whether it already ran. */
typedef struct {
  lv_timer_t *timer;
  lv_timer_cb_t cb;
} ui_oneshot_t;

/* Replaces any pending call on `s`. */
void ui_oneshot_start(ui_oneshot_t *s, lv_timer_cb_t cb, uint32_t delay_ms);
void ui_oneshot_cancel(ui_oneshot_t *s);

#endif
