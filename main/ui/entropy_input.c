#include "entropy_input.h"

#include "../core/entropy_pool.h"

#include <lvgl.h>

static void indev_event_cb(lv_event_t *e) {
  lv_indev_t *indev = lv_event_get_indev(e);
  if (!indev)
    return;

  // Press timing carries more than the coordinates do; the cycle counter
  // sampled inside entropy_pool_stir() is what captures it.
  lv_point_t point;
  lv_indev_get_point(indev, &point);
  entropy_pool_stir(((uint32_t)point.x << 16) ^ (uint32_t)point.y);
}

void entropy_input_attach(void) {
  for (lv_indev_t *indev = lv_indev_get_next(NULL); indev;
       indev = lv_indev_get_next(indev))
    lv_indev_add_event_cb(indev, indev_event_cb, LV_EVENT_PRESSED, NULL);
}
