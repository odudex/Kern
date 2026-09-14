#include "display_cleanup.h"
#include "secure_memory.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lvgl.h>
/* LVGL 9.5: public API exposes only the active draw buffer. Cleanup must
 * include inactive banks too. Keep this dependency explicit and tested. */
#include <src/display/lv_display_private.h>
#ifdef ESP_PLATFORM
#include <bsp/display_security.h>
#endif

void ui_display_scrub(void) {
  lv_display_t *disp = lv_display_get_default();
  if (!disp)
    return;
  if (disp->flushing && disp->flush_wait_cb) {
    disp->flush_wait_cb(disp);
    disp->flushing = 0;
  }
  while (disp->flushing)
    vTaskDelay(1);

  lv_draw_buf_t *buffers[] = {disp->buf_1, disp->buf_2, disp->buf_3};
  for (unsigned i = 0; i < 3; ++i)
    if (buffers[i])
      kern_memory_wipe(buffers[i]->data, buffers[i]->data_size);
#ifdef ESP_PLATFORM
  bsp_display_scrub_buffers();
#endif
}
