#include "bsp/display_security.h"
#include "esp_check.h"
#include "esp_lcd_mipi_dsi.h"
#include "secure_memory.h"
#include <stdlib.h>

static void *framebuffers[3];
static unsigned framebuffer_count;
static size_t framebuffer_bytes;

void bsp_display_register_sensitive_buffers(esp_lcd_panel_handle_t panel,
                                            unsigned count, size_t bytes) {
  if (count == 0 || count > 3)
    abort();
  ESP_ERROR_CHECK(esp_lcd_dpi_panel_get_frame_buffer(
      panel, count, &framebuffers[0], &framebuffers[1], &framebuffers[2]));
  framebuffer_count = count;
  framebuffer_bytes = bytes;
}

void bsp_display_scrub_buffers(void) {
  for (unsigned i = 0; i < framebuffer_count; ++i)
    kern_memory_wipe(framebuffers[i], framebuffer_bytes);
}
