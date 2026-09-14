#pragma once
#include "esp_lcd_panel_ops.h"
#include <stddef.h>

/* Register all retained DSI scanout banks at display initialization. */
void bsp_display_register_sensitive_buffers(esp_lcd_panel_handle_t panel,
                                            unsigned count, size_t bytes);
/* LVGL must have finished rendering/flushing before calling this. */
void bsp_display_scrub_buffers(void);
