#pragma once

#include "esp_err.h"
#include "esp_lcd_mipi_dsi.h"
#include "esp_lcd_types.h"

typedef struct {
  int dummy;
} bsp_display_config_t;

typedef struct {
  esp_lcd_dsi_bus_handle_t mipi_dsi_bus;
  esp_lcd_panel_io_handle_t io;
  esp_lcd_panel_handle_t panel;
  esp_lcd_panel_handle_t control;
} bsp_lcd_handles_t;

esp_err_t bsp_display_new(const bsp_display_config_t *config,
                          esp_lcd_panel_handle_t *ret_panel,
                          esp_lcd_panel_io_handle_t *ret_io);
esp_err_t bsp_display_new_with_handles(const bsp_display_config_t *config,
                                       bsp_lcd_handles_t *ret_handles);
esp_err_t bsp_display_brightness_init(void);
esp_err_t bsp_display_brightness_set(int brightness_percent);
esp_err_t bsp_display_backlight_on(void);
esp_err_t bsp_display_backlight_off(void);
