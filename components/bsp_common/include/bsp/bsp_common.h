#pragma once

#include "bsp/config.h"
#include "bsp/display_types.h"
#include "bsp/touch.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "esp_err.h"
#include "esp_lcd_mipi_dsi.h"
#include "esp_lcd_panel_ops.h"
#include "esp_ldo_regulator.h"
#include <stdbool.h>
#include <stdint.h>

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
#include "esp_lv_adapter.h"
#include "lvgl.h"
#endif

/* Hold an ESP32-C6 co-processor in reset (GPIO_NUM_NC logs a no-op). */
esp_err_t bsp_common_wifi_coproc_disable(gpio_num_t en_gpio);

/* Shared I2C master bus lifecycle. */
esp_err_t bsp_common_i2c_init(i2c_port_num_t port, gpio_num_t sda,
                              gpio_num_t scl, bool internal_pullup);
esp_err_t bsp_common_i2c_deinit(void);
i2c_master_bus_handle_t bsp_common_i2c_get_handle(void);
esp_err_t bsp_common_i2c_probe(uint8_t addr);

/* LEDC PWM backlight (shared by all GPIO-backlit boards). */
typedef struct {
  gpio_num_t gpio_num;
  bool output_invert;
  int min_duty_percent; /* 0 for linear 0..100%; e.g. 47 for wave_4b */
} bsp_ledc_backlight_cfg_t;

esp_err_t bsp_common_backlight_ledc_init(const bsp_ledc_backlight_cfg_t *cfg);
esp_err_t bsp_common_backlight_ledc_set(int brightness_percent);

/* Idempotent internal LDO rail enable (no-op when chan_id <= 0). */
esp_err_t bsp_common_ldo_enable(int chan_id, int voltage_mv,
                                esp_ldo_channel_handle_t *handle_slot);

/* MIPI-DSI bus + DBI IO + panel bringup shared by all DSI boards. */
typedef esp_err_t (*bsp_dsi_panel_create_fn)(esp_lcd_dsi_bus_handle_t dsi_bus,
                                             esp_lcd_panel_io_handle_t io,
                                             uint8_t bits_per_pixel,
                                             lcd_color_format_t color_fmt,
                                             esp_lcd_panel_handle_t *ret_panel);

typedef struct {
  int phy_ldo_chan;
  int phy_ldo_mv;
  uint8_t lane_num;
  uint32_t lane_bitrate_mbps;
  esp_err_t (*pre_bus_init)(void); /* optional board power-rail hook */
  bsp_dsi_panel_create_fn create_panel;
  bool mirror_180;
} bsp_dsi_display_cfg_t;

esp_err_t bsp_common_dsi_display_init(const bsp_dsi_display_cfg_t *cfg,
                                      bsp_lcd_handles_t *ret_handles);

/* GT911 touch bringup shared by all GT911 boards. */
typedef struct {
  uint16_t x_max;
  uint16_t y_max;
  gpio_num_t rst_gpio_num;
  gpio_num_t int_gpio_num;
  bool mirror_x;
  bool mirror_y;
  bool probe_backup_addr;  /* probe 0x5D then 0x14 */
  bool pass_driver_data;   /* attach esp_lcd_touch_io_gt911_config_t */
  bool manual_reset_retry; /* 200 ms settling + 3x retry (wave_4b) */
} bsp_gt911_touch_cfg_t;

esp_err_t bsp_common_touch_gt911_new(const bsp_gt911_touch_cfg_t *cfg,
                                     esp_lcd_touch_handle_t *ret_touch);

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
typedef struct {
  uint16_t h_res;
  uint16_t v_res;
  uint8_t bits_per_pixel;
  bool is_mipi_dsi; /* true: MIPI-DSI + sensitive buffer scrub; false: SPI */
  bool use_psram;   /* false for DSI, true for wave_35 SPI */
} bsp_lvgl_display_cfg_t;

lv_display_t *bsp_common_display_start(const bsp_lvgl_display_cfg_t *cfg);
#endif
