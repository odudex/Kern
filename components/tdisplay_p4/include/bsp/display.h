#pragma once
#include "esp_lcd_mipi_dsi.h"
#include "esp_lcd_types.h"
#include "sdkconfig.h"

/* LCD color formats */
#define ESP_LCD_COLOR_FORMAT_RGB565 (1)
#define ESP_LCD_COLOR_FORMAT_RGB888 (2)

/* LCD display color format */
#if CONFIG_BSP_LCD_COLOR_FORMAT_RGB888
#define BSP_LCD_COLOR_FORMAT (ESP_LCD_COLOR_FORMAT_RGB888)
#else
#define BSP_LCD_COLOR_FORMAT (ESP_LCD_COLOR_FORMAT_RGB565)
#endif
/* LCD display color bytes endianess */
#define BSP_LCD_BIGENDIAN (0)
/* LCD display color bits */
#define BSP_LCD_BITS_PER_PIXEL (16)
/* LCD display color space */
#define BSP_LCD_COLOR_SPACE (LCD_RGB_ELEMENT_ORDER_RGB)

/* RM69A10 AMOLED, portrait 568x1232 */
#define BSP_LCD_H_RES (568)
#define BSP_LCD_V_RES (1232)

/* MIPI-DSI: 2 data lanes, 1000 Mbps/lane, DPI pixel clock 60 MHz
 * (from LilyGO t_display_p4_config.h, rm69a10 namespace). */
#define BSP_LCD_MIPI_DSI_LANE_NUM (2)
#define BSP_LCD_MIPI_DSI_LANE_BITRATE_MBPS (1000)
#define BSP_LCD_DPI_CLK_MHZ (60)

/* DPI video timing (RM69A10) */
#define BSP_LCD_DPI_HSYNC (50)
#define BSP_LCD_DPI_HBP (150)
#define BSP_LCD_DPI_HFP (50)
#define BSP_LCD_DPI_VSYNC (40)
#define BSP_LCD_DPI_VBP (120)
#define BSP_LCD_DPI_VFP (80)

/* MIPI DSI PHY power LDO (ESP32-P4 internal LDO channel 3 @ 2.5 V) */
#define BSP_MIPI_DSI_PHY_PWR_LDO_CHAN (3)
#define BSP_MIPI_DSI_PHY_PWR_LDO_VOLTAGE_MV (2500)

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
