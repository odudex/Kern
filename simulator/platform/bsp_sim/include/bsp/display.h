#pragma once
#include "esp_err.h"
#include <stdint.h>

#ifndef SIM_LCD_H_RES
#define SIM_LCD_H_RES 720
#endif
#ifndef SIM_LCD_V_RES
#define SIM_LCD_V_RES 720
#endif

#define BSP_LCD_H_RES            SIM_LCD_H_RES
#define BSP_LCD_V_RES            SIM_LCD_V_RES
#define BSP_LCD_BITS_PER_PIXEL   16
#define BSP_LCD_COLOR_FORMAT     1  /* RGB565 */

esp_err_t bsp_display_brightness_init(void);
esp_err_t bsp_display_brightness_set(int brightness_percent);
esp_err_t bsp_display_backlight_on(void);
esp_err_t bsp_display_backlight_off(void);
