#pragma once
#include "bsp/display_types.h"
#include "sdkconfig.h"

/* LCD color formats */
#define ESP_LCD_COLOR_FORMAT_RGB565 (1)
#define ESP_LCD_COLOR_FORMAT_RGB888 (2)

/* LCD display color format */
#define BSP_LCD_COLOR_FORMAT (ESP_LCD_COLOR_FORMAT_RGB565)
/* LCD display color bytes endianness */
#define BSP_LCD_BIGENDIAN (1)
/* LCD display color bits */
#define BSP_LCD_BITS_PER_PIXEL (16)
/* LCD display color space */
#define BSP_LCD_COLOR_SPACE (ESP_LCD_COLOR_SPACE_RGB)

#define BSP_LCD_H_RES (320)
#define BSP_LCD_V_RES (480)
