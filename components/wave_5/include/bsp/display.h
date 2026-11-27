#pragma once
#include "bsp/display_types.h"
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

#define BSP_LCD_H_RES (720)
#define BSP_LCD_V_RES (1280)
#define BSP_LCD_MIPI_DSI_LANE_BITRATE_MBPS (700)

#define BSP_LCD_MIPI_DSI_LANE_NUM (2)
#define BSP_MIPI_DSI_PHY_PWR_LDO_CHAN (3)
#define BSP_MIPI_DSI_PHY_PWR_LDO_VOLTAGE_MV (2500)
