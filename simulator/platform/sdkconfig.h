/**
 * Simulator sdkconfig.h
 * Provides CONFIG_* defines that application code expects from ESP-IDF Kconfig
 */

#pragma once

/* Display */
#define CONFIG_BSP_LCD_COLOR_FORMAT_RGB565 1

/* FreeRTOS */
#define CONFIG_FREERTOS_HZ 1000

/* Cache line size (used for PPA buffer alignment in scanner.c) */
#define CONFIG_CACHE_L2_CACHE_LINE_SIZE 64

/* I2C */
#define CONFIG_BSP_I2C_NUM 0
