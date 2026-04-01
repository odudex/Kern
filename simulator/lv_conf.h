/**
 * LVGL configuration for Kern Desktop Simulator
 * Based on lv_conf_template.h for LVGL v9.3.0
 */

#ifndef LV_CONF_H
#define LV_CONF_H

/*====================
   COLOR SETTINGS
 *====================*/

#define LV_COLOR_DEPTH 16

/*=========================
   STDLIB WRAPPER SETTINGS
 *=========================*/

#define LV_USE_STDLIB_MALLOC    LV_STDLIB_CLIB
#define LV_USE_STDLIB_STRING    LV_STDLIB_CLIB
#define LV_USE_STDLIB_SPRINTF   LV_STDLIB_CLIB

/*====================
   HAL SETTINGS
 *====================*/

#define LV_DEF_REFR_PERIOD 15
#define LV_DPI_DEF 130

/*=================
 * OPERATING SYSTEM
 *=================*/

#define LV_USE_OS LV_OS_PTHREAD

/*========================
 * RENDERING CONFIGURATION
 *========================*/

#define LV_DRAW_SW_DRAW_UNIT_CNT 1

/*=======================
 * FEATURE CONFIGURATION
 *=======================*/

#define LV_FONT_MONTSERRAT_14 1
#define LV_FONT_MONTSERRAT_24 1
#define LV_FONT_MONTSERRAT_36 1

/*==================
 * WIDGETS
 *==================*/

#define LV_USE_CANVAS 1

/*==================
 * EXTRAS
 *==================*/

#define LV_USE_QRCODE 1

/*====================
 * DEMOS AND EXAMPLES
 *====================*/

#define LV_BUILD_EXAMPLES 0

/*===================
 * SDL DISPLAY DRIVER
 *===================*/

#define LV_USE_SDL 1
#define LV_SDL_RENDER_MODE LV_DISPLAY_RENDER_MODE_DIRECT
#define LV_SDL_BUF_COUNT 1

#endif /* LV_CONF_H */
