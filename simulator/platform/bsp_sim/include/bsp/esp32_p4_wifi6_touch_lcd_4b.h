#pragma once
#include "bsp/config.h"
#include "bsp/display.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"

/* GPIO defines matching the real BSP */
#define BSP_I2C_SCL (GPIO_NUM_8)
#define BSP_I2C_SDA (GPIO_NUM_7)
#define BSP_LCD_BACKLIGHT (GPIO_NUM_26)
#define BSP_LCD_RST (GPIO_NUM_27)
#define BSP_LCD_TOUCH_RST (GPIO_NUM_23)
#define BSP_LCD_TOUCH_INT (GPIO_NUM_NC)

#if (BSP_CONFIG_NO_GRAPHIC_LIB == 0)
#include "lvgl.h"

lv_display_t *bsp_display_start(void);
bool          bsp_display_lock(uint32_t timeout_ms);
void          bsp_display_unlock(void);
#endif /* BSP_CONFIG_NO_GRAPHIC_LIB */

esp_err_t               bsp_i2c_init(void);
esp_err_t               bsp_i2c_deinit(void);
i2c_master_bus_handle_t bsp_i2c_get_handle(void);
