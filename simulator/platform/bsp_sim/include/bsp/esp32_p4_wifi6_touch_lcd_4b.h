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
#include "esp_lvgl_port.h"
#include "lvgl.h"

#define BSP_LCD_DRAW_BUFF_SIZE   (BSP_LCD_H_RES * BSP_LCD_V_RES / 4)
#define BSP_LCD_DRAW_BUFF_DOUBLE 0

typedef struct {
    lvgl_port_cfg_t lvgl_port_cfg;
    uint32_t buffer_size;
    bool double_buffer;
    struct {
        unsigned int buff_dma    : 1;
        unsigned int buff_spiram : 1;
        unsigned int sw_rotate   : 1;
    } flags;
} bsp_display_cfg_t;

lv_display_t *bsp_display_start(void);
lv_display_t *bsp_display_start_with_config(const bsp_display_cfg_t *cfg);
lv_indev_t   *bsp_display_get_input_dev(void);
bool          bsp_display_lock(uint32_t timeout_ms);
void          bsp_display_unlock(void);
#endif /* BSP_CONFIG_NO_GRAPHIC_LIB */

esp_err_t               bsp_i2c_init(void);
esp_err_t               bsp_i2c_deinit(void);
i2c_master_bus_handle_t bsp_i2c_get_handle(void);
