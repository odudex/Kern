/**
 * BSP Simulator — implements esp_lvgl_port and BSP display stubs
 */

#include "esp_lvgl_port.h"
#include "bsp/esp32_p4_wifi6_touch_lcd_4b.h"
#include "esp_log.h"

#include "src/drivers/sdl/lv_sdl_window.h"
#include "src/drivers/sdl/lv_sdl_mouse.h"

#include <pthread.h>
#include <time.h>

static const char *TAG = "BSP_SIM";

static pthread_mutex_t s_lvgl_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Saved indev for bsp_display_get_input_dev() */
static lv_indev_t *s_mouse_indev = NULL;

/* ---------- lvgl_port API ---------- */

esp_err_t lvgl_port_init(const lvgl_port_cfg_t *cfg) {
    (void)cfg;
    return ESP_OK;
}

esp_err_t lvgl_port_deinit(void) {
    return ESP_OK;
}

bool lvgl_port_lock(uint32_t timeout_ms) {
    if (timeout_ms == 0) {
        pthread_mutex_lock(&s_lvgl_mutex);
        return true;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += (long)(timeout_ms / 1000);
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    return pthread_mutex_timedlock(&s_lvgl_mutex, &ts) == 0;
}

void lvgl_port_unlock(void) {
    pthread_mutex_unlock(&s_lvgl_mutex);
}

void lvgl_port_flush_ready(lv_display_t *disp) {
    (void)disp;
}

/* ---------- BSP display stubs ---------- */

lv_display_t *bsp_display_start(void) {
    bsp_display_cfg_t cfg = {
        .lvgl_port_cfg = ESP_LVGL_PORT_INIT_CONFIG(),
        .buffer_size   = BSP_LCD_DRAW_BUFF_SIZE,
        .double_buffer = BSP_LCD_DRAW_BUFF_DOUBLE,
        .flags = { .buff_dma = 0, .buff_spiram = 0, .sw_rotate = 0 },
    };
    return bsp_display_start_with_config(&cfg);
}

lv_display_t *bsp_display_start_with_config(const bsp_display_cfg_t *cfg) {
    (void)cfg;
    lv_display_t *disp = lv_sdl_window_create(BSP_LCD_H_RES, BSP_LCD_V_RES);
    if (disp) {
        lv_sdl_window_set_title(disp, "Kern Simulator");
    }
    s_mouse_indev = lv_sdl_mouse_create();
    return disp;
}

lv_indev_t *bsp_display_get_input_dev(void) {
    return s_mouse_indev;
}

esp_err_t bsp_display_brightness_init(void) {
    return ESP_OK;
}

esp_err_t bsp_display_brightness_set(int pct) {
    ESP_LOGI(TAG, "brightness_set(%d)", pct);
    return ESP_OK;
}

esp_err_t bsp_display_backlight_on(void) {
    return ESP_OK;
}

esp_err_t bsp_display_backlight_off(void) {
    return ESP_OK;
}

/* ---------- I2C stubs ---------- */

esp_err_t bsp_i2c_init(void) {
    return ESP_OK;
}

esp_err_t bsp_i2c_deinit(void) {
    return ESP_OK;
}

i2c_master_bus_handle_t bsp_i2c_get_handle(void) {
    return NULL;
}
