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

static pthread_mutex_t s_lvgl_mutex;
static pthread_once_t s_lvgl_mutex_once = PTHREAD_ONCE_INIT;
static pthread_t s_main_thread;
static volatile bool s_main_thread_set = false;

static void init_lvgl_mutex(void) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&s_lvgl_mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    s_main_thread = pthread_self();
    s_main_thread_set = true;
}

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
    pthread_once(&s_lvgl_mutex_once, init_lvgl_mutex);

    /* Main thread uses recursive lock (re-entrant from LVGL callbacks).
     * Background threads (camera stream) use trylock so they never block
     * the main thread during page-destroy waits. */
    if (s_main_thread_set && pthread_equal(pthread_self(), s_main_thread)) {
        return pthread_mutex_lock(&s_lvgl_mutex) == 0;
    }

    if (timeout_ms == 0) {
        /* Background thread: use a short timed lock so the stream thread
         * can acquire the lock between lv_timer_handler() calls, without
         * blocking long enough to deadlock during page-destroy waits. */
        timeout_ms = 10;
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

/**
 * Wrapper for lv_refr_now() — linked via --wrap=lv_refr_now.
 *
 * Camera frame callbacks call lv_refr_now() from background threads to force
 * an immediate display update.  On the real device this works because the
 * display driver writes directly to the LCD.  With SDL2, rendering must happen
 * on the main thread; calling from a background thread silently fails but
 * clears LVGL's dirty state, preventing the main thread from ever rendering
 * the update.
 *
 * Making this a no-op lets lv_img_set_src() mark the widget dirty, and the
 * main loop's lv_timer_handler() picks it up on the next iteration (~30 fps).
 */
void __wrap_lv_refr_now(lv_display_t *disp) {
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

bool bsp_display_lock(uint32_t timeout_ms) {
    return lvgl_port_lock(timeout_ms);
}

void bsp_display_unlock(void) {
    lvgl_port_unlock();
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
    /* Return a non-NULL dummy handle so callers (scanner, capture_entropy)
     * don't bail out.  app_video_main() ignores the handle in the simulator. */
    return (i2c_master_bus_handle_t)1;
}
