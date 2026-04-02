/**
 * Kern Desktop Simulator — Entry Point
 *
 * Mirrors the initialization sequence from main/main.c but uses
 * SDL2 for display and mouse input instead of ESP32-P4 hardware.
 */

#include "lvgl.h"
#include "src/drivers/sdl/lv_sdl_window.h"
#include "src/drivers/sdl/lv_sdl_mouse.h"
#include "ui/theme.h"
#include "ui/assets/kern_logo_lvgl.h"
#include "core/settings.h"
#include "core/pin.h"
#include "core/session.h"
#include "pages/pin/pin_page.h"
#include "pages/login/login.h"
#include "ui/nav.h"
#include "utils/bip39_filter.h"
#include <wally_core.h>
#include <nvs_flash.h>
#include <esp_err.h>
#include "sim_video.h"
#include "sim_nvs.h"
#include "sim_sdcard.h"
#include <SDL2/SDL.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include "esp_log.h"

#ifndef SIM_LCD_H_RES
#define SIM_LCD_H_RES 720
#endif
#ifndef SIM_LCD_V_RES
#define SIM_LCD_V_RES 720
#endif

/* -------------------------------------------------------------------------- */
/* Forward declarations                                                        */
/* -------------------------------------------------------------------------- */
static void splash_done_cb(lv_timer_t *t);
static void post_unlock_cb(void);
static void session_expired_handler(void);

/* -------------------------------------------------------------------------- */
/* Session expiry handler                                                      */
/* -------------------------------------------------------------------------- */

static void session_expired_handler(void) {
    /* Lock device: clear screen and show PIN unlock page */
    lv_obj_t *scr = lv_screen_active();
    lv_obj_clean(scr);
    pin_page_create(scr, PIN_PAGE_UNLOCK, post_unlock_cb, NULL);
}

/* -------------------------------------------------------------------------- */
/* Post-unlock callback                                                        */
/* -------------------------------------------------------------------------- */

static void post_unlock_cb(void) {
    pin_page_destroy();

    /* Start session timeout */
    uint16_t timeout = pin_get_session_timeout();
    if (timeout > 0)
        session_start(timeout);

    /* Show login page (wallet selector / main menu) */
    lv_obj_t *scr = lv_screen_active();
    lv_obj_clean(scr);
    nav_init(scr);
    login_page_create(scr);
}

/* -------------------------------------------------------------------------- */
/* Splash → PIN transition (fired by one-shot LVGL timer after 3 s)          */
/* -------------------------------------------------------------------------- */

static void splash_done_cb(lv_timer_t *t) {
    lv_timer_delete(t);

    lv_obj_t *scr = lv_screen_active();
    lv_obj_clean(scr);

    if (pin_is_configured()) {
        pin_page_create(scr, PIN_PAGE_UNLOCK, post_unlock_cb, NULL);
    } else {
        nav_init(scr);
        login_page_create(scr);
    }
}

/* -------------------------------------------------------------------------- */
/* Main                                                                        */
/* -------------------------------------------------------------------------- */

static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Kern Desktop Simulator\n\n");
    printf("Options:\n");
    printf("  -q, --qr-image <path>   Load QR image for camera simulation\n");
    printf("  -Q, --qr-dir <path>     Load QR images from directory\n");
    printf("  -d, --data-dir <path>   Data directory (default: simulator/sim_data/)\n");
    printf("  -W, --width <N>         Display width in pixels (default: %d)\n", SIM_LCD_H_RES);
    printf("  -H, --height <N>        Display height in pixels (default: %d)\n", SIM_LCD_V_RES);
    printf("  -v, --verbose           Enable DEBUG-level logging\n");
    printf("  -h, --help              Show this help\n");
}

int main(int argc, char *argv[]) {
    /* Parse CLI arguments before any init */
    static const struct option long_opts[] = {
        { "qr-image", required_argument, NULL, 'q' },
        { "qr-dir",   required_argument, NULL, 'Q' },
        { "data-dir", required_argument, NULL, 'd' },
        { "width",    required_argument, NULL, 'W' },
        { "height",   required_argument, NULL, 'H' },
        { "verbose",  no_argument,       NULL, 'v' },
        { "help",     no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    int sim_width = SIM_LCD_H_RES;
    int sim_height = SIM_LCD_V_RES;
    int opt;
    while ((opt = getopt_long(argc, argv, "q:Q:d:W:H:vh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'q':
                sim_video_set_qr_image(optarg);
                break;
            case 'Q':
                sim_video_set_qr_dir(optarg);
                break;
            case 'd': {
                char nvs_path[512];
                snprintf(nvs_path, sizeof(nvs_path), "%s/nvs", optarg);
                sim_nvs_set_data_dir(nvs_path);
                sim_sdcard_set_data_dir(optarg);
                break;
            }
            case 'W':
                sim_width = atoi(optarg);
                break;
            case 'H':
                sim_height = atoi(optarg);
                break;
            case 'v':
                esp_log_level_set("*", ESP_LOG_DEBUG);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                fprintf(stderr,
                    "Usage: %s [--qr-image PATH] [--qr-dir DIR] [--data-dir DIR]"
                    " [--width N] [--height N] [--verbose]\n",
                    argv[0]);
                return 1;
        }
    }

    printf("Kern Simulator starting (%dx%d)\n", sim_width, sim_height);

    /* Initialize libwally-core */
    if (wally_init(0) != WALLY_OK) {
        fprintf(stderr, "wally_init failed\n");
        return 1;
    }

    /* Initialize LVGL */
    lv_init();

    /* Create SDL2 display */
    lv_display_t *disp = lv_sdl_window_create(sim_width, sim_height);
    if (!disp) {
        fprintf(stderr, "Failed to create SDL display\n");
        return 1;
    }

    lv_sdl_window_set_title(disp, "Kern Simulator");

    /* Create SDL2 mouse input */
    lv_indev_t *mouse = lv_sdl_mouse_create();
    (void)mouse;

    /* Initialize theme (copies Montserrat fonts, sets icon fallbacks) */
    theme_init();

    /* Apply dark background and default text style to screen */
    lv_obj_t *scr = lv_screen_active();
    theme_apply_screen(scr);

    /* Force initial render */
    lv_refr_now(NULL);

    /* -----------------------------------------------------------------------
     * Initialize NVS (file-backed storage for settings and PIN)
     * --------------------------------------------------------------------- */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        ret = nvs_flash_init();
    }
    if (ret != ESP_OK) {
        fprintf(stderr, "NVS init failed: 0x%x\n", ret);
        return 1;
    }

    /* Initialize persistent settings */
    settings_init();

    /* -----------------------------------------------------------------------
     * Show animated Kern logo splash screen
     * --------------------------------------------------------------------- */
    kern_logo_animated(scr);

    /* -----------------------------------------------------------------------
     * Initialize application modules (while splash plays)
     * --------------------------------------------------------------------- */
    bip39_filter_init();
    pin_init();

    /* Register session expiry callback */
    session_set_expired_callback(session_expired_handler);

    /* -----------------------------------------------------------------------
     * Schedule transition to PIN gate after 3-second splash
     * (single-threaded: use one-shot LVGL timer instead of vTaskDelay)
     * --------------------------------------------------------------------- */
    lv_timer_t *splash_timer = lv_timer_create(splash_done_cb, 3000, NULL);
    lv_timer_set_repeat_count(splash_timer, 1);

    /* -----------------------------------------------------------------------
     * Main loop
     * SDL_QUIT is handled by LVGL's SDL driver which calls exit(0)
     * --------------------------------------------------------------------- */
    while (1) {
        uint32_t ms_til_next = lv_timer_handler();
        SDL_Delay(ms_til_next < 1 ? 1 : ms_til_next);
    }

    return 0;
}
