// Session lock — inactivity screensaver and lock/power-off routing shared by
// the device (main.c) and simulator (main_sim.c) entry points

#ifndef SESSION_LOCK_H
#define SESSION_LOCK_H

#include <lvgl.h>

/* Wire inactivity monitoring (screensaver + session lock). Call once at boot
 * with the LVGL lock held, after settings_init() and pin_init(). */
void session_lock_init(void);

/* Show the boot gate on `screen`: PIN unlock page if a PIN is configured,
 * otherwise the login page. */
void session_lock_boot_gate(lv_obj_t *screen);

#endif // SESSION_LOCK_H
