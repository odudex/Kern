// Session lock — inactivity screensaver and lock/power-off routing shared by
// the device (main.c) and simulator (main_sim.c) entry points

#ifndef SESSION_LOCK_H
#define SESSION_LOCK_H

#include <lvgl.h>

/* Wire inactivity monitoring (screensaver + session lock). Call once at boot
 * with the LVGL lock held, after settings_init() and pin_init(). */
void session_lock_init(void);

/* Tear down sensitive state and render the lock face before shutdown/reboot.
 * Call on the LVGL thread. Does not itself power off the device. */
void session_lock_now(void);

/* Leave the lock face rendered by session_lock_now() and show the gate again
 * (PIN unlock or login), as a tap on the lock face would. */
void session_lock_dismiss(void);

/* Show the boot gate on `screen`: PIN unlock page if a PIN is configured,
 * otherwise the login page. */
void session_lock_boot_gate(lv_obj_t *screen);

/* Re-sync session/screensaver timeouts from settings. Call after NVS content
 * is replaced wholesale (encryption provisioning wipes settings). */
void session_lock_reload_settings(void);

#endif // SESSION_LOCK_H
