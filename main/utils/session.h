// Inactivity monitoring — screensaver overlay and session lock

#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>

typedef void (*session_expired_cb_t)(void);
typedef void (*session_screensaver_cb_t)(void);

/* Create the 1s inactivity timer. Call once at boot, after LVGL is up. */
void session_init(session_screensaver_cb_t saver_cb,
                  session_expired_cb_t expired_cb);

/* Inactivity before the screensaver overlay appears. 0 = off. */
void session_set_screensaver_timeout(uint16_t sec);

/* Inactivity before the session expires (device locks). 0 = off. */
void session_set_timeout(uint16_t sec);

#endif // SESSION_H
