// Session timeout — locks device after user inactivity

#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>

typedef void (*session_expired_cb_t)(void);

/* Start monitoring inactivity. timeout_sec=0 disables the timer. */
void session_start(uint16_t timeout_sec);

/* Stop monitoring (e.g. when PIN is removed). */
void session_stop(void);

/* Register callback invoked when session expires. */
void session_set_expired_callback(session_expired_cb_t cb);

#endif // SESSION_H
