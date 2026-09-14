#pragma once

/* LVGL-thread-only ownership registry. Register before a flow allocates any
 * state; unregister at the beginning of its idempotent destructor. */
typedef void (*session_cleanup_fn)(void);
void session_cleanup_register(session_cleanup_fn cleanup);
void session_cleanup_unregister(session_cleanup_fn cleanup);
void session_cleanup_run(void);
