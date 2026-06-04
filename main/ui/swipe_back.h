#ifndef SWIPE_BACK_H
#define SWIPE_BACK_H

#include <lvgl.h>

// Attach swipe-to-go-back gesture to a screen object.
// back_cb is called (no args) when the swipe threshold is met.
// Do NOT call this on security-sensitive pages.
void swipe_back_attach(lv_obj_t *screen, void (*back_cb)(void));

#endif
