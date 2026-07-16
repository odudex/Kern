#ifndef SCREENSAVER_H
#define SCREENSAVER_H

#include <lvgl.h>

typedef void (*screensaver_dismiss_cb_t)(void);

/* `hint` (NULL for none) is shown under the logo so the lock face is
 * distinguishable from the plain inactivity overlay. */
void screensaver_create(lv_obj_t *parent, screensaver_dismiss_cb_t dismiss_cb,
                        const char *hint);
void screensaver_destroy(void);
bool screensaver_is_active(void);

#endif /* SCREENSAVER_H */
