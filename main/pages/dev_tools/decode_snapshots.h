#ifndef DECODE_SNAPSHOTS_H
#define DECODE_SNAPSHOTS_H

#ifdef K_QUIRC_DEBUG

#include <lvgl.h>

void decode_snapshots_page_create(lv_obj_t *parent, void (*return_cb)(void));
void decode_snapshots_page_show(void);
void decode_snapshots_page_hide(void);
void decode_snapshots_page_destroy(void);

#endif /* K_QUIRC_DEBUG */

#endif /* DECODE_SNAPSHOTS_H */
