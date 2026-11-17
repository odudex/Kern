/**
 * Address label shown next to an address QR code.
 */

#ifndef ADDRESS_LABEL_H
#define ADDRESS_LABEL_H

#include "lvgl.h"

/**
 * Create a wrapped, centered label showing `address` in 4-char blocks with
 * alternating primary/highlight colors. Tapping it cycles the display through
 * 4-char blocks, 6-char blocks and the plain address. The label keeps its own
 * copy of `address`. The caller sets the width.
 *
 * @param parent  Parent LVGL object
 * @param address Address to display
 * @return The label object
 */
lv_obj_t *address_label_create(lv_obj_t *parent, const char *address);

#endif // ADDRESS_LABEL_H
