#ifndef QR_VIEWER_H
#define QR_VIEWER_H

#include <lvgl.h>

/**
 * Create the QR viewer page
 * @param parent Parent LVGL object
 * @param qr_content Content to display as QR code
 * @param title Optional title to display (can be NULL)
 * @param return_cb Callback function to call when returning
 */
void qr_viewer_page_create(lv_obj_t *parent, const char *qr_content,
                           const char *title, void (*return_cb)(void));

/**
 * Create the QR viewer page with format support
 * @param parent Parent LVGL object
 * @param qr_format QR format (FORMAT_NONE, FORMAT_PMOFN, FORMAT_UR)
 * @param content Content or base64 PSBT string
 * @param title Optional title to display (can be NULL)
 * @param return_cb Callback function to call when returning
 * @return true on success, false on failure
 */
bool qr_viewer_page_create_with_format(lv_obj_t *parent, int qr_format,
                                       const char *content, const char *title,
                                       void (*return_cb)(void));

/**
 * Make a widget open the QR viewer fullscreen when tapped (tap again to
 * return). Copies content/title; frees them when the widget is deleted.
 * @param obj Widget to make tappable (e.g. a small QR container)
 * @param content Content to display as QR code
 * @param title Optional title to display (can be NULL)
 */
void qr_viewer_attach_fullscreen(lv_obj_t *obj, const char *content,
                                 const char *title);

/**
 * Show the QR viewer page
 */
void qr_viewer_page_show(void);

/**
 * Hide the QR viewer page
 */
void qr_viewer_page_hide(void);

/**
 * Destroy the QR viewer page and free resources
 */
void qr_viewer_page_destroy(void);

#endif
