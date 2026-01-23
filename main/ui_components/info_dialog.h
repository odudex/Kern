#ifndef INFO_DIALOG_H
#define INFO_DIALOG_H

/**
 * Callback function type for info dialog response
 * @param user_data Optional user data passed to the callback
 */
typedef void (*info_dialog_callback_t)(void *user_data);

/**
 * Show a fullscreen info dialog with OK button
 * @param title The dialog title (can be NULL for no title)
 * @param message The message to display
 * @param callback The callback function to call when OK is pressed
 * @param user_data Optional user data passed to the callback
 */
void show_info_dialog(const char *title, const char *message,
                      info_dialog_callback_t callback, void *user_data);

/**
 * Show an overlay info dialog with OK button (semi-transparent, centered)
 * @param title The dialog title (can be NULL for no title)
 * @param message The message to display
 * @param callback The callback function to call when OK is pressed
 * @param user_data Optional user data passed to the callback
 */
void show_info_dialog_overlay(const char *title, const char *message,
                              info_dialog_callback_t callback, void *user_data);

#endif // INFO_DIALOG_H
