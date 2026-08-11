#ifndef DIALOG_H
#define DIALOG_H

#include <lvgl.h>
#include <stdbool.h>

typedef enum {
  DIALOG_INFO,
  DIALOG_ERROR,
  DIALOG_CONFIRM,
} dialog_type_t;

typedef enum {
  DIALOG_STYLE_FULLSCREEN,
  DIALOG_STYLE_OVERLAY,
} dialog_style_t;

typedef void (*dialog_callback_t)(void *user_data);
typedef void (*dialog_simple_callback_t)(void);
typedef void (*dialog_confirm_callback_t)(bool confirmed, void *user_data);

void dialog_show_info(const char *title, const char *message,
                      dialog_callback_t callback, void *user_data,
                      dialog_style_t style);

/* Same layout as dialog_show_info, with the single button carrying the given
   label — for acknowledgements where "OK" understates what is being agreed. */
void dialog_show_acknowledge(const char *title, const char *message,
                             const char *button_text,
                             dialog_callback_t callback, void *user_data,
                             dialog_style_t style);

void dialog_show_error_timeout(const char *message,
                               dialog_simple_callback_t callback,
                               int timeout_ms);

void dialog_show_confirm(const char *message,
                         dialog_confirm_callback_t callback, void *user_data,
                         dialog_style_t style);

void dialog_show_danger_confirm(const char *message,
                                dialog_confirm_callback_t callback,
                                void *user_data, dialog_style_t style);

#define DIALOG_SENSITIVE_DATA_WARNING                                          \
  "Sensitive data will be displayed on screen, make sure no one can see it.\n" \
  "Proceed?"

void dialog_show_message(const char *title, const char *message);

/**
 * Show a buttonless progress dialog (e.g. "Wiping Flash...", "Encrypting...").
 * Returns the root object — caller must lv_obj_del() it when done.
 */
lv_obj_t *dialog_show_progress(const char *title, const char *message,
                               dialog_style_t style);

#endif
