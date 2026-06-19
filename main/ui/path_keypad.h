#ifndef PATH_KEYPAD_H
#define PATH_KEYPAD_H

#include <lvgl.h>
#include <stddef.h>

typedef struct ui_path_keypad_s ui_path_keypad_t;

typedef void (*ui_path_keypad_submit_cb)(const char *path, void *user_data);
typedef void (*ui_path_keypad_cancel_cb)(void *user_data);

typedef struct {
  const char *title;
  const char *initial_path; // e.g. "m/48'/0'/0'/2'"; the "m/" prefix is fixed
  size_t max_depth;         // path components allowed (0 = default 10)
  const char *invalid_message;
  ui_path_keypad_submit_cb submit_cb;
  ui_path_keypad_cancel_cb cancel_cb;
  void *user_data;
} ui_path_keypad_config_t;

void ui_path_keypad_open(ui_path_keypad_t **handle,
                         const ui_path_keypad_config_t *config);
void ui_path_keypad_close(ui_path_keypad_t **handle);

#endif // PATH_KEYPAD_H
