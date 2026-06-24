#ifndef NUMERIC_KEYPAD_H
#define NUMERIC_KEYPAD_H

#include <lvgl.h>
#include <stdint.h>

typedef struct ui_numeric_keypad_s ui_numeric_keypad_t;

typedef void (*ui_numeric_keypad_submit_cb)(uint32_t value, void *user_data);
typedef void (*ui_numeric_keypad_cancel_cb)(void *user_data);

typedef struct {
  const char *title;
  uint32_t initial_value;
  uint32_t min_value;
  uint32_t max_value;
  uint8_t max_digits;
  const char *invalid_message;
  ui_numeric_keypad_submit_cb submit_cb;
  ui_numeric_keypad_cancel_cb cancel_cb;
  void *user_data;
} ui_numeric_keypad_config_t;

void ui_numeric_keypad_open(ui_numeric_keypad_t **handle,
                            const ui_numeric_keypad_config_t *config);
void ui_numeric_keypad_close(ui_numeric_keypad_t **handle);

#endif // NUMERIC_KEYPAD_H
