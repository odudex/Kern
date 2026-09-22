/*
 * UI Keyboard Component
 * A grid-based keyboard using lv_buttonmatrix for letter input
 * with support for enabling/disabling individual keys
 */

#ifndef KEYBOARD_H
#define KEYBOARD_H

#include <lvgl.h>
#include <stdbool.h>

// Keyboard key indices (for enable/disable)
#define UI_KB_KEY_A 0
#define UI_KB_KEY_B 1
#define UI_KB_KEY_C 2
#define UI_KB_KEY_D 3
#define UI_KB_KEY_E 4
#define UI_KB_KEY_F 5
#define UI_KB_KEY_G 6
#define UI_KB_KEY_H 7
#define UI_KB_KEY_I 8
#define UI_KB_KEY_J 9
#define UI_KB_KEY_K 10
#define UI_KB_KEY_L 11
#define UI_KB_KEY_M 12
#define UI_KB_KEY_N 13
#define UI_KB_KEY_O 14
#define UI_KB_KEY_P 15
#define UI_KB_KEY_Q 16
#define UI_KB_KEY_R 17
#define UI_KB_KEY_S 18
#define UI_KB_KEY_T 19
#define UI_KB_KEY_U 20
#define UI_KB_KEY_V 21
#define UI_KB_KEY_W 22
#define UI_KB_KEY_X 23
#define UI_KB_KEY_Y 24
#define UI_KB_KEY_Z 25
#define UI_KB_KEY_BACKSPACE 26
#define UI_KB_KEY_OK 27
#define UI_KB_KEY_COUNT 28

// Special key values returned by callbacks
#define UI_KB_BACKSPACE '\b'
#define UI_KB_OK '\n'

// Callback function type for key presses
// Returns the character pressed ('a'-'z', UI_KB_BACKSPACE, or UI_KB_OK)
typedef void (*ui_keyboard_callback_t)(char key);

// Keyboard structure
typedef struct {
  lv_obj_t *container;
  lv_obj_t *btnmatrix;
  lv_obj_t *title_label;
  lv_obj_t *input_label;
  ui_keyboard_callback_t callback;
  bool enabled_keys[UI_KB_KEY_COUNT]; // Revert to simple bool array
} ui_keyboard_t;

/**
 * @brief Create a keyboard
 *
 * @param parent Parent LVGL object
 * @param title Title to display above keyboard (e.g., "Word 1/12")
 * @param callback Function to call when a key is pressed
 * @return ui_keyboard_t* Pointer to created keyboard, NULL on failure
 */
ui_keyboard_t *ui_keyboard_create(lv_obj_t *parent, const char *title,
                                  ui_keyboard_callback_t callback);

/**
 * @brief Update the keyboard title
 *
 * @param kb Pointer to keyboard
 * @param title New title text
 */
void ui_keyboard_set_title(ui_keyboard_t *kb, const char *title);

/**
 * @brief Update the input display text (shows current prefix)
 *
 * @param kb Pointer to keyboard
 * @param text Text to display (current input)
 */
void ui_keyboard_set_input_text(ui_keyboard_t *kb, const char *text);

/**
 * @brief Enable or disable a specific key
 *
 * @param kb Pointer to keyboard
 * @param key_index Key index (UI_KB_KEY_A to UI_KB_KEY_OK)
 * @param enabled true to enable, false to disable
 */
void ui_keyboard_set_key_enabled(ui_keyboard_t *kb, int key_index,
                                 bool enabled);

/**
 * @brief Enable or disable all letter keys based on a bitmask
 * Bit 0 = 'a', Bit 25 = 'z'
 *
 * @param kb Pointer to keyboard
 * @param letter_mask 26-bit mask where bit N enables letter 'a'+N
 */
void ui_keyboard_set_letters_enabled(ui_keyboard_t *kb, uint32_t letter_mask);

/**
 * @brief Set the OK button visibility/enabled state
 *
 * @param kb Pointer to keyboard
 * @param enabled true to enable, false to disable
 */
void ui_keyboard_set_ok_enabled(ui_keyboard_t *kb, bool enabled);

/**
 * @brief Show the keyboard
 *
 * @param kb Pointer to keyboard
 */
void ui_keyboard_show(ui_keyboard_t *kb);

/**
 * @brief Hide the keyboard
 *
 * @param kb Pointer to keyboard
 */
void ui_keyboard_hide(ui_keyboard_t *kb);

/**
 * @brief Destroy the keyboard and free resources
 *
 * @param kb Pointer to keyboard
 */
void ui_keyboard_destroy(ui_keyboard_t *kb);

#endif
