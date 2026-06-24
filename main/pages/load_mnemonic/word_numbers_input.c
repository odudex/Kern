// Decimal BIP39 word-number input for the 12/24-word flow.
// Each word is a 1-2048 number entered on the shared numeric keypad.

#include "word_numbers_input.h"
#include "../../ui/dialog.h"
#include "../../ui/numeric_keypad.h"
#include "../../ui/theme_widgets.h"
#include "../../ui/word_selector.h"
#include "../../utils/secure_mem.h"
#include "../shared/mnemonic_editor.h"
#include <stdio.h>
#include <wally_bip39.h>

#define MAX_WORDS 24
#define MAX_MNEMONIC_LEN 256

static lv_obj_t *word_numbers_screen = NULL;
static ui_numeric_keypad_t *keypad = NULL;
static struct words *bip39_wordlist = NULL;
static void (*return_callback)(void) = NULL;
static void (*success_callback)(void) = NULL;
static uint16_t entered_numbers[MAX_WORDS];
static size_t target_word_count = 0;
static size_t current_word_index = 0;

static const char *word_for_number(uint16_t number) {
  if (!bip39_wordlist || number < 1 || number > 2048)
    return NULL;
  return bip39_get_word_by_index(bip39_wordlist, number - 1);
}

static void finish_mnemonic(void) {
  char mnemonic[MAX_MNEMONIC_LEN];
  size_t used = 0;
  mnemonic[0] = '\0';

  for (size_t i = 0; i < target_word_count; i++) {
    const char *word = word_for_number(entered_numbers[i]);
    int written = word ? snprintf(mnemonic + used, MAX_MNEMONIC_LEN - used,
                                  "%s%s", i ? " " : "", word)
                       : -1;
    if (written < 0 || (size_t)written >= MAX_MNEMONIC_LEN - used) {
      secure_memzero(mnemonic, sizeof(mnemonic));
      dialog_show_error_timeout("Failed to build mnemonic", return_callback, 0);
      return;
    }
    used += (size_t)written;
  }

  word_numbers_input_page_hide();
  mnemonic_editor_page_create(lv_screen_active(), return_callback,
                              success_callback, mnemonic, false);
  mnemonic_editor_page_show();
  secure_memzero(mnemonic, sizeof(mnemonic));
}

static void open_word_keypad(uint16_t initial);

static void word_submit_cb(uint32_t value, void *user_data) {
  (void)user_data;
  entered_numbers[current_word_index++] = (uint16_t)value;
  if (current_word_index >= target_word_count)
    finish_mnemonic();
  else
    open_word_keypad(0);
}

static void word_cancel_cb(void *user_data) {
  (void)user_data;
  if (current_word_index == 0) {
    if (return_callback)
      return_callback();
  } else {
    current_word_index--;
    open_word_keypad(entered_numbers[current_word_index]);
  }
}

static void open_word_keypad(uint16_t initial) {
  char title[32];
  snprintf(title, sizeof(title), "Word %u/%u",
           (unsigned)(current_word_index + 1), (unsigned)target_word_count);

  ui_numeric_keypad_config_t config = {
      .title = title,
      .initial_value = initial,
      .min_value = 1,
      .max_value = 2048,
      .max_digits = 4,
      .invalid_message = "Enter 1-2048",
      .submit_cb = word_submit_cb,
      .cancel_cb = word_cancel_cb,
  };
  ui_numeric_keypad_open(&keypad, &config);
}

static void word_count_back_cb(void) {
  if (return_callback)
    return_callback();
}

static void word_count_selected_cb(int word_count) {
  target_word_count = (size_t)word_count;
  current_word_index = 0;
  secure_memzero(entered_numbers, sizeof(entered_numbers));
  if (word_numbers_screen)
    lv_obj_add_flag(word_numbers_screen, LV_OBJ_FLAG_HIDDEN);
  open_word_keypad(0);
}

void word_numbers_input_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                    void (*success_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;
  success_callback = success_cb;
  secure_memzero(entered_numbers, sizeof(entered_numbers));
  target_word_count = 0;
  current_word_index = 0;

  if (bip39_get_wordlist(NULL, &bip39_wordlist) != WALLY_OK ||
      !bip39_wordlist) {
    dialog_show_error_timeout("Failed to load wordlist", return_cb, 0);
    return;
  }

  word_numbers_screen = theme_create_page_container(parent);
  ui_word_count_selector_create(word_numbers_screen, word_count_back_cb,
                                word_count_selected_cb);
}

void word_numbers_input_page_show(void) {
  if (word_numbers_screen)
    lv_obj_clear_flag(word_numbers_screen, LV_OBJ_FLAG_HIDDEN);
}

void word_numbers_input_page_hide(void) {
  if (word_numbers_screen)
    lv_obj_add_flag(word_numbers_screen, LV_OBJ_FLAG_HIDDEN);
}

void word_numbers_input_page_destroy(void) {
  ui_numeric_keypad_close(&keypad);
  if (word_numbers_screen) {
    lv_obj_del(word_numbers_screen);
    word_numbers_screen = NULL;
  }
  bip39_wordlist = NULL;
  return_callback = NULL;
  success_callback = NULL;
  target_word_count = 0;
  current_word_index = 0;
  secure_memzero(entered_numbers, sizeof(entered_numbers));
}
