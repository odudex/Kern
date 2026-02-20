// Manual Mnemonic Input Page - BIP39 word entry with smart filtering

#include "manual_input.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/keyboard.h"
#include "../../ui/menu.h"
#include "../../ui/theme.h"
#include "../../ui/word_selector.h"
#include "../../utils/bip39_filter.h"
#include "../shared/mnemonic_editor.h"
#include <lvgl.h>
#include <stdio.h>
#include <string.h>

#include "../../utils/secure_mem.h"

typedef enum {
  MODE_WORD_COUNT_SELECT,
  MODE_KEYBOARD_INPUT,
  MODE_WORD_SELECT
} input_mode_t;

#define MAX_MNEMONIC_LEN 256

static lv_obj_t *manual_input_screen = NULL;
static lv_obj_t *back_btn = NULL;
static ui_menu_t *current_menu = NULL;
static ui_keyboard_t *keyboard = NULL;
static void (*return_callback)(void) = NULL;
static void (*success_callback)(void) = NULL;

static int total_words = 0;
static int current_word_index = 0;
static char entered_words[24][16];
static char current_prefix[BIP39_MAX_PREFIX_LEN + 1];
static int prefix_len = 0;

static const char *filtered_words[BIP39_MAX_FILTERED_WORDS];
static int filtered_count = 0;
static input_mode_t current_mode = MODE_WORD_COUNT_SELECT;
static char pending_word[16] = {0};
static bool checksum_filter_mode = false;

static void word_confirmation_cb(bool confirmed, void *user_data);
static void create_word_count_menu(void);
static void create_keyboard_input(void);
static void create_word_select_menu(void);
static void update_keyboard_state(void);
static void filter_words_by_prefix(void);
static void on_word_count_selected(int word_count);
static void keyboard_callback(char key);
static void word_selected_cb(void);
static void back_to_keyboard_cb(void);
static void back_cb(void);
static void finish_mnemonic(void);
static void cleanup_ui(void);

static void filter_words_by_prefix(void) {
  if (checksum_filter_mode && current_word_index == total_words - 1) {
    filtered_count = bip39_filter_last_word_by_prefix(
        entered_words, total_words, current_prefix, prefix_len, filtered_words,
        BIP39_MAX_FILTERED_WORDS);
  } else {
    filtered_count = bip39_filter_by_prefix(
        current_prefix, prefix_len, filtered_words, BIP39_MAX_FILTERED_WORDS);
  }
}

static void cleanup_ui(void) {
  if (back_btn) {
    lv_obj_del(back_btn);
    back_btn = NULL;
  }
  if (current_menu) {
    ui_menu_destroy(current_menu);
    current_menu = NULL;
  }
  if (keyboard) {
    ui_keyboard_destroy(keyboard);
    keyboard = NULL;
  }
}

static void show_word_confirmation(const char *word) {
  strncpy(pending_word, word, sizeof(pending_word) - 1);
  pending_word[sizeof(pending_word) - 1] = '\0';

  char msg[64];
  snprintf(msg, sizeof(msg), "Word %d: %s", current_word_index + 1, word);

  dialog_show_confirm(msg, word_confirmation_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static void word_confirmation_cb(bool confirmed, void *user_data) {
  (void)user_data;

  if (confirmed) {
    snprintf(entered_words[current_word_index], sizeof(entered_words[0]), "%s",
             pending_word);
    current_word_index++;
    prefix_len = 0;
    current_prefix[0] = '\0';
    pending_word[0] = '\0';
    cleanup_ui();

    if (current_word_index >= total_words) {
      finish_mnemonic();
    } else {
      // Clear cache when moving to last word so it gets recalculated
      if (checksum_filter_mode && current_word_index == total_words - 1) {
        bip39_filter_clear_last_word_cache();
      }
      create_keyboard_input();
    }
  } else {
    pending_word[0] = '\0';
    if (current_menu) {
      ui_menu_destroy(current_menu);
      current_menu = NULL;
    }

    if (keyboard) {
      ui_keyboard_show(keyboard);
      update_keyboard_state();
    } else {
      create_keyboard_input();
    }
  }
}

static void create_word_count_menu(void) {
  cleanup_ui();
  current_mode = MODE_WORD_COUNT_SELECT;
  ui_word_count_selector_create(manual_input_screen, back_cb,
                                on_word_count_selected);
}

static void update_keyboard_state(void) {
  if (!keyboard)
    return;

  char title[48];
  bool is_last_word =
      checksum_filter_mode && current_word_index == total_words - 1;
  if (is_last_word) {
    snprintf(title, sizeof(title), "Word %d/%d (checksum)",
             current_word_index + 1, total_words);
  } else {
    snprintf(title, sizeof(title), "Word %d/%d", current_word_index + 1,
             total_words);
  }
  ui_keyboard_set_title(keyboard, title);
  ui_keyboard_set_input_text(keyboard, current_prefix);

  uint32_t valid_letters;
  int match_count;
  if (is_last_word) {
    valid_letters = bip39_filter_get_valid_letters_for_last_word(
        entered_words, total_words, current_prefix, prefix_len);
    filter_words_by_prefix();
    match_count = filtered_count;
  } else {
    valid_letters = bip39_filter_get_valid_letters(current_prefix, prefix_len);
    match_count = bip39_filter_count_matches(current_prefix, prefix_len);
  }

  ui_keyboard_set_letters_enabled(keyboard, valid_letters);
  ui_keyboard_set_key_enabled(keyboard, UI_KB_KEY_BACKSPACE,
                              prefix_len > 0 || current_word_index > 0);
  ui_keyboard_set_ok_enabled(keyboard,
                             prefix_len > 0 && match_count > 0 &&
                                 match_count <= BIP39_MAX_FILTERED_WORDS);
}

static void back_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed && return_callback)
    return_callback();
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  dialog_show_confirm("Are you sure?", back_confirm_cb, NULL,
                      DIALOG_STYLE_OVERLAY);
}

static void create_keyboard_input(void) {
  cleanup_ui();
  current_mode = MODE_KEYBOARD_INPUT;

  char title[48];
  snprintf(title, sizeof(title), "Word %d/%d", current_word_index + 1,
           total_words);

  keyboard = ui_keyboard_create(manual_input_screen, title, keyboard_callback);
  if (!keyboard)
    return;

  // Back button top-left
  back_btn = ui_create_back_button(manual_input_screen, back_btn_cb);

  update_keyboard_state();
  ui_keyboard_show(keyboard);
}

static void create_word_select_menu(void) {
  cleanup_ui();
  current_mode = MODE_WORD_SELECT;
  filter_words_by_prefix();

  if (filtered_count == 0) {
    create_keyboard_input();
    return;
  }

  char title[64];
  snprintf(title, sizeof(title), "Select: %s...", current_prefix);

  current_menu =
      ui_menu_create(manual_input_screen, title, back_to_keyboard_cb);
  if (!current_menu)
    return;

  for (int i = 0; i < filtered_count; i++) {
    ui_menu_add_entry(current_menu, filtered_words[i], word_selected_cb);
  }
  ui_menu_show(current_menu);
}

static void on_word_count_selected(int word_count) {
  total_words = word_count;
  current_word_index = 0;
  prefix_len = 0;
  current_prefix[0] = '\0';
  secure_memzero(entered_words, sizeof(entered_words));
  create_keyboard_input();
}

static void keyboard_callback(char key) {
  if (key >= 'a' && key <= 'z') {
    if (prefix_len < BIP39_MAX_PREFIX_LEN) {
      current_prefix[prefix_len++] = key;
      current_prefix[prefix_len] = '\0';

      filter_words_by_prefix();
      if (filtered_count == 1) {
        show_word_confirmation(filtered_words[0]);
      } else {
        update_keyboard_state();
      }
    }
  } else if (key == UI_KB_BACKSPACE) {
    if (prefix_len > 0) {
      prefix_len--;
      current_prefix[prefix_len] = '\0';
      update_keyboard_state();
    } else if (current_word_index > 0) {
      current_word_index--;
      strncpy(current_prefix, entered_words[current_word_index],
              BIP39_MAX_PREFIX_LEN);
      current_prefix[BIP39_MAX_PREFIX_LEN] = '\0';
      prefix_len = strlen(current_prefix);
      entered_words[current_word_index][0] = '\0';
      update_keyboard_state();
    }
  } else if (key == UI_KB_OK) {
    filter_words_by_prefix();
    if (filtered_count > 0)
      create_word_select_menu();
  }
}

static void word_selected_cb(void) {
  if (!current_menu)
    return;

  int selected = ui_menu_get_selected(current_menu);
  if (selected < 0 || selected >= filtered_count)
    return;

  const char *word = filtered_words[selected];
  if (current_menu)
    ui_menu_hide(current_menu);
  show_word_confirmation(word);
}

static void back_to_keyboard_cb(void) { create_keyboard_input(); }

static void back_cb(void) {
  switch (current_mode) {
  case MODE_WORD_COUNT_SELECT:
    if (return_callback)
      return_callback();
    break;

  case MODE_KEYBOARD_INPUT:
    if (prefix_len > 0) {
      prefix_len = 0;
      current_prefix[0] = '\0';
      update_keyboard_state();
    } else if (current_word_index > 0) {
      current_word_index--;
      strncpy(current_prefix, entered_words[current_word_index],
              BIP39_MAX_PREFIX_LEN);
      current_prefix[BIP39_MAX_PREFIX_LEN] = '\0';
      prefix_len = strlen(current_prefix);
      entered_words[current_word_index][0] = '\0';
      update_keyboard_state();
    } else {
      create_word_count_menu();
    }
    break;

  case MODE_WORD_SELECT:
    create_keyboard_input();
    break;
  }
}

static void finish_mnemonic(void) {
  char mnemonic[MAX_MNEMONIC_LEN];
  mnemonic[0] = '\0';

  for (int i = 0; i < total_words; i++) {
    if (i > 0)
      strncat(mnemonic, " ", sizeof(mnemonic) - strlen(mnemonic) - 1);
    strncat(mnemonic, entered_words[i],
            sizeof(mnemonic) - strlen(mnemonic) - 1);
  }

  manual_input_page_hide();
  mnemonic_editor_page_create(lv_screen_active(), return_callback,
                              success_callback, mnemonic, checksum_filter_mode);
  mnemonic_editor_page_show();
}

void manual_input_page_create(lv_obj_t *parent, void (*return_cb)(void),
                              void (*success_cb)(void),
                              bool checksum_filter_last_word) {
  if (!parent)
    return;

  return_callback = return_cb;
  success_callback = success_cb;
  checksum_filter_mode = checksum_filter_last_word;

  if (!bip39_filter_init()) {
    dialog_show_error("Failed to load wordlist", return_cb, 0);
    return;
  }

  total_words = 0;
  current_word_index = 0;
  prefix_len = 0;
  current_prefix[0] = '\0';
  filtered_count = 0;
  secure_memzero(entered_words, sizeof(entered_words));
  bip39_filter_clear_last_word_cache();

  manual_input_screen = theme_create_page_container(parent);
  create_word_count_menu();
}

void manual_input_page_show(void) {
  if (manual_input_screen)
    lv_obj_clear_flag(manual_input_screen, LV_OBJ_FLAG_HIDDEN);
  if (current_mode == MODE_KEYBOARD_INPUT && keyboard) {
    ui_keyboard_show(keyboard);
  } else if (current_menu) {
    ui_menu_show(current_menu);
  }
}

void manual_input_page_hide(void) {
  if (manual_input_screen)
    lv_obj_add_flag(manual_input_screen, LV_OBJ_FLAG_HIDDEN);
  if (keyboard)
    ui_keyboard_hide(keyboard);
  if (current_menu)
    ui_menu_hide(current_menu);
}

void manual_input_page_destroy(void) {
  cleanup_ui();

  if (manual_input_screen) {
    lv_obj_del(manual_input_screen);
    manual_input_screen = NULL;
  }

  secure_memzero(entered_words, sizeof(entered_words));
  secure_memzero(current_prefix, sizeof(current_prefix));
  secure_memzero(pending_word, sizeof(pending_word));

  return_callback = NULL;
  success_callback = NULL;
  total_words = 0;
  current_word_index = 0;
  prefix_len = 0;
  filtered_count = 0;
  current_mode = MODE_WORD_COUNT_SELECT;
  checksum_filter_mode = false;
  bip39_filter_clear_last_word_cache();
}
