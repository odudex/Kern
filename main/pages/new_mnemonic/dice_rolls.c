// Dice Rolls Page - Generate mnemonic entropy from dice rolls

#include "dice_rolls.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/theme.h"
#include "../../ui/word_selector.h"
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>
#ifdef SIMULATOR
#include <stdio.h>
#endif
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>

#include "../../utils/secure_mem.h"

#define MIN_ROLLS_12_WORDS 50
#define MIN_ROLLS_24_WORDS 99
#define MAX_ROLLS 256
#define ENTROPY_12_WORDS 16
#define ENTROPY_24_WORDS 32

static lv_obj_t *dice_rolls_screen = NULL;
static lv_obj_t *back_btn = NULL;
static lv_obj_t *dice_btnmatrix = NULL;
static lv_obj_t *title_label = NULL;
static lv_obj_t *rolls_label = NULL;
static void (*return_callback)(void) = NULL;
static char *completed_mnemonic = NULL;

static int total_words = 0;
static int min_rolls = 0;
static char rolls_string[MAX_ROLLS + 1];
static int rolls_count = 0;

static void create_word_count_menu(void);
static void create_dice_input(void);
static void cleanup_ui(void);
static void on_word_count_selected(int word_count);
static void back_cb(void);
static void dice_btnmatrix_event_cb(lv_event_t *e);
static void update_display(void);
static bool generate_mnemonic_from_rolls(void);
static void finish_dice_rolls(void);
static void confirm_finish_cb(bool confirmed, void *user_data);
static void back_btn_cb(lv_event_t *e);
static void back_confirm_cb(bool confirmed, void *user_data);

static const char *dice_map[] = {
    "1", "2", "3", "\n", "4", "5", "6", "\n", LV_SYMBOL_BACKSPACE, "Done", ""};

static void cleanup_ui(void) {
  if (back_btn) {
    lv_obj_del(back_btn);
    back_btn = NULL;
  }
  if (dice_btnmatrix) {
    lv_obj_del(dice_btnmatrix);
    dice_btnmatrix = NULL;
  }
  if (title_label) {
    lv_obj_del(title_label);
    title_label = NULL;
  }
  if (rolls_label) {
    lv_obj_del(rolls_label);
    rolls_label = NULL;
  }
}

static void create_word_count_menu(void) {
  cleanup_ui();
  ui_word_count_selector_create(dice_rolls_screen, back_cb,
                                on_word_count_selected);
}

static void back_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed) {
    rolls_count = 0;
    rolls_string[0] = '\0';
    if (return_callback)
      return_callback();
  }
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  dialog_show_confirm("Are you sure?", back_confirm_cb, NULL,
                      DIALOG_STYLE_OVERLAY);
}

static void create_dice_input(void) {
  cleanup_ui();

  title_label = theme_create_page_title(dice_rolls_screen, "");

  rolls_label = lv_label_create(dice_rolls_screen);
  lv_obj_set_style_text_color(rolls_label, highlight_color(), 0);
  lv_obj_set_style_text_font(rolls_label, theme_font_medium(), 0);
  lv_obj_set_width(rolls_label, LV_PCT(90));
  lv_label_set_long_mode(rolls_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(rolls_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(rolls_label, LV_ALIGN_TOP_MID, 0, 130);

  back_btn = ui_create_back_button(dice_rolls_screen, back_btn_cb);

  dice_btnmatrix = lv_btnmatrix_create(dice_rolls_screen);
  lv_btnmatrix_set_map(dice_btnmatrix, dice_map);
  lv_obj_align(dice_btnmatrix, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_size(dice_btnmatrix, LV_PCT(100), LV_PCT(50));
  theme_apply_btnmatrix(dice_btnmatrix);

  lv_obj_add_event_cb(dice_btnmatrix, dice_btnmatrix_event_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);

  update_display();
}

static void update_display(void) {
  if (!title_label || !rolls_label)
    return;

  char title[64];
  snprintf(title, sizeof(title), "%d Words - %d/%d rolls", total_words,
           rolls_count, min_rolls);
  lv_label_set_text(title_label, title);

  if (rolls_count == 0) {
    lv_label_set_text(rolls_label, "_");
  } else {
    char display[MAX_ROLLS + 2];
    snprintf(display, sizeof(display), "%s_", rolls_string);
    lv_label_set_text(rolls_label, display);
  }

  if (dice_btnmatrix) {
    // Done button (index 7)
    if (rolls_count >= min_rolls)
      lv_btnmatrix_clear_btn_ctrl(dice_btnmatrix, 7,
                                  LV_BTNMATRIX_CTRL_DISABLED);
    else
      lv_btnmatrix_set_btn_ctrl(dice_btnmatrix, 7, LV_BTNMATRIX_CTRL_DISABLED);

    // Backspace button (index 6)
    if (rolls_count > 0)
      lv_btnmatrix_clear_btn_ctrl(dice_btnmatrix, 6,
                                  LV_BTNMATRIX_CTRL_DISABLED);
    else
      lv_btnmatrix_set_btn_ctrl(dice_btnmatrix, 6, LV_BTNMATRIX_CTRL_DISABLED);
  }
}

static void dice_btnmatrix_event_cb(lv_event_t *e) {
  lv_obj_t *obj = lv_event_get_target(e);
  uint32_t id = lv_btnmatrix_get_selected_btn(obj);
  const char *txt = lv_btnmatrix_get_btn_text(obj, id);

  if (!txt)
    return;

  if (strcmp(txt, "Done") == 0) {
    if (rolls_count >= min_rolls) {
      char msg[64];
      snprintf(msg, sizeof(msg), "Generate %d-word mnemonic from %d rolls?",
               total_words, rolls_count);
      dialog_show_confirm(msg, confirm_finish_cb, NULL, DIALOG_STYLE_OVERLAY);
    }
  } else if (strcmp(txt, LV_SYMBOL_BACKSPACE) == 0) {
    if (rolls_count > 0) {
      rolls_count--;
      rolls_string[rolls_count] = '\0';
      update_display();
    }
  } else {
    char dice_value = txt[0];
    if (dice_value >= '1' && dice_value <= '6' && rolls_count < MAX_ROLLS) {
      rolls_string[rolls_count++] = dice_value;
      rolls_string[rolls_count] = '\0';
      update_display();
    }
  }
}

static void confirm_finish_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed)
    finish_dice_rolls();
}

static bool generate_mnemonic_from_rolls(void) {
  if (rolls_count < min_rolls)
    return false;

  size_t entropy_len =
      (total_words == 12) ? ENTROPY_12_WORDS : ENTROPY_24_WORDS;

  unsigned char hash[SHA256_LEN];
  if (wally_sha256((const unsigned char *)rolls_string, rolls_count, hash,
                   sizeof(hash)) != WALLY_OK)
    return false;

  char *mnemonic = NULL;
  if (bip39_mnemonic_from_bytes(NULL, hash, entropy_len, &mnemonic) !=
          WALLY_OK ||
      !mnemonic)
    return false;

  if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    wally_free_string(mnemonic);
    return false;
  }

  if (completed_mnemonic)
    free(completed_mnemonic);
  completed_mnemonic = strdup(mnemonic);
  wally_free_string(mnemonic);

  secure_memzero(hash, sizeof(hash));
  secure_memzero(rolls_string, sizeof(rolls_string));
  rolls_count = 0;

  return true;
}

static void finish_dice_rolls(void) {
  if (!generate_mnemonic_from_rolls()) {
    dialog_show_error("Failed to generate mnemonic", NULL, 0);
    return;
  }

  dice_rolls_page_hide();
  if (return_callback)
    return_callback();
}

static void on_word_count_selected(int word_count) {
  total_words = word_count;
  min_rolls = (word_count == 12) ? MIN_ROLLS_12_WORDS : MIN_ROLLS_24_WORDS;
  rolls_count = 0;
  rolls_string[0] = '\0';
  create_dice_input();
}

static void back_cb(void) {
  void (*callback)(void) = return_callback;
  dice_rolls_page_hide();
  dice_rolls_page_destroy();
  if (callback)
    callback();
}

void dice_rolls_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;

  if (completed_mnemonic) {
    free(completed_mnemonic);
    completed_mnemonic = NULL;
  }

  total_words = 0;
  min_rolls = 0;
  rolls_count = 0;
  rolls_string[0] = '\0';

  dice_rolls_screen = theme_create_page_container(parent);

  create_word_count_menu();
}

void dice_rolls_page_show(void) {
  if (dice_rolls_screen)
    lv_obj_clear_flag(dice_rolls_screen, LV_OBJ_FLAG_HIDDEN);
}

void dice_rolls_page_hide(void) {
  if (dice_rolls_screen)
    lv_obj_add_flag(dice_rolls_screen, LV_OBJ_FLAG_HIDDEN);
}

void dice_rolls_page_destroy(void) {
  cleanup_ui();

  if (dice_rolls_screen) {
    lv_obj_del(dice_rolls_screen);
    dice_rolls_screen = NULL;
  }

  secure_memzero(rolls_string, sizeof(rolls_string));
  rolls_count = 0;
  total_words = 0;
  min_rolls = 0;
  return_callback = NULL;
}

char *dice_rolls_get_completed_mnemonic(void) {
  if (completed_mnemonic) {
    char *result = completed_mnemonic;
    completed_mnemonic = NULL;
    return result;
  }
  return NULL;
}
