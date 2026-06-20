// Mnemonic Words Backup Page

#include "mnemonic_words.h"
#include "../../../core/key.h"
#include "../../../ui/theme.h"
#include "../../../ui/theme_widgets.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>

static lv_obj_t *mnemonic_screen = NULL;
static void (*return_callback)(void) = NULL;

static void back_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

void mnemonic_words_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded())
    return;

  return_callback = return_cb;

  char **words = NULL;
  size_t word_count = 0;
  if (!key_get_mnemonic_words(&words, &word_count))
    return;

  mnemonic_screen = theme_create_page_container(parent);
  lv_obj_add_flag(mnemonic_screen, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(mnemonic_screen, back_cb, LV_EVENT_CLICKED, NULL);

  theme_create_page_title(mnemonic_screen, "BIP39 Words");

  lv_obj_t *content = lv_obj_create(mnemonic_screen);
  lv_obj_set_size(content, LV_PCT(100), LV_SIZE_CONTENT);
  lv_obj_set_style_pad_all(content, 0, 0);
  lv_obj_set_style_border_width(content, 0, 0);
  lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, 0);
  lv_obj_set_flex_grow(content, 1);
  lv_obj_add_flag(content, LV_OBJ_FLAG_EVENT_BUBBLE);
  lv_obj_align(content, LV_ALIGN_CENTER, 0, 0);
  lv_obj_set_flex_flow(content, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(content, LV_FLEX_ALIGN_SPACE_EVENLY,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  if (word_count == 12) {
    lv_obj_t *col = theme_create_flex_column(content);
    lv_obj_set_flex_align(col, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START,
                          LV_FLEX_ALIGN_START);
    lv_obj_set_style_pad_row(col, 6, 0);
    lv_obj_add_flag(col, LV_OBJ_FLAG_EVENT_BUBBLE);

    for (size_t i = 0; i < word_count; i++) {
      lv_obj_t *row = theme_create_flex_row(col);
      lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                            LV_FLEX_ALIGN_START);
      lv_obj_set_style_pad_column(row, 6, 0);
      lv_obj_add_flag(row, LV_OBJ_FLAG_EVENT_BUBBLE);

      char num_buf[12];
      snprintf(num_buf, sizeof(num_buf), "%u.", (unsigned)(i + 1));

      lv_obj_t *num = theme_create_label(row, num_buf, false);
      lv_obj_set_style_text_font(num, theme_font_medium(), 0);
      lv_obj_set_style_text_color(num, secondary_color(), 0);

      lv_obj_t *word = theme_create_label(row, words[i], false);
      lv_obj_set_style_text_font(word, theme_font_medium(), 0);
      lv_obj_set_style_text_color(word, primary_color(), 0);
    }

  } else if (word_count == 24) {
    lv_obj_t *left_col = theme_create_flex_column(content);
    lv_obj_set_flex_align(left_col, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START,
                          LV_FLEX_ALIGN_START);
    lv_obj_set_style_pad_row(left_col, 6, 0);
    lv_obj_add_flag(left_col, LV_OBJ_FLAG_EVENT_BUBBLE);

    lv_obj_t *right_col = theme_create_flex_column(content);
    lv_obj_set_flex_align(right_col, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START,
                          LV_FLEX_ALIGN_START);
    lv_obj_set_style_pad_row(right_col, 6, 0);
    lv_obj_add_flag(right_col, LV_OBJ_FLAG_EVENT_BUBBLE);

    for (size_t i = 0; i < 24; i++) {
      lv_obj_t *col = (i < 12) ? left_col : right_col;

      lv_obj_t *row = theme_create_flex_row(col);
      lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                            LV_FLEX_ALIGN_START);
      lv_obj_set_style_pad_column(row, 6, 0);
      lv_obj_add_flag(row, LV_OBJ_FLAG_EVENT_BUBBLE);

      char num_buf[12];
      snprintf(num_buf, sizeof(num_buf), "%u.", (unsigned)(i + 1));

      lv_obj_t *num = theme_create_label(row, num_buf, false);
      lv_obj_set_style_text_font(num, theme_font_medium(), 0);
      lv_obj_set_style_text_color(num, secondary_color(), 0);

      lv_obj_t *word = theme_create_label(row, words[i], false);
      lv_obj_set_style_text_font(word, theme_font_medium(), 0);
      lv_obj_set_style_text_color(word, primary_color(), 0);
    }
  }

  for (size_t i = 0; i < word_count; i++)
    free(words[i]);
  free(words);

  lv_obj_t *hint = theme_create_label(mnemonic_screen, "Tap to return", false);
  lv_obj_set_style_text_align(hint, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_align(hint, LV_ALIGN_BOTTOM_MID, 0, -theme_default_padding());
}

void mnemonic_words_page_show(void) {
  if (mnemonic_screen)
    lv_obj_clear_flag(mnemonic_screen, LV_OBJ_FLAG_HIDDEN);
}

void mnemonic_words_page_hide(void) {
  if (mnemonic_screen)
    lv_obj_add_flag(mnemonic_screen, LV_OBJ_FLAG_HIDDEN);
}

void mnemonic_words_page_destroy(void) {
  if (mnemonic_screen) {
    lv_obj_del(mnemonic_screen);
    mnemonic_screen = NULL;
  }
  return_callback = NULL;
}
