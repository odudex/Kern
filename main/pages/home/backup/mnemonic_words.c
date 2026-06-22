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

static lv_obj_t *create_word_column(lv_obj_t *parent) {
  lv_obj_t *col = theme_create_flex_column(parent);
  lv_obj_set_flex_align(col, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_START);
  lv_obj_set_style_pad_row(col, 6, 0);
  lv_obj_add_flag(col, LV_OBJ_FLAG_EVENT_BUBBLE);
  return col;
}

static void add_word_row(lv_obj_t *col, size_t index, const char *word,
                         int32_t num_width) {
  lv_obj_t *row = theme_create_flex_row(col);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_START);
  lv_obj_set_style_pad_column(row, 6, 0);
  lv_obj_add_flag(row, LV_OBJ_FLAG_EVENT_BUBBLE);

  char num_buf[12];
  snprintf(num_buf, sizeof(num_buf), "%u.", (unsigned)(index + 1));

  lv_obj_t *num = theme_create_label(row, num_buf, false);
  lv_obj_set_style_text_font(num, theme_font_medium(), 0);
  lv_obj_set_style_text_color(num, secondary_color(), 0);
  lv_label_set_long_mode(num, LV_LABEL_LONG_CLIP);
  lv_obj_set_width(num, num_width);
  lv_obj_set_style_text_align(num, LV_TEXT_ALIGN_RIGHT, 0);

  lv_obj_t *label = theme_create_label(row, word, false);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(label, primary_color(), 0);
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

  // Fixed-width number column so every word starts at the same x. Measure every
  // index and take the widest (a "10." can render wider than "12.") so no
  // number gets clipped; scales with the per-board font.
  int32_t num_width = 0;
  for (size_t i = 0; i < word_count; i++) {
    char buf[12];
    snprintf(buf, sizeof(buf), "%u.", (unsigned)(i + 1));
    lv_point_t s;
    lv_text_get_size(&s, buf, theme_font_medium(), 0, 0, LV_COORD_MAX,
                     LV_TEXT_FLAG_NONE);
    if (s.x > num_width)
      num_width = s.x;
  }

  // Portrait keeps the tall 1-column (or 2 for 24 words) layout. Wide screens
  // (landscape, and the square wave_4b) are short, so spread into more, shorter
  // columns until the rows fit between the title band and the bottom hint
  // instead of growing over them.
  size_t columns = (word_count > 12) ? 2 : 1;
  if (theme_is_landscape()) {
    int32_t top_band = theme_corner_button_height() + theme_small_padding();
    int32_t bottom_band =
        theme_default_padding() + lv_font_get_line_height(theme_font_small());
    // content is screen-centered, so reserve the larger band on both sides to
    // keep the centered block clear of the title and the hint.
    int32_t reserve = (top_band > bottom_band) ? top_band : bottom_band;
    int32_t avail_h = theme_screen_height() - 2 * reserve;
    int32_t row_h =
        lv_font_get_line_height(theme_font_medium()) + 6; // + pad_row gap
    size_t max_rows = (avail_h > row_h) ? (size_t)(avail_h / row_h) : 1;
    while ((word_count + columns - 1) / columns > max_rows &&
           columns < word_count)
      columns++;
  }
  size_t per_col = (word_count + columns - 1) / columns;

  lv_obj_t *col = NULL;
  for (size_t i = 0; i < word_count; i++) {
    if (i % per_col == 0)
      col = create_word_column(content);
    add_word_row(col, i, words[i], num_width);
  }

  for (size_t i = 0; i < word_count; i++)
    free(words[i]);
  free(words);

  lv_obj_t *hint = theme_create_label(mnemonic_screen, "Tap to return", true);
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
