// Mnemonic Words Backup Page

#include "mnemonic_words.h"
#include "../../../core/key.h"
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

  char word_list[512];
  int offset = 0;

  if (word_count == 12) {
    for (size_t i = 0; i < word_count; i++) {
      offset += snprintf(word_list + offset, sizeof(word_list) - offset,
                         "%s%zu. %s", i > 0 ? "\n" : "", i + 1, words[i]);
    }
    lv_obj_t *label = theme_create_label(content, word_list, false);
    lv_obj_set_style_text_font(label, theme_font_medium(), 0);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_LEFT, 0);

  } else if (word_count == 24) {
    for (size_t i = 0; i < 12; i++) {
      offset += snprintf(word_list + offset, sizeof(word_list) - offset,
                         "%s%zu. %s", i > 0 ? "\n" : "", i + 1, words[i]);
    }
    lv_obj_t *left = theme_create_label(content, word_list, false);
    lv_obj_set_style_text_font(left, theme_font_medium(), 0);
    lv_obj_set_style_text_align(left, LV_TEXT_ALIGN_LEFT, 0);

    offset = 0;
    for (size_t i = 12; i < 24; i++) {
      offset += snprintf(word_list + offset, sizeof(word_list) - offset,
                         "%s%zu. %s", i > 12 ? "\n" : "", i + 1, words[i]);
    }
    lv_obj_t *right = theme_create_label(content, word_list, false);
    lv_obj_set_style_text_font(right, theme_font_medium(), 0);
    lv_obj_set_style_text_align(right, LV_TEXT_ALIGN_LEFT, 0);
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
