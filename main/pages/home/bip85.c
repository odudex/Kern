#include "bip85.h"
#include "../../core/key.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/numeric_keypad.h"
#include "../../ui/theme.h"
#include "../../ui/word_selector.h"
#include "../../utils/secure_mem.h"
#include "../shared/key_confirmation.h"
#include <lvgl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_bip85.h>
#include <wally_core.h>
#include <wally_crypto.h>

#define BIP85_INDEX_MAX (BIP32_INITIAL_HARDENED_CHILD - 1)

static lv_obj_t *bip85_screen = NULL;
static void (*return_callback)(void) = NULL;
static void (*success_callback)(void) = NULL;

static int selected_word_count = 0;
static uint32_t selected_child_index = 0;
static char *child_mnemonic = NULL;

static lv_obj_t *flow_back_btn = NULL;
static ui_numeric_keypad_t *index_keypad = NULL;
static lv_obj_t *result_header = NULL;
static lv_obj_t *result_content = NULL;
static lv_obj_t *load_btn = NULL;

static void create_word_count_menu(void);
static void create_result_ui(void);
static void cleanup_flow_ui(void);
static void clear_child_mnemonic(void);

static void clear_child_mnemonic(void) {
  if (child_mnemonic) {
    wally_free_string(child_mnemonic);
    child_mnemonic = NULL;
  }
}

static void cleanup_flow_ui(void) {
  ui_numeric_keypad_close(&index_keypad);

  if (flow_back_btn) {
    lv_obj_del(flow_back_btn);
    flow_back_btn = NULL;
  }
  if (result_header) {
    lv_obj_del(result_header);
    result_header = NULL;
  }
  if (result_content) {
    lv_obj_del(result_content);
    result_content = NULL;
  }
  if (load_btn) {
    lv_obj_del(load_btn);
    load_btn = NULL;
  }
}

static bool derive_child_mnemonic(void) {
  struct ext_key *master_key = NULL;
  unsigned char entropy[HMAC_SHA512_LEN];
  size_t written = 0;
  char *mnemonic = NULL;
  bool ok = false;

  clear_child_mnemonic();

  if (!key_get_derived_key("m", &master_key))
    goto cleanup;

  if (bip85_get_bip39_entropy(master_key, NULL, (uint32_t)selected_word_count,
                              selected_child_index, entropy, sizeof(entropy),
                              &written) != WALLY_OK)
    goto cleanup;

  if (bip39_mnemonic_from_bytes(NULL, entropy, written, &mnemonic) !=
          WALLY_OK ||
      !mnemonic)
    goto cleanup;

  child_mnemonic = mnemonic;
  ok = true;

cleanup:
  if (!ok && mnemonic)
    wally_free_string(mnemonic);
  if (master_key)
    bip32_key_free(master_key);
  secure_memzero(entropy, sizeof(entropy));
  return ok;
}

static void append_words_to_buffer(char *out, size_t out_len, char **words,
                                   int start, int end) {
  size_t offset = 0;
  out[0] = '\0';

  for (int i = start; i < end; i++) {
    offset += snprintf(out + offset, out_len - offset, "%s%d. %s",
                       i > start ? "\n" : "", i + 1, words[i]);
    if (offset >= out_len)
      break;
  }
}

static void create_word_labels(lv_obj_t *parent) {
  char *mnemonic_copy = strdup(child_mnemonic);
  char *words[24] = {0};
  int word_count = 0;
  char word_list[512];

  if (!mnemonic_copy)
    return;

  char *token = strtok(mnemonic_copy, " ");
  while (token && word_count < 24) {
    words[word_count++] = token;
    token = strtok(NULL, " ");
  }

  if (word_count == 12) {
    append_words_to_buffer(word_list, sizeof(word_list), words, 0, 12);
    lv_obj_t *label = theme_create_label(parent, word_list, false);
    lv_obj_set_style_text_font(label, theme_font_medium(), 0);
    lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_LEFT, 0);
  } else if (word_count == 24) {
    append_words_to_buffer(word_list, sizeof(word_list), words, 0, 12);
    lv_obj_t *left = theme_create_label(parent, word_list, false);
    lv_obj_set_style_text_font(left, theme_font_medium(), 0);
    lv_obj_set_style_text_align(left, LV_TEXT_ALIGN_LEFT, 0);

    append_words_to_buffer(word_list, sizeof(word_list), words, 12, 24);
    lv_obj_t *right = theme_create_label(parent, word_list, false);
    lv_obj_set_style_text_font(right, theme_font_medium(), 0);
    lv_obj_set_style_text_align(right, LV_TEXT_ALIGN_LEFT, 0);
  }

  secure_memzero(word_list, sizeof(word_list));
  SECURE_FREE_STRING(mnemonic_copy);
}

static void result_back_btn_cb(lv_event_t *e) {
  (void)e;
  clear_child_mnemonic();
  if (return_callback)
    return_callback();
}

static void success_from_key_confirmation_cb(void) {
  key_confirmation_page_destroy();
  clear_child_mnemonic();
  if (success_callback)
    success_callback();
}

static void return_from_key_confirmation_cb(void) {
  key_confirmation_page_destroy();
  bip85_page_show();
}

static void load_btn_cb(lv_event_t *e) {
  (void)e;
  if (!child_mnemonic)
    return;

  bip85_page_hide();
  key_confirmation_page_create(
      lv_screen_active(), return_from_key_confirmation_cb,
      success_from_key_confirmation_cb, child_mnemonic, strlen(child_mnemonic));
  key_confirmation_page_show();
}

static void create_result_ui(void) {
  char fingerprint_hex[9];
  char fingerprint_text[32];

  cleanup_flow_ui();
  if (bip85_screen)
    lv_obj_clear_flag(bip85_screen, LV_OBJ_FLAG_HIDDEN);

  result_header = theme_create_flex_row(bip85_screen);
  lv_obj_set_style_pad_column(result_header, 8, 0);
  lv_obj_align(result_header, LV_ALIGN_TOP_MID, 0, theme_get_default_padding());

  lv_obj_t *title = lv_label_create(result_header);
  lv_label_set_text(title, "BIP85>BIP39");
  lv_obj_set_style_text_font(title, theme_font_small(), 0);
  lv_obj_set_style_text_color(title, main_color(), 0);

  if (key_mnemonic_fingerprint_hex(child_mnemonic, fingerprint_hex)) {
    snprintf(fingerprint_text, sizeof(fingerprint_text), "%s", fingerprint_hex);
  } else {
    snprintf(fingerprint_text, sizeof(fingerprint_text), "unknown");
  }

  lv_obj_t *fingerprint = lv_label_create(result_header);
  lv_label_set_text(fingerprint, fingerprint_text);
  lv_obj_set_style_text_font(fingerprint, theme_font_small(), 0);
  lv_obj_set_style_text_color(fingerprint, highlight_color(), 0);

  flow_back_btn = ui_create_back_button(bip85_screen, result_back_btn_cb);

  result_content = lv_obj_create(bip85_screen);
  lv_obj_set_size(result_content, LV_PCT(92), LV_SIZE_CONTENT);
  lv_obj_align(result_content, LV_ALIGN_CENTER, 0, 0);
  theme_apply_transparent_container(result_content);
  lv_obj_clear_flag(result_content, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(result_content, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(result_content, LV_FLEX_ALIGN_SPACE_EVENLY,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_column(result_content, theme_get_default_padding(), 0);

  create_word_labels(result_content);

  int32_t pad = theme_get_default_padding();
  load_btn = theme_create_button(bip85_screen, "Load", true);
  lv_obj_set_size(load_btn, 140, theme_get_min_touch_size());
  lv_obj_align(load_btn, LV_ALIGN_BOTTOM_RIGHT, -pad / 3, -pad / 3);
  lv_obj_add_event_cb(load_btn, load_btn_cb, LV_EVENT_CLICKED, NULL);
}

static void derive_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed) {
    if (return_callback)
      return_callback();
    return;
  }

  if (!derive_child_mnemonic()) {
    dialog_show_error_timeout("Failed to derive BIP85 mnemonic",
                              return_callback, 0);
    return;
  }

  create_result_ui();
}

static void request_derivation_confirmation(void) {
  dialog_show_danger_confirm(DIALOG_SENSITIVE_DATA_WARNING, derive_confirm_cb,
                             NULL, DIALOG_STYLE_OVERLAY);
}

static void index_submit_cb(uint32_t value, void *user_data) {
  (void)user_data;
  selected_child_index = value;
  request_derivation_confirmation();
}

static void index_cancel_cb(void *user_data) {
  (void)user_data;
  create_word_count_menu();
}

static void open_index_keypad(void) {
  ui_numeric_keypad_config_t config = {
      .title = "Child Index",
      .initial_value = selected_child_index,
      .max_value = BIP85_INDEX_MAX,
      .max_digits = 10,
      .invalid_message = "Invalid child index",
      .submit_cb = index_submit_cb,
      .cancel_cb = index_cancel_cb,
      .user_data = NULL,
  };
  ui_numeric_keypad_open(&index_keypad, &config);
}

static void on_word_count_selected(int word_count) {
  selected_word_count = word_count;
  selected_child_index = 0;
  if (bip85_screen)
    lv_obj_add_flag(bip85_screen, LV_OBJ_FLAG_HIDDEN);
  open_index_keypad();
}

static void word_count_back_cb(void) {
  if (return_callback)
    return_callback();
}

static void create_word_count_menu(void) {
  cleanup_flow_ui();
  if (bip85_screen)
    lv_obj_clear_flag(bip85_screen, LV_OBJ_FLAG_HIDDEN);
  ui_word_count_selector_create(bip85_screen, word_count_back_cb,
                                on_word_count_selected);
}

void bip85_page_create(lv_obj_t *parent, void (*return_cb)(void),
                       void (*success_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;
  success_callback = success_cb;
  selected_word_count = 0;
  selected_child_index = 0;
  clear_child_mnemonic();

  bip85_screen = theme_create_page_container(parent);
  create_word_count_menu();
}

void bip85_page_show(void) {
  if (bip85_screen)
    lv_obj_clear_flag(bip85_screen, LV_OBJ_FLAG_HIDDEN);
}

void bip85_page_hide(void) {
  if (bip85_screen)
    lv_obj_add_flag(bip85_screen, LV_OBJ_FLAG_HIDDEN);
  ui_numeric_keypad_close(&index_keypad);
}

void bip85_page_destroy(void) {
  cleanup_flow_ui();
  clear_child_mnemonic();

  if (bip85_screen) {
    lv_obj_del(bip85_screen);
    bip85_screen = NULL;
  }

  return_callback = NULL;
  success_callback = NULL;
  selected_word_count = 0;
  selected_child_index = 0;
}
