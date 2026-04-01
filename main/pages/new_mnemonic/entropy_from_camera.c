// Entropy From Camera Page - Generate mnemonic from camera entropy

#include "entropy_from_camera.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/theme.h"
#include "../../ui/word_selector.h"
#include "../capture_entropy.h"
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>
#ifdef SIMULATOR
#include <stdio.h>
#endif
#include <wally_bip39.h>
#include <wally_core.h>

#include "../../utils/secure_mem.h"

#define ENTROPY_12_WORDS 16
#define ENTROPY_24_WORDS 32

static lv_obj_t *entropy_screen = NULL;
static lv_obj_t *hash_container = NULL;
static lv_obj_t *proceed_btn = NULL;
static lv_obj_t *back_btn = NULL;
static lv_obj_t *title_label = NULL;
static void (*return_callback)(void) = NULL;
static char *completed_mnemonic = NULL;

static int total_words = 0;
static uint8_t entropy_hash[32];
static bool hash_captured = false;

static void create_word_count_menu(void);
static void show_hash_display(void);
static void cleanup_ui(void);
static void on_word_count_selected(int word_count);
static void back_cb(void);
static void return_from_capture_cb(void);
static void proceed_cb(lv_event_t *e);
static void hash_back_cb(lv_event_t *e);

static void cleanup_ui(void) {
  if (hash_container) {
    lv_obj_del(hash_container);
    hash_container = NULL;
  }
  if (proceed_btn) {
    lv_obj_del(proceed_btn);
    proceed_btn = NULL;
  }
  if (back_btn) {
    lv_obj_del(back_btn);
    back_btn = NULL;
  }
  if (title_label) {
    lv_obj_del(title_label);
    title_label = NULL;
  }
}

static void create_word_count_menu(void) {
  cleanup_ui();
  ui_word_count_selector_create(entropy_screen, back_cb,
                                on_word_count_selected);
}

static void on_word_count_selected(int word_count) {
  total_words = word_count;
  capture_entropy_page_create(lv_screen_active(), return_from_capture_cb);
  capture_entropy_page_show();
  entropy_from_camera_page_hide();
}

static void return_from_capture_cb(void) {
  if (capture_entropy_has_result()) {
    capture_entropy_get_hash(entropy_hash);
    hash_captured = true;
  }
  capture_entropy_page_destroy();

  entropy_from_camera_page_show();

  if (hash_captured) {
    show_hash_display();
  } else {
    create_word_count_menu();
  }
}

static void show_hash_display(void) {
  cleanup_ui();

  char title_text[32];
  snprintf(title_text, sizeof(title_text), "%d Words - Entropy", total_words);
  title_label = theme_create_page_title(entropy_screen, title_text);

  back_btn = ui_create_back_button(entropy_screen, hash_back_cb);

  hash_container = lv_obj_create(entropy_screen);
  lv_obj_set_size(hash_container, LV_PCT(90), LV_SIZE_CONTENT);
  lv_obj_align(hash_container, LV_ALIGN_CENTER, 0, -40);
  theme_apply_transparent_container(hash_container);
  lv_obj_clear_flag(hash_container, LV_OBJ_FLAG_SCROLLABLE);

  char display_text[128];
  char hex_hash[65];
  for (int i = 0; i < 32; i++) {
    snprintf(hex_hash + i * 2, 3, "%02x", entropy_hash[i]);
  }
  snprintf(display_text, sizeof(display_text), "SHA256 of snapshot:\n%s",
           hex_hash);

  lv_obj_t *hash_label = lv_label_create(hash_container);
  lv_label_set_text(hash_label, display_text);
  lv_obj_set_width(hash_label, LV_PCT(100));
  lv_label_set_long_mode(hash_label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(hash_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_color(hash_label, highlight_color(), 0);
  lv_obj_set_style_text_font(hash_label, theme_font_small(), 0);

  proceed_btn = theme_create_button(entropy_screen, "Proceed", true);
  lv_obj_align(proceed_btn, LV_ALIGN_BOTTOM_MID, 0, -40);
  lv_obj_add_event_cb(proceed_btn, proceed_cb, LV_EVENT_CLICKED, NULL);

  lv_obj_t *btn_label = lv_obj_get_child(proceed_btn, 0);
  if (btn_label) {
    theme_apply_button_label(btn_label, false);
  }
}

static void hash_back_cb(lv_event_t *e) {
  (void)e;
  hash_captured = false;
  secure_memzero(entropy_hash, sizeof(entropy_hash));
  create_word_count_menu();
}

static void proceed_cb(lv_event_t *e) {
  (void)e;

  size_t entropy_len =
      (total_words == 12) ? ENTROPY_12_WORDS : ENTROPY_24_WORDS;

  char *mnemonic = NULL;
  if (bip39_mnemonic_from_bytes(NULL, entropy_hash, entropy_len, &mnemonic) !=
          WALLY_OK ||
      !mnemonic) {
    dialog_show_error("Failed to generate mnemonic", NULL, 0);
    return;
  }

  if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    wally_free_string(mnemonic);
    dialog_show_error("Invalid mnemonic generated", NULL, 0);
    return;
  }

  if (completed_mnemonic)
    free(completed_mnemonic);
  completed_mnemonic = strdup(mnemonic);
  wally_free_string(mnemonic);

  secure_memzero(entropy_hash, sizeof(entropy_hash));
  hash_captured = false;

  entropy_from_camera_page_hide();
  if (return_callback)
    return_callback();
}

static void back_cb(void) {
  void (*callback)(void) = return_callback;
  entropy_from_camera_page_hide();
  entropy_from_camera_page_destroy();
  if (callback)
    callback();
}

void entropy_from_camera_page_create(lv_obj_t *parent,
                                     void (*return_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;

  if (completed_mnemonic) {
    free(completed_mnemonic);
    completed_mnemonic = NULL;
  }

  total_words = 0;
  hash_captured = false;
  secure_memzero(entropy_hash, sizeof(entropy_hash));

  entropy_screen = theme_create_page_container(parent);

  create_word_count_menu();
}

void entropy_from_camera_page_show(void) {
  if (entropy_screen)
    lv_obj_clear_flag(entropy_screen, LV_OBJ_FLAG_HIDDEN);
}

void entropy_from_camera_page_hide(void) {
  if (entropy_screen)
    lv_obj_add_flag(entropy_screen, LV_OBJ_FLAG_HIDDEN);
}

void entropy_from_camera_page_destroy(void) {
  cleanup_ui();

  if (entropy_screen) {
    lv_obj_del(entropy_screen);
    entropy_screen = NULL;
  }

  secure_memzero(entropy_hash, sizeof(entropy_hash));
  hash_captured = false;
  total_words = 0;
  return_callback = NULL;
}

char *entropy_from_camera_get_completed_mnemonic(void) {
  if (completed_mnemonic) {
    char *result = completed_mnemonic;
    completed_mnemonic = NULL;
    return result;
  }
  return NULL;
}
