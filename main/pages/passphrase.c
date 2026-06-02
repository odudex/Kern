#include "passphrase.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/theme_widgets.h"
#include <lvgl.h>
#include <stdio.h>

static lv_obj_t *passphrase_screen = NULL;
static ui_text_input_t text_input = {0};
static void (*return_callback)(void) = NULL;
static passphrase_success_callback_t success_callback = NULL;

static void back_confirm_cb(bool result, void *user_data) {
  (void)user_data;
  if (result && return_callback)
    return_callback();
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  dialog_show_confirm("Are you sure you want to go back?", back_confirm_cb,
                      NULL, DIALOG_STYLE_OVERLAY);
}

static void confirm_passphrase_cb(bool result, void *user_data) {
  (void)user_data;
  if (result && success_callback)
    success_callback(lv_textarea_get_text(text_input.textarea));
}

static void keyboard_ready_cb(lv_event_t *e) {
  (void)e;
  char prompt[128];
  snprintf(prompt, sizeof(prompt), "Confirm passphrase:\n\"%s\"",
           lv_textarea_get_text(text_input.textarea));
  dialog_show_confirm(prompt, confirm_passphrase_cb, NULL,
                      DIALOG_STYLE_OVERLAY);
}

void passphrase_page_create(lv_obj_t *parent, void (*return_cb)(void),
                            passphrase_success_callback_t success_cb) {
  (void)parent;
  return_callback = return_cb;
  success_callback = success_cb;

  // Screen
  passphrase_screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(passphrase_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(passphrase_screen);
  lv_obj_clear_flag(passphrase_screen, LV_OBJ_FLAG_SCROLLABLE);

  // Create title label
  theme_create_page_title(passphrase_screen, "Enter Passphrase");

  // Back button
  ui_create_back_button(passphrase_screen, back_btn_cb);

  // Text input (textarea + keyboard)
  ui_text_input_create(&text_input, passphrase_screen, "passphrase", false,
                       keyboard_ready_cb);
}

void passphrase_page_show(void) {
  if (passphrase_screen)
    lv_obj_clear_flag(passphrase_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_clear_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void passphrase_page_hide(void) {
  if (passphrase_screen)
    lv_obj_add_flag(passphrase_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_add_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void passphrase_page_destroy(void) {
  ui_text_input_destroy(&text_input);
  if (passphrase_screen) {
    lv_obj_del(passphrase_screen);
    passphrase_screen = NULL;
  }
  return_callback = NULL;
  success_callback = NULL;
}
