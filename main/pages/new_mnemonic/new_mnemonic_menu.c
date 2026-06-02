// New Mnemonic Menu Page

#include "new_mnemonic_menu.h"
#include "../../ui/dialog.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "../home/home.h"
#include "../load_mnemonic/manual_input.h"
#include "../shared/key_confirmation.h"
#include "../shared/mnemonic_editor.h"
#include "dice_rolls.h"
#include "entropy_from_camera.h"
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

static ui_menu_t *new_mnemonic_menu = NULL;
static lv_obj_t *new_mnemonic_menu_screen = NULL;
static void (*return_callback)(void) = NULL;

static void from_dice_rolls_cb(void);
static void from_words_cb(void);
static void from_camera_cb(void);
static void back_cb(void);
static void return_from_dice_rolls_cb(void);
static void return_from_entropy_from_camera_cb(void);
static void return_from_manual_input_cb(void);
static void return_from_mnemonic_editor_cb(void);
static void return_from_key_confirmation_cb(void);
static void success_from_key_confirmation_cb(void);

static void return_from_dice_rolls_cb(void) {
  char *mnemonic = dice_rolls_get_completed_mnemonic();
  dice_rolls_page_destroy();

  if (mnemonic) {
    mnemonic_editor_page_create(
        lv_screen_active(), return_from_mnemonic_editor_cb,
        success_from_key_confirmation_cb, mnemonic, true);
    mnemonic_editor_page_show();
    free(mnemonic);
  } else {
    new_mnemonic_menu_page_show();
  }
}

static void return_from_entropy_from_camera_cb(void) {
  char *mnemonic = entropy_from_camera_get_completed_mnemonic();
  entropy_from_camera_page_destroy();

  if (mnemonic) {
    mnemonic_editor_page_create(
        lv_screen_active(), return_from_mnemonic_editor_cb,
        success_from_key_confirmation_cb, mnemonic, true);
    mnemonic_editor_page_show();
    free(mnemonic);
  } else {
    new_mnemonic_menu_page_show();
  }
}

static void return_from_manual_input_cb(void) {
  manual_input_page_destroy();
  new_mnemonic_menu_page_show();
}

static void return_from_mnemonic_editor_cb(void) {
  mnemonic_editor_page_destroy();
  new_mnemonic_menu_page_show();
}

static void return_from_key_confirmation_cb(void) {
  key_confirmation_page_destroy();
  new_mnemonic_menu_page_show();
}

static void success_from_key_confirmation_cb(void) {
  key_confirmation_page_destroy();
  new_mnemonic_menu_page_destroy();
  home_page_create(lv_screen_active());
  home_page_show();
}

static void (*pending_action)(void) = NULL;

static void launch_dice_rolls(void) {
  dice_rolls_page_create(lv_screen_active(), return_from_dice_rolls_cb);
  dice_rolls_page_show();
}

static void launch_words(void) {
  manual_input_page_create(lv_screen_active(), return_from_manual_input_cb,
                           success_from_key_confirmation_cb, true);
  manual_input_page_show();
}

static void launch_camera(void) {
  entropy_from_camera_page_create(lv_screen_active(),
                                  return_from_entropy_from_camera_cb);
  entropy_from_camera_page_show();
}

static void danger_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed)
    return;
  new_mnemonic_menu_page_hide();
  pending_action();
}

static void warn_and_launch(void (*action)(void)) {
  pending_action = action;
  dialog_show_danger_confirm(DIALOG_SENSITIVE_DATA_WARNING, danger_confirm_cb,
                             NULL, DIALOG_STYLE_OVERLAY);
}

static void from_dice_rolls_cb(void) { warn_and_launch(launch_dice_rolls); }

static void from_words_cb(void) { warn_and_launch(launch_words); }

static void from_camera_cb(void) { warn_and_launch(launch_camera); }

static void back_cb(void) {
  void (*callback)(void) = return_callback;
  new_mnemonic_menu_page_hide();
  new_mnemonic_menu_page_destroy();
  if (callback)
    callback();
}

void new_mnemonic_menu_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent)
    return;

  return_callback = return_cb;

  new_mnemonic_menu_screen = theme_create_page_container(parent);

  new_mnemonic_menu =
      ui_menu_create(new_mnemonic_menu_screen, "New Mnemonic", back_cb);
  if (!new_mnemonic_menu)
    return;

  ui_menu_add_entry(new_mnemonic_menu, "From Dice Rolls", from_dice_rolls_cb);
  ui_menu_add_entry(new_mnemonic_menu, "From Words", from_words_cb);
  ui_menu_add_entry(new_mnemonic_menu, "From Camera", from_camera_cb);
  ui_menu_show(new_mnemonic_menu);
}

void new_mnemonic_menu_page_show(void) {
  if (new_mnemonic_menu)
    ui_menu_show(new_mnemonic_menu);
}

void new_mnemonic_menu_page_hide(void) {
  if (new_mnemonic_menu)
    ui_menu_hide(new_mnemonic_menu);
}

void new_mnemonic_menu_page_destroy(void) {
  if (new_mnemonic_menu) {
    ui_menu_destroy(new_mnemonic_menu);
    new_mnemonic_menu = NULL;
  }
  if (new_mnemonic_menu_screen) {
    lv_obj_del(new_mnemonic_menu_screen);
    new_mnemonic_menu_screen = NULL;
  }
  return_callback = NULL;
}
