/*
 * KEF Decrypt Page
 * Key entry + decryption for KEF-encrypted data.
 * Follows the same pattern as passphrase.c.
 *
 * Decryption (PBKDF2 with 100k+ iterations) runs on a separate FreeRTOS
 * task to avoid triggering the watchdog on the LVGL task.  An LVGL timer
 * polls for completion and handles the result on the UI thread.
 */

#include "kef_decrypt_page.h"
#include "../../core/kef.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/theme.h"
#include "../../utils/secure_mem.h"
#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/idf_additions.h>
#include <freertos/task.h>
#include <stdlib.h>
#include <string.h>

#define DECRYPT_TASK_STACK_SIZE 8192

static lv_obj_t *kef_screen = NULL;
static lv_obj_t *progress_dialog = NULL;
static ui_text_input_t text_input = {0};
static lv_timer_t *poll_timer = NULL;

static void (*return_callback)(void) = NULL;
static kef_decrypt_success_cb_t success_callback = NULL;

static uint8_t *envelope_copy = NULL;
static size_t envelope_copy_len = 0;
static uint8_t *key_copy = NULL;
static size_t key_copy_len = 0;
static uint8_t *decrypted_data = NULL;
static size_t decrypted_len = 0;

/* Shared state between FreeRTOS task and LVGL timer */
static volatile bool decrypt_done = false;
static kef_error_t decrypt_result = KEF_OK;
static TaskHandle_t decrypt_task_handle = NULL;

static void show_input(void) {
  ui_text_input_show(&text_input);
  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }
}

static void show_loading(void) {
  ui_text_input_hide(&text_input);
  progress_dialog =
      dialog_show_progress("KEF", "Decrypting...", DIALOG_STYLE_OVERLAY);
}

/* Runs on CPU 1 — does NOT touch LVGL */
static void decrypt_task(void *arg) {
  (void)arg;

  /* Temporarily unsubscribe IDLE1 from WDT so PBKDF2 doesn't trigger it */
  TaskHandle_t idle1 = xTaskGetIdleTaskHandleForCore(1);
  esp_task_wdt_delete(idle1);

  /* Free any previous decrypted data */
  if (decrypted_data) {
    SECURE_FREE_BUFFER(decrypted_data, decrypted_len);
    decrypted_len = 0;
  }

  decrypt_result = kef_decrypt(envelope_copy, envelope_copy_len, key_copy,
                               key_copy_len, &decrypted_data, &decrypted_len);

  /* Zero key immediately after use */
  SECURE_FREE_BUFFER(key_copy, key_copy_len);
  key_copy_len = 0;

  /* Re-subscribe IDLE1 to WDT before exiting */
  esp_task_wdt_add(idle1);

  decrypt_done = true;
  vTaskDelete(NULL);
}

/* LVGL timer polls for decrypt task completion */
static void poll_timer_cb(lv_timer_t *timer) {
  (void)timer;
  if (!decrypt_done)
    return;

  /* Task finished — stop polling */
  lv_timer_del(poll_timer);
  poll_timer = NULL;
  decrypt_task_handle = NULL;

  if (decrypt_result == KEF_OK) {
    if (success_callback)
      success_callback(decrypted_data, decrypted_len);
    return;
  }

  /* Show error and let user retry */
  show_input();
  if (text_input.textarea)
    lv_textarea_set_text(text_input.textarea, "");

  if (decrypt_result == KEF_ERR_AUTH) {
    dialog_show_error("Wrong key", NULL, 0);
  } else {
    dialog_show_error(kef_error_str(decrypt_result), NULL, 0);
  }
}

static void keyboard_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(text_input.textarea);
  if (!text || text[0] == '\0')
    return;

  /* Copy key before clearing textarea */
  key_copy_len = strlen(text);
  key_copy = malloc(key_copy_len);
  if (!key_copy)
    return;
  memcpy(key_copy, text, key_copy_len);

  lv_textarea_set_text(text_input.textarea, "");
  show_loading();

  /* Launch decryption on CPU 1 to keep LVGL (CPU 0) responsive */
  decrypt_done = false;
  if (xTaskCreatePinnedToCore(decrypt_task, "kef_dec", DECRYPT_TASK_STACK_SIZE,
                              NULL, 5, &decrypt_task_handle, 1) != pdPASS) {
    /* Fallback: if task creation fails, clean up and show error */
    SECURE_FREE_BUFFER(key_copy, key_copy_len);
    key_copy_len = 0;
    show_input();
    dialog_show_error("Task creation failed", NULL, 0);
    return;
  }

  /* Poll every 100ms for task completion */
  poll_timer = lv_timer_create(poll_timer_cb, 100, NULL);
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

void kef_decrypt_page_create(lv_obj_t *parent, void (*return_cb)(void),
                             kef_decrypt_success_cb_t success_cb,
                             const uint8_t *envelope, size_t envelope_len) {
  (void)parent;
  return_callback = return_cb;
  success_callback = success_cb;

  /* Copy envelope data */
  envelope_copy = malloc(envelope_len);
  if (!envelope_copy)
    return;
  memcpy(envelope_copy, envelope, envelope_len);
  envelope_copy_len = envelope_len;

  /* Parse KEF ID for the title */
  const uint8_t *id = NULL;
  size_t id_len = 0;
  uint8_t version;
  uint32_t iterations;
  const char *prefix = "Enter Key for: ";
  char title[64] = "Enter Key";
  if (kef_parse_header(envelope, envelope_len, &id, &id_len, &version,
                       &iterations) == KEF_OK &&
      id_len > 0) {
    size_t prefix_len = strlen(prefix);
    size_t copy_len = id_len < sizeof(title) - prefix_len - 1
                          ? id_len
                          : sizeof(title) - prefix_len - 1;
    memcpy(title, prefix, prefix_len);
    memcpy(title + prefix_len, id, copy_len);
    title[prefix_len + copy_len] = '\0';
  }

  /* Screen */
  kef_screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(kef_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(kef_screen);
  lv_obj_clear_flag(kef_screen, LV_OBJ_FLAG_SCROLLABLE);

  /* Title — shows KEF ID if available */
  theme_create_page_title(kef_screen, title);

  /* Back button */
  ui_create_back_button(kef_screen, back_btn_cb);

  /* Text input (textarea + eye toggle + keyboard) */
  ui_text_input_create(&text_input, kef_screen, "key", true, keyboard_ready_cb);

  progress_dialog = NULL;
}

void kef_decrypt_page_show(void) {
  if (kef_screen)
    lv_obj_clear_flag(kef_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_clear_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void kef_decrypt_page_hide(void) {
  if (kef_screen)
    lv_obj_add_flag(kef_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_add_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void kef_decrypt_page_destroy(void) {
  if (decrypt_task_handle) {
    vTaskDelete(decrypt_task_handle);
    decrypt_task_handle = NULL;
  }
  if (poll_timer) {
    lv_timer_del(poll_timer);
    poll_timer = NULL;
  }
  decrypt_done = false;
  ui_text_input_destroy(&text_input);
  if (kef_screen) {
    lv_obj_del(kef_screen);
    kef_screen = NULL;
  }
  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }

  SECURE_FREE_BUFFER(envelope_copy, envelope_copy_len);
  envelope_copy_len = 0;
  SECURE_FREE_BUFFER(key_copy, key_copy_len);
  key_copy_len = 0;
  SECURE_FREE_BUFFER(decrypted_data, decrypted_len);
  decrypted_len = 0;

  return_callback = NULL;
  success_callback = NULL;
}
