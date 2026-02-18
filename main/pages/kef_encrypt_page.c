/*
 * KEF Encrypt Page
 *
 * Shared encryption flow: fingerprint/custom ID prompt, two-step key
 * confirmation, and background encryption on CPU 1.  On success the
 * caller-supplied callback receives the encrypted KEF envelope.
 *
 * Mirrors the kef_decrypt_page pattern.
 */

#include "kef_encrypt_page.h"
#include "../core/kef.h"
#include "../core/key.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/theme.h"
#include "../utils/secure_mem.h"

#include <esp_task_wdt.h>
#include <freertos/FreeRTOS.h>
#include <freertos/idf_additions.h>
#include <freertos/task.h>
#include <stdlib.h>
#include <string.h>

#define KEF_ITERATIONS 100000
#define ENCRYPT_TASK_STACK_SIZE 8192

static lv_obj_t *overlay_screen = NULL;
static lv_obj_t *overlay_title = NULL;
static lv_obj_t *progress_dialog = NULL;
static ui_text_input_t text_input = {0};
static lv_obj_t *strength_label = NULL;

static void (*return_callback)(void) = NULL;
static kef_encrypt_success_cb_t success_callback = NULL;

/* Data to encrypt (copied from caller) */
static uint8_t *data_copy = NULL;
static size_t data_copy_len = 0;

/* KEF ID (fingerprint or custom) */
static char kef_id[64] = {0};

/* Background encryption task */
static TaskHandle_t encrypt_task_handle = NULL;
static lv_timer_t *encrypt_poll_timer = NULL;
static volatile bool encrypt_done = false;
static kef_error_t encrypt_result = KEF_OK;

/* Key material */
static uint8_t *encrypt_key_copy = NULL;
static size_t encrypt_key_copy_len = 0;
static uint8_t *encrypt_envelope = NULL;
static size_t encrypt_envelope_len = 0;

/* Key confirmation (two-step entry) */
static uint8_t *confirm_key = NULL;
static size_t confirm_key_len = 0;

/* ---------- Forward declarations ---------- */

static void show_password_input(void);

/* ---------- Key strength indicator ---------- */

typedef enum {
  KEY_STRENGTH_NONE,
  KEY_STRENGTH_WEAK,
  KEY_STRENGTH_FAIR,
  KEY_STRENGTH_GOOD,
  KEY_STRENGTH_STRONG,
} key_strength_t;

static key_strength_t calculate_key_strength(const char *text) {
  if (!text || text[0] == '\0')
    return KEY_STRENGTH_NONE;

  size_t len = strlen(text);
  int has_lower = 0, has_upper = 0, has_digit = 0, has_symbol = 0;

  for (size_t i = 0; i < len; i++) {
    char c = text[i];
    if (c >= 'a' && c <= 'z')
      has_lower = 1;
    else if (c >= 'A' && c <= 'Z')
      has_upper = 1;
    else if (c >= '0' && c <= '9')
      has_digit = 1;
    else
      has_symbol = 1;
  }

  int classes = has_lower + has_upper + has_digit + has_symbol;

  if (len < 6)
    return KEY_STRENGTH_WEAK;
  if (len < 8)
    return (classes >= 3) ? KEY_STRENGTH_FAIR : KEY_STRENGTH_WEAK;
  if (len < 12)
    return (classes >= 3) ? KEY_STRENGTH_GOOD : KEY_STRENGTH_FAIR;
  return (classes >= 3) ? KEY_STRENGTH_STRONG : KEY_STRENGTH_GOOD;
}

static const char *strength_text(key_strength_t s) {
  switch (s) {
  case KEY_STRENGTH_WEAK:
    return "Weak";
  case KEY_STRENGTH_FAIR:
    return "Fair";
  case KEY_STRENGTH_GOOD:
    return "Good";
  case KEY_STRENGTH_STRONG:
    return "Strong";
  default:
    return "";
  }
}

static lv_color_t strength_color(key_strength_t s) {
  switch (s) {
  case KEY_STRENGTH_WEAK:
    return error_color();
  case KEY_STRENGTH_FAIR:
    return highlight_color();
  case KEY_STRENGTH_GOOD:
  case KEY_STRENGTH_STRONG:
    return yes_color();
  default:
    return lv_color_white();
  }
}

static void key_changed_cb(lv_event_t *e) {
  (void)e;
  if (!strength_label || !text_input.textarea)
    return;

  /* Only show strength during first entry, not confirm step */
  if (confirm_key) {
    lv_label_set_text(strength_label, "");
    return;
  }

  const char *text = lv_textarea_get_text(text_input.textarea);
  key_strength_t s = calculate_key_strength(text);

  if (s == KEY_STRENGTH_NONE) {
    lv_label_set_text(strength_label, "");
  } else {
    lv_label_set_text(strength_label, strength_text(s));
    lv_obj_set_style_text_color(strength_label, strength_color(s), 0);
  }
}

/* ---------- Overlay management ---------- */

static void destroy_overlay(void) {
  if (encrypt_task_handle) {
    vTaskDelete(encrypt_task_handle);
    encrypt_task_handle = NULL;
  }
  if (encrypt_poll_timer) {
    lv_timer_del(encrypt_poll_timer);
    encrypt_poll_timer = NULL;
  }
  encrypt_done = false;
  ui_text_input_destroy(&text_input);

  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }
  if (overlay_screen) {
    lv_obj_del(overlay_screen);
    overlay_screen = NULL;
  }

  SECURE_FREE_BUFFER(encrypt_key_copy, encrypt_key_copy_len);
  encrypt_key_copy_len = 0;
  SECURE_FREE_BUFFER(confirm_key, confirm_key_len);
  confirm_key_len = 0;
  overlay_title = NULL;
  strength_label = NULL;
}

static void cancel_cb(lv_event_t *e) {
  (void)e;
  destroy_overlay();
  if (return_callback)
    return_callback();
}

static void create_overlay(const char *title, const char *placeholder,
                           bool password_mode, lv_event_cb_t ready_cb) {
  destroy_overlay();

  overlay_screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(overlay_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(overlay_screen);
  lv_obj_clear_flag(overlay_screen, LV_OBJ_FLAG_SCROLLABLE);

  overlay_title = theme_create_page_title(overlay_screen, title);
  ui_create_back_button(overlay_screen, cancel_cb);

  ui_text_input_create(&text_input, overlay_screen, placeholder, password_mode,
                       ready_cb);

  if (password_mode) {
    strength_label = lv_label_create(overlay_screen);
    lv_label_set_text(strength_label, "");
    lv_obj_set_style_text_font(strength_label, theme_font_small(), 0);
    lv_obj_align(strength_label, LV_ALIGN_TOP_MID, 0, 195);
    lv_obj_add_event_cb(text_input.keyboard, key_changed_cb,
                        LV_EVENT_VALUE_CHANGED, NULL);
  }
}

/* ---------- Encryption task (runs on CPU 1) ---------- */

static void encrypt_task(void *arg) {
  (void)arg;

  TaskHandle_t idle1 = xTaskGetIdleTaskHandleForCore(1);
  esp_task_wdt_delete(idle1);

  if (encrypt_envelope) {
    SECURE_FREE_BUFFER(encrypt_envelope, encrypt_envelope_len);
    encrypt_envelope_len = 0;
  }

  encrypt_result =
      kef_encrypt((const uint8_t *)kef_id, strlen(kef_id), KEF_V20_GCM_E4,
                  encrypt_key_copy, encrypt_key_copy_len, KEF_ITERATIONS,
                  data_copy, data_copy_len, &encrypt_envelope,
                  &encrypt_envelope_len);

  SECURE_FREE_BUFFER(encrypt_key_copy, encrypt_key_copy_len);
  encrypt_key_copy_len = 0;

  esp_task_wdt_add(idle1);
  encrypt_done = true;
  vTaskDelete(NULL);
}

/* ---------- Poll timer ---------- */

static void encrypt_poll_timer_cb(lv_timer_t *timer) {
  (void)timer;
  if (!encrypt_done)
    return;

  lv_timer_del(encrypt_poll_timer);
  encrypt_poll_timer = NULL;
  encrypt_task_handle = NULL;

  if (encrypt_result == KEF_OK) {
    destroy_overlay();

    if (success_callback)
      success_callback(kef_id, encrypt_envelope, encrypt_envelope_len);
    return;
  }

  /* Encryption error — reset to first key entry for retry */
  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }
  if (overlay_title)
    lv_label_set_text(overlay_title, "Encryption Key");
  ui_text_input_show(&text_input);
  if (text_input.textarea)
    lv_textarea_set_text(text_input.textarea, "");
  if (strength_label)
    lv_obj_clear_flag(strength_label, LV_OBJ_FLAG_HIDDEN);
  dialog_show_error(kef_error_str(encrypt_result), NULL, 0);
}

/* ---------- Password input with confirmation ---------- */

static void password_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(text_input.textarea);
  if (!text || text[0] == '\0')
    return;

  size_t len = strlen(text);

  if (!confirm_key) {
    /* First entry — save and ask for confirmation */
    confirm_key = malloc(len);
    if (!confirm_key)
      return;
    memcpy(confirm_key, text, len);
    confirm_key_len = len;
    lv_textarea_set_text(text_input.textarea, "");
    if (overlay_title)
      lv_label_set_text(overlay_title, "Confirm Key");
    if (strength_label)
      lv_obj_add_flag(strength_label, LV_OBJ_FLAG_HIDDEN);
    return;
  }

  /* Second entry — compare */
  if (len != confirm_key_len || memcmp(text, confirm_key, len) != 0) {
    SECURE_FREE_BUFFER(confirm_key, confirm_key_len);
    confirm_key_len = 0;
    lv_textarea_set_text(text_input.textarea, "");
    if (overlay_title)
      lv_label_set_text(overlay_title, "Encryption Key");
    if (strength_label)
      lv_obj_clear_flag(strength_label, LV_OBJ_FLAG_HIDDEN);
    dialog_show_error("Keys don't match", NULL, 0);
    return;
  }

  /* Match — transfer to encrypt_key_copy and proceed */
  encrypt_key_copy = confirm_key;
  encrypt_key_copy_len = confirm_key_len;
  confirm_key = NULL;
  confirm_key_len = 0;

  lv_textarea_set_text(text_input.textarea, "");

  /* Show loading state */
  ui_text_input_hide(&text_input);
  progress_dialog =
      dialog_show_progress("KEF", "Encrypting...", DIALOG_STYLE_OVERLAY);

  /* Launch encryption on CPU 1 */
  encrypt_done = false;
  if (xTaskCreatePinnedToCore(encrypt_task, "kef_enc", ENCRYPT_TASK_STACK_SIZE,
                              NULL, 5, &encrypt_task_handle, 1) != pdPASS) {
    SECURE_FREE_BUFFER(encrypt_key_copy, encrypt_key_copy_len);
    encrypt_key_copy_len = 0;
    if (progress_dialog) {
      lv_obj_del(progress_dialog);
      progress_dialog = NULL;
    }
    ui_text_input_show(&text_input);
    dialog_show_error("Task creation failed", NULL, 0);
    return;
  }

  encrypt_poll_timer = lv_timer_create(encrypt_poll_timer_cb, 100, NULL);
}

static void show_password_input(void) {
  create_overlay("Encryption Key", "key", true, password_ready_cb);
}

/* ---------- ID input ---------- */

static void id_keyboard_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(text_input.textarea);
  if (!text || text[0] == '\0')
    return;

  size_t len = strlen(text);
  if (len >= sizeof(kef_id))
    len = sizeof(kef_id) - 1;
  memcpy(kef_id, text, len);
  kef_id[len] = '\0';

  destroy_overlay();
  show_password_input();
}

static void id_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed) {
    show_password_input();
  } else {
    create_overlay("Custom ID", "ID", false, id_keyboard_ready_cb);
  }
}

/* ---------- Page lifecycle ---------- */

void kef_encrypt_page_create(lv_obj_t *parent, void (*return_cb)(void),
                              kef_encrypt_success_cb_t success_cb,
                              const uint8_t *data, size_t data_len) {
  (void)parent;
  if (!data || data_len == 0)
    return;

  return_callback = return_cb;
  success_callback = success_cb;

  /* Copy data to encrypt */
  data_copy = malloc(data_len);
  if (!data_copy)
    return;
  memcpy(data_copy, data, data_len);
  data_copy_len = data_len;

  /* Get fingerprint and prompt for ID */
  char fp_hex[9] = {0};
  if (!key_get_fingerprint_hex(fp_hex)) {
    SECURE_FREE_BUFFER(data_copy, data_copy_len);
    data_copy_len = 0;
    dialog_show_error("Failed to get fingerprint", return_cb, 0);
    return;
  }
  snprintf(kef_id, sizeof(kef_id), "%s", fp_hex);

  char msg[80];
  snprintf(msg, sizeof(msg), "Use fingerprint %s as backup ID?", fp_hex);
  dialog_show_confirm(msg, id_confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
}

void kef_encrypt_page_show(void) {
  if (overlay_screen)
    lv_obj_clear_flag(overlay_screen, LV_OBJ_FLAG_HIDDEN);
}

void kef_encrypt_page_hide(void) {
  if (overlay_screen)
    lv_obj_add_flag(overlay_screen, LV_OBJ_FLAG_HIDDEN);
}

void kef_encrypt_page_destroy(void) {
  destroy_overlay();

  SECURE_FREE_BUFFER(data_copy, data_copy_len);
  data_copy_len = 0;
  SECURE_FREE_BUFFER(encrypt_envelope, encrypt_envelope_len);
  encrypt_envelope_len = 0;

  return_callback = NULL;
  success_callback = NULL;
  secure_memzero(kef_id, sizeof(kef_id));
}
