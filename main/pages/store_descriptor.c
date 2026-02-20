// Store Descriptor Page — save descriptor to flash or SD card

#include "store_descriptor.h"
#include "../core/storage.h"
#include "../core/wallet.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/theme.h"
#include "shared/kef_encrypt_page.h"

#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

static lv_obj_t *main_screen = NULL;
static lv_obj_t *progress_dialog = NULL;
static lv_timer_t *save_timer = NULL;
static void (*return_callback)(void) = NULL;
static storage_location_t target_location;
static bool target_encrypted;

/* Descriptor text to save */
static char *descriptor_text = NULL;

/* Pending save (encrypted path — valid between encrypt success and save) */
static const uint8_t *pending_envelope = NULL;
static size_t pending_envelope_len = 0;
static const char *pending_id = NULL;

/* Plaintext path — ID text input */
static ui_text_input_t id_input = {0};
static bool id_input_created = false;

/* ---------- Navigation ---------- */

static void go_back(void) {
  if (return_callback)
    return_callback();
}

/* ---------- Save result handling ---------- */

static void save_success_dialog_cb(void *user_data) {
  (void)user_data;
  go_back();
}

static void do_save_encrypted(void) {
  esp_err_t ret =
      storage_save_descriptor(target_location, pending_id, pending_envelope,
                              pending_envelope_len, true);

  pending_envelope = NULL;
  pending_envelope_len = 0;
  pending_id = NULL;

  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }
  kef_encrypt_page_destroy();

  if (ret == ESP_OK) {
    const char *loc_name =
        (target_location == STORAGE_FLASH) ? "flash" : "SD card";
    char msg[64];
    snprintf(msg, sizeof(msg), "Descriptor saved to %s", loc_name);
    dialog_show_info("Saved", msg, save_success_dialog_cb, NULL,
                     DIALOG_STYLE_OVERLAY);
  } else {
    dialog_show_error("Failed to save", go_back, 0);
  }
}

static void do_save_plaintext(const char *id) {
  esp_err_t ret = storage_save_descriptor(target_location, id,
                                          (const uint8_t *)descriptor_text,
                                          strlen(descriptor_text), false);

  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }

  if (ret == ESP_OK) {
    const char *loc_name =
        (target_location == STORAGE_FLASH) ? "flash" : "SD card";
    char msg[64];
    snprintf(msg, sizeof(msg), "Descriptor saved to %s", loc_name);
    dialog_show_info("Saved", msg, save_success_dialog_cb, NULL,
                     DIALOG_STYLE_OVERLAY);
  } else {
    dialog_show_error("Failed to save", go_back, 0);
  }
}

/* ---------- Overwrite confirmation ---------- */

static char pending_plaintext_id[STORAGE_MAX_SANITIZED_ID_LEN + 1];

static void overwrite_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed) {
    if (target_encrypted) {
      do_save_encrypted();
    } else {
      do_save_plaintext(pending_plaintext_id);
    }
  } else {
    if (target_encrypted) {
      pending_envelope = NULL;
      pending_envelope_len = 0;
      pending_id = NULL;
      if (progress_dialog) {
        lv_obj_del(progress_dialog);
        progress_dialog = NULL;
      }
      kef_encrypt_page_destroy();
    }
    go_back();
  }
}

/* ---------- Encrypted path — deferred save ---------- */

static void deferred_save_encrypted_cb(lv_timer_t *timer) {
  (void)timer;
  save_timer = NULL;

  if (storage_descriptor_exists(target_location, pending_id, true)) {
    if (progress_dialog) {
      lv_obj_del(progress_dialog);
      progress_dialog = NULL;
    }
    dialog_show_danger_confirm(
        "A descriptor with this ID\nalready exists. Overwrite?",
        overwrite_confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
    return;
  }

  do_save_encrypted();
}

static void encrypt_return_cb(void) {
  kef_encrypt_page_destroy();
  go_back();
}

static void encrypt_success_cb(const char *id, const uint8_t *envelope,
                               size_t len) {
  pending_envelope = envelope;
  pending_envelope_len = len;
  pending_id = id;

  progress_dialog =
      dialog_show_progress("KEF", "Saving...", DIALOG_STYLE_OVERLAY);
  save_timer = lv_timer_create(deferred_save_encrypted_cb, 50, NULL);
  lv_timer_set_repeat_count(save_timer, 1);
}

/* ---------- Plaintext path — ID input ---------- */

static void deferred_save_plaintext_cb(lv_timer_t *timer) {
  (void)timer;
  save_timer = NULL;

  if (storage_descriptor_exists(target_location, pending_plaintext_id, false)) {
    if (progress_dialog) {
      lv_obj_del(progress_dialog);
      progress_dialog = NULL;
    }
    dialog_show_danger_confirm(
        "A descriptor with this ID already exists. Overwrite?",
        overwrite_confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
    return;
  }

  do_save_plaintext(pending_plaintext_id);
}

static void id_input_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(id_input.textarea);
  if (!text || strlen(text) == 0) {
    dialog_show_error("Please enter an ID", NULL, 2000);
    return;
  }

  snprintf(pending_plaintext_id, sizeof(pending_plaintext_id), "%s", text);
  ui_text_input_hide(&id_input);

  progress_dialog = dialog_show_progress("Saving", "Saving descriptor...",
                                         DIALOG_STYLE_OVERLAY);
  save_timer = lv_timer_create(deferred_save_plaintext_cb, 50, NULL);
  lv_timer_set_repeat_count(save_timer, 1);
}

/* ---------- Page lifecycle ---------- */

void store_descriptor_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                  storage_location_t location, bool encrypted) {
  if (!parent || !wallet_has_descriptor())
    return;

  return_callback = return_cb;
  target_location = location;
  target_encrypted = encrypted;

  /* Get descriptor string */
  if (!wallet_get_descriptor_string(&descriptor_text) || !descriptor_text) {
    dialog_show_error("No descriptor loaded", return_cb, 0);
    return;
  }

  const char *title =
      (location == STORAGE_FLASH) ? "Save to Flash" : "Save to SD Card";
  main_screen = theme_create_page_container(parent);
  lv_obj_t *title_label = lv_label_create(main_screen);
  lv_label_set_text(title_label, title);
  lv_obj_set_style_text_font(title_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(title_label, main_color(), 0);
  lv_obj_align(title_label, LV_ALIGN_CENTER, 0, 0);

  if (encrypted) {
    /* Use the original descriptor checksum as the default backup ID */
    char *checksum = NULL;
    wallet_get_descriptor_checksum(&checksum);

    kef_encrypt_page_create(parent, encrypt_return_cb, encrypt_success_cb,
                            (const uint8_t *)descriptor_text,
                            strlen(descriptor_text), checksum);
    free(checksum);
  } else {
    /* Show ID text input for plaintext save */
    ui_text_input_create(&id_input, parent, "Descriptor name", false,
                         id_input_ready_cb);
    id_input_created = true;
  }
}

void store_descriptor_page_show(void) {
  if (main_screen)
    lv_obj_clear_flag(main_screen, LV_OBJ_FLAG_HIDDEN);
}

void store_descriptor_page_hide(void) {
  if (main_screen)
    lv_obj_add_flag(main_screen, LV_OBJ_FLAG_HIDDEN);
}

void store_descriptor_page_destroy(void) {
  if (save_timer) {
    lv_timer_del(save_timer);
    save_timer = NULL;
  }
  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }

  kef_encrypt_page_destroy();

  if (id_input_created) {
    ui_text_input_destroy(&id_input);
    id_input_created = false;
  }

  pending_envelope = NULL;
  pending_envelope_len = 0;
  pending_id = NULL;
  pending_plaintext_id[0] = '\0';

  if (descriptor_text) {
    free(descriptor_text);
    descriptor_text = NULL;
  }

  if (main_screen) {
    lv_obj_del(main_screen);
    main_screen = NULL;
  }

  return_callback = NULL;
}
