// Store Descriptor Page — save descriptor to flash or SD card

#include "store_descriptor.h"
#include "../core/bip138_backup.h"
#include "../core/descriptor_checksum.h"
#include "../core/storage.h"
#include "../core/wallet.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/oneshot.h"
#include "../ui/theme_widgets.h"
#include "../utils/session_cleanup.h"
#include "shared/kef_encrypt_page.h"

#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static lv_obj_t *main_screen = NULL;
static lv_obj_t *progress_dialog = NULL;
static ui_oneshot_t save_timer;
static void (*return_callback)(void) = NULL;
static storage_location_t target_location;
static storage_descriptor_format_t target_format;

/* Descriptor text to save */
static char *descriptor_text = NULL;

/* Pending save (encrypted path — valid between encrypt success and save) */
static const uint8_t *pending_envelope = NULL;
static size_t pending_envelope_len = 0;
static const char *pending_id = NULL;

/* Plaintext path — ID text input */
static ui_text_input_t id_input = {0};
static bool id_input_created = false;
static char descriptor_default_id[9] = {0};

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

static void show_saved(const char *path) {
  char msg[128];
  snprintf(msg, sizeof(msg), "Saved to:\n%s", path);
  dialog_show_info("Saved", msg, save_success_dialog_cb, NULL,
                   DIALOG_STYLE_OVERLAY);
}

static void do_save_kef(void) {
  esp_err_t ret =
      storage_save_descriptor(target_location, pending_id, pending_envelope,
                              pending_envelope_len, STORAGE_DESCRIPTOR_KEF);

  /* Build the path before the cleanup below frees pending_id (page-owned). */
  char path[96];
  storage_descriptor_path(target_location, pending_id, STORAGE_DESCRIPTOR_KEF,
                          path, sizeof(path));

  pending_envelope = NULL;
  pending_envelope_len = 0;
  pending_id = NULL;

  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }
  kef_encrypt_page_destroy();

  if (ret == ESP_OK)
    show_saved(path);
  else
    dialog_show_error_timeout("Failed to save", go_back, 0);
}

/* Plaintext and BIP138 saves share the name prompt; only the bytes differ. */
static void do_save_named(const char *id) {
  esp_err_t ret = ESP_FAIL;
  if (target_format == STORAGE_DESCRIPTOR_BIP138) {
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (bip138_backup_encrypt(descriptor_text, &blob, &blob_len)) {
      ret = storage_save_descriptor(target_location, id, blob, blob_len,
                                    STORAGE_DESCRIPTOR_BIP138);
      free(blob);
    }
  } else {
    ret = storage_save_descriptor(
        target_location, id, (const uint8_t *)descriptor_text,
        strlen(descriptor_text), STORAGE_DESCRIPTOR_TXT);
  }

  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }

  if (ret == ESP_OK) {
    char path[96];
    storage_descriptor_path(target_location, id, target_format, path,
                            sizeof(path));
    show_saved(path);
  } else {
    dialog_show_error_timeout("Failed to save", go_back, 0);
  }
}

/* ---------- Overwrite confirmation ---------- */

static char pending_plaintext_id[STORAGE_MAX_SANITIZED_ID_LEN + 1];

static void overwrite_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed) {
    if (target_format == STORAGE_DESCRIPTOR_KEF) {
      do_save_kef();
    } else {
      do_save_named(pending_plaintext_id);
    }
  } else {
    if (target_format == STORAGE_DESCRIPTOR_KEF) {
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

  if (storage_descriptor_exists(target_location, pending_id,
                                STORAGE_DESCRIPTOR_KEF)) {
    if (progress_dialog) {
      lv_obj_del(progress_dialog);
      progress_dialog = NULL;
    }
    dialog_show_danger_confirm(
        "A descriptor with this ID\nalready exists. Overwrite?",
        overwrite_confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
    return;
  }

  do_save_kef();
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
  ui_oneshot_start(&save_timer, deferred_save_encrypted_cb, 50);
}

/* ---------- Plaintext path — ID input ---------- */

static void deferred_save_plaintext_cb(lv_timer_t *timer) {
  (void)timer;

  if (storage_descriptor_exists(target_location, pending_plaintext_id,
                                target_format)) {
    if (progress_dialog) {
      lv_obj_del(progress_dialog);
      progress_dialog = NULL;
    }
    dialog_show_danger_confirm(
        "A descriptor with this ID already exists. Overwrite?",
        overwrite_confirm_cb, NULL, DIALOG_STYLE_OVERLAY);
    return;
  }

  do_save_named(pending_plaintext_id);
}

static void id_input_back_cb(lv_event_t *e) {
  (void)e;
  go_back();
}

static void id_input_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(id_input.textarea);
  if (!text || strlen(text) == 0) {
    dialog_show_error_timeout("Please enter an ID", NULL, 2000);
    return;
  }

  snprintf(pending_plaintext_id, sizeof(pending_plaintext_id), "%s", text);
  ui_text_input_hide(&id_input);

  progress_dialog = dialog_show_progress("Saving", "Saving descriptor...",
                                         DIALOG_STYLE_OVERLAY);
  ui_oneshot_start(&save_timer, deferred_save_plaintext_cb, 50);
}

/* ---------- Page lifecycle ---------- */

void store_descriptor_page_create_for_descriptor(
    lv_obj_t *parent, void (*return_cb)(void), storage_location_t location,
    storage_descriptor_format_t format,
    const struct wally_descriptor *descriptor) {
  session_cleanup_register(store_descriptor_page_destroy);
  if (!parent || !descriptor)
    return;

  return_callback = return_cb;
  target_location = location;
  target_format = format;
  descriptor_default_id[0] = '\0';

  if (!descriptor_string_from_descriptor(descriptor, &descriptor_text) ||
      !descriptor_text) {
    dialog_show_error_timeout("No descriptor loaded", return_cb, 0);
    return;
  }
  if (!descriptor_checksum_from_descriptor(descriptor, descriptor_default_id))
    descriptor_default_id[0] = '\0'; // the id field opens blank to fill in

  const char *title =
      (location == STORAGE_FLASH) ? "Save to Flash" : "Save to SD Card";
  main_screen = theme_create_page_container(parent);

  if (format == STORAGE_DESCRIPTOR_KEF) {
    lv_obj_t *title_label = lv_label_create(main_screen);
    lv_label_set_text(title_label, title);
    lv_obj_set_style_text_font(title_label, theme_font_medium(), 0);
    lv_obj_set_style_text_color(title_label, primary_color(), 0);
    lv_obj_align(title_label, LV_ALIGN_CENTER, 0, 0);
    kef_encrypt_page_create(
        parent, encrypt_return_cb, encrypt_success_cb,
        (const uint8_t *)descriptor_text, strlen(descriptor_text),
        descriptor_default_id[0] ? descriptor_default_id : NULL, false);
  } else {
    theme_create_page_title(main_screen, title);
    ui_create_back_button(main_screen, id_input_back_cb);
    ui_text_input_create(&id_input, main_screen, "Descriptor name", false,
                         id_input_ready_cb);
    lv_textarea_set_text(id_input.textarea, descriptor_default_id);
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
  session_cleanup_unregister(store_descriptor_page_destroy);
  ui_oneshot_cancel(&save_timer);
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
  descriptor_default_id[0] = '\0';

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
