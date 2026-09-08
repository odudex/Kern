// Load Descriptor Storage Page — list and load descriptors from flash or SD

#include "load_descriptor_storage.h"
#include "../core/bip138_backup.h"
#include "../core/kef.h"
#include "../core/registry.h"
#include "../core/storage.h"
#include "../ui/dialog.h"
#include "../utils/secure_mem.h"
#include "../utils/session_cleanup.h"
#include "sd_card.h"
#include "shared/descriptor_loader.h"
#include "shared/kef_decrypt_page.h"
#include "shared/sd_file_browser.h"
#include "shared/storage_browser.h"
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

static void (*success_callback)(void) = NULL;
static char *pending_kef_descriptor = NULL;

/* Flash uses the fixed-folder storage_browser (SPIFFS is flat); SD browses
 * anywhere on the card via sd_file_browser. */
static enum { BROWSER_STORAGE, BROWSER_SD } active_browser = BROWSER_STORAGE;

static void browser_show(void) {
  if (active_browser == BROWSER_SD)
    sd_file_browser_show();
  else
    storage_browser_show();
}

static void browser_hide(void) {
  if (active_browser == BROWSER_SD)
    sd_file_browser_hide();
  else
    storage_browser_hide();
}

/* ---------- Descriptor validation callback ---------- */

static void success_callback_wrapper(void) {
  if (success_callback)
    success_callback();
}

static void descriptor_validation_cb(descriptor_validation_result_t result,
                                     void *user_data) {
  if (result == VALIDATION_SUCCESS) {
    free(pending_kef_descriptor);
    pending_kef_descriptor = NULL;
    descriptor_loader_show_loaded_menu(success_callback_wrapper);
    return;
  }

  free(pending_kef_descriptor);
  pending_kef_descriptor = NULL;
  descriptor_loader_show_error(result);
  browser_show();
}

/* ---------- Decrypt callbacks ---------- */

static void return_from_kef_decrypt(void) {
  kef_decrypt_page_destroy();
  browser_show();
}

static void success_from_kef_decrypt(const uint8_t *data, size_t len) {
  /* Copy decrypted data BEFORE destroying the page (data is page-owned) */
  char *descriptor_str = malloc(len + 1);
  if (!descriptor_str) {
    kef_decrypt_page_destroy();
    dialog_show_error_timeout("Out of memory", NULL, 0);
    browser_show();
    return;
  }
  memcpy(descriptor_str, data, len);
  descriptor_str[len] = '\0';

  kef_decrypt_page_destroy();
  browser_hide();

  free(pending_kef_descriptor);
  pending_kef_descriptor = descriptor_str;
  descriptor_str = NULL;

  descriptor_loader_process_string(pending_kef_descriptor,
                                   descriptor_validation_cb, (void *)1);
}

/* ---------- Shared load tails (flash + SD) ---------- */

/* Hand a validated KEF envelope to the decrypt page; the caller keeps ownership
 * of the buffer (the page copies it). */
static void decrypt_envelope(uint8_t *envelope, size_t env_len) {
  browser_hide();
  kef_decrypt_page_create(lv_screen_active(), return_from_kef_decrypt,
                          success_from_kef_decrypt, envelope, env_len);
  kef_decrypt_page_show();
}

static void process_plaintext(const uint8_t *data, size_t len) {
  char *descriptor_str = malloc(len + 1);
  if (!descriptor_str) {
    dialog_show_error_timeout("Out of memory", NULL, 0);
    return;
  }
  memcpy(descriptor_str, data, len);
  descriptor_str[len] = '\0';

  browser_hide();
  descriptor_loader_process_string(descriptor_str, descriptor_validation_cb,
                                   NULL);
  free(descriptor_str);
}

/* A BIP138 backup opens only with a key present in its descriptor. Opening
 * one may derive several xpubs, so it runs behind a progress dialog from a
 * one-shot timer, like the other slow flows. */
static uint8_t *pending_bip138 = NULL;
static size_t pending_bip138_len = 0;
static lv_obj_t *bip138_progress = NULL;

static void deferred_bip138_cb(lv_timer_t *timer) {
  (void)timer;
  char *descriptor_str = NULL;
  bool opened = bip138_backup_decrypt_any(pending_bip138, pending_bip138_len,
                                          &descriptor_str, NULL);
  free(pending_bip138);
  pending_bip138 = NULL;
  pending_bip138_len = 0;
  if (bip138_progress) {
    lv_obj_del(bip138_progress);
    bip138_progress = NULL;
  }
  if (!opened) {
    dialog_show_error_timeout("Backup is not addressed to the loaded key", NULL,
                              0);
    return;
  }
  browser_hide();
  descriptor_loader_process_string(descriptor_str, descriptor_validation_cb,
                                   NULL);
  SECURE_FREE_STRING(descriptor_str);
}

static void process_bip138(const uint8_t *data, size_t len) {
  free(pending_bip138);
  pending_bip138 = malloc(len);
  if (!pending_bip138) {
    dialog_show_error_timeout("Out of memory", NULL, 0);
    return;
  }
  memcpy(pending_bip138, data, len);
  pending_bip138_len = len;
  bip138_progress = dialog_show_progress(
      "Descriptor Backup", "Opening backup...", DIALOG_STYLE_OVERLAY);
  lv_timer_t *t = lv_timer_create(deferred_bip138_cb, 50, NULL);
  lv_timer_set_repeat_count(t, 1);
}

/* Flash storage_browser callback: load by filename, format from extension. */
static void load_selected(int idx, const char *filename) {
  (void)idx;

  uint8_t *data = NULL;
  size_t data_len = 0;
  storage_descriptor_format_t format = STORAGE_DESCRIPTOR_TXT;

  if (storage_load_descriptor(storage_browser_get_location(), filename, &data,
                              &data_len, &format) != ESP_OK) {
    dialog_show_error_timeout("Failed to load file", NULL, 0);
    return;
  }

  switch (format) {
  case STORAGE_DESCRIPTOR_KEF:
    if (kef_is_envelope(data, data_len))
      decrypt_envelope(data, data_len);
    else
      dialog_show_error_timeout("Invalid encrypted data", NULL, 0);
    break;
  case STORAGE_DESCRIPTOR_BIP138:
    process_bip138(data, data_len);
    break;
  default:
    process_plaintext(data, data_len);
    break;
  }
  free(data);
}

/* SD sd_file_browser callback: browse anywhere, KEF detected by content so
 * arbitrarily named files load correctly. */
static void sd_desc_on_file_selected(const char *full_path, const char *dir,
                                     const char *name) {
  (void)dir;
  (void)name;

  uint8_t *data = NULL;
  size_t len = 0;
  if (sd_card_read_file(full_path, &data, &len) != ESP_OK || !data ||
      len == 0) {
    free(data);
    dialog_show_error_timeout("Failed to read file", NULL, 0);
    return;
  }

  size_t env_len = 0;
  uint8_t *envelope = kef_envelope_from_bytes(data, len, &env_len);
  if (envelope) {
    decrypt_envelope(envelope, env_len);
    free(envelope); /* kef_decrypt_page copies it */
    free(data);
    return;
  }

  if (bip138_backup_detect(data, len))
    process_bip138(data, len);
  else
    process_plaintext(data, len);
  free(data);
}

/* ---------- Display name ---------- */

/* A registered backup is already in the session and is managed from Session
 * Descriptors, so the flash list leaves it out. Other BIP138 files stay
 * listed: they belong to another key or lack this device's approval mark. */
static bool is_registered_backup(storage_location_t loc, const char *filename) {
  if (loc != STORAGE_FLASH ||
      storage_descriptor_format(filename) != STORAGE_DESCRIPTOR_BIP138)
    return false;
  const char *start = filename;
  size_t prefix_len = strlen(STORAGE_DESCRIPTOR_PREFIX);
  if (strncmp(start, STORAGE_DESCRIPTOR_PREFIX, prefix_len) == 0)
    start += prefix_len;
  size_t id_len = strlen(start) - strlen(STORAGE_DESCRIPTOR_EXT_BIP138);
  char id[REGISTRY_ID_MAX_LEN];
  if (id_len >= sizeof(id))
    id_len = sizeof(id) - 1;
  memcpy(id, start, id_len);
  id[id_len] = '\0';
  const registry_entry_t *entry = registry_find_by_id(id);
  return entry && entry->persisted && entry->loc == STORAGE_FLASH;
}

static esp_err_t list_loadable_descriptors(storage_location_t loc,
                                           char ***files_out, int *count_out) {
  esp_err_t ret = storage_list_descriptors(loc, files_out, count_out);
  if (ret != ESP_OK)
    return ret;
  int kept = 0;
  for (int i = 0; i < *count_out; i++) {
    if (is_registered_backup(loc, (*files_out)[i]))
      free((*files_out)[i]);
    else
      (*files_out)[kept++] = (*files_out)[i];
  }
  *count_out = kept;
  return ESP_OK;
}

static char *get_display_name(storage_location_t loc, const char *filename) {
  if (storage_descriptor_format(filename) == STORAGE_DESCRIPTOR_KEF) {
    uint8_t *data = NULL;
    size_t data_len = 0;

    if (storage_load_descriptor(loc, filename, &data, &data_len, NULL) !=
        ESP_OK)
      return strdup(filename);

    char *name = storage_get_kef_display_name(data, data_len);
    free(data);
    return name ? name : strdup(filename);
  }

  /* Plaintext and BIP138 files: strip prefix and extension for display */
  const char *start = filename;
  size_t prefix_len = strlen(STORAGE_DESCRIPTOR_PREFIX);

  /* On flash, filenames have d_ prefix; on SD they don't */
  if (strncmp(start, STORAGE_DESCRIPTOR_PREFIX, prefix_len) == 0)
    start += prefix_len;

  static const char *const exts[] = {STORAGE_DESCRIPTOR_EXT_BIP138_SD,
                                     STORAGE_DESCRIPTOR_EXT_BIP138,
                                     STORAGE_DESCRIPTOR_EXT_TXT};
  size_t slen = strlen(start);
  size_t name_len = slen;
  for (size_t i = 0; i < sizeof(exts) / sizeof(exts[0]); i++) {
    size_t ext_len = strlen(exts[i]);
    if (slen > ext_len && strcmp(start + slen - ext_len, exts[i]) == 0) {
      name_len = slen - ext_len;
      break;
    }
  }

  char *name = malloc(name_len + 1);
  if (name) {
    memcpy(name, start, name_len);
    name[name_len] = '\0';
  }
  return name;
}

/* ---------- Page lifecycle ---------- */

void load_descriptor_storage_page_create(lv_obj_t *parent,
                                         void (*return_cb)(void),
                                         void (*success_cb)(void),
                                         storage_location_t location) {
  session_cleanup_register(load_descriptor_storage_page_destroy);
  if (!parent)
    return;

  success_callback = success_cb;

  if (location == STORAGE_SD) {
    active_browser = BROWSER_SD;
    sd_file_browser_config_t config = {
        .title = "Load Descriptor",
        .on_file_selected = sd_desc_on_file_selected,
        .return_cb = return_cb,
    };
    sd_file_browser_create(parent, &config);
    return;
  }

  active_browser = BROWSER_STORAGE;
  storage_browser_config_t config = {
      .item_type_name = "descriptor",
      .location = location,
      .list_files = list_loadable_descriptors,
      .delete_file = storage_delete_descriptor,
      .get_display_name = get_display_name,
      .load_selected = load_selected,
      .return_cb = return_cb,
  };

  storage_browser_create(parent, &config);
}

void load_descriptor_storage_page_show(void) { browser_show(); }

void load_descriptor_storage_page_hide(void) { browser_hide(); }

void load_descriptor_storage_page_destroy(void) {
  session_cleanup_unregister(load_descriptor_storage_page_destroy);
  free(pending_bip138);
  pending_bip138 = NULL;
  pending_bip138_len = 0;
  if (bip138_progress) {
    lv_obj_del(bip138_progress);
    bip138_progress = NULL;
  }
  kef_decrypt_page_destroy();
  if (active_browser == BROWSER_SD)
    sd_file_browser_destroy();
  else
    storage_browser_destroy();
  active_browser = BROWSER_STORAGE;
  success_callback = NULL;
}
