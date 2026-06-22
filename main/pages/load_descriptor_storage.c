// Load Descriptor Storage Page — list and load descriptors from flash or SD

#include "load_descriptor_storage.h"
#include "../core/kef.h"
#include "../core/storage.h"
#include "../ui/dialog.h"
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

static void success_callback_wrapper(void *user_data) {
  (void)user_data;
  if (success_callback)
    success_callback();
}

static void descriptor_validation_cb(descriptor_validation_result_t result,
                                     void *user_data) {
  if (result == VALIDATION_SUCCESS) {
    if (user_data) {
      free(pending_kef_descriptor);
      pending_kef_descriptor = NULL;
      dialog_show_info("Loaded", "Descriptor loaded for this session",
                       success_callback_wrapper, NULL, DIALOG_STYLE_OVERLAY);
    } else {
      if (success_callback)
        success_callback();
    }
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

/* Flash storage_browser callback: load by filename, KEF detected by extension.
 */
static void load_selected(int idx, const char *filename) {
  (void)idx;

  uint8_t *data = NULL;
  size_t data_len = 0;
  bool encrypted = false;

  if (storage_load_descriptor(storage_browser_get_location(), filename, &data,
                              &data_len, &encrypted) != ESP_OK) {
    dialog_show_error_timeout("Failed to load file", NULL, 0);
    return;
  }

  if (encrypted && !kef_is_envelope(data, data_len)) {
    free(data);
    dialog_show_error_timeout("Invalid encrypted data", NULL, 0);
    return;
  }

  if (encrypted)
    decrypt_envelope(data, data_len);
  else
    process_plaintext(data, data_len);
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

  process_plaintext(data, len);
  free(data);
}

/* ---------- Display name ---------- */

static bool filename_is_kef(const char *filename) {
  size_t len = strlen(filename);
  return len >= 4 &&
         strcmp(filename + len - 4, STORAGE_DESCRIPTOR_EXT_KEF) == 0;
}

static char *get_display_name(storage_location_t loc, const char *filename) {
  if (filename_is_kef(filename)) {
    uint8_t *data = NULL;
    size_t data_len = 0;
    bool encrypted = false;

    if (storage_load_descriptor(loc, filename, &data, &data_len, &encrypted) !=
        ESP_OK)
      return strdup(filename);

    char *name = storage_get_kef_display_name(data, data_len);
    free(data);
    return name ? name : strdup(filename);
  }

  /* For .txt files: strip prefix and extension for display */
  const char *start = filename;
  size_t prefix_len = strlen(STORAGE_DESCRIPTOR_PREFIX);

  /* On flash, filenames have d_ prefix; on SD they don't */
  if (strncmp(start, STORAGE_DESCRIPTOR_PREFIX, prefix_len) == 0)
    start += prefix_len;

  size_t slen = strlen(start);
  size_t ext_len = strlen(STORAGE_DESCRIPTOR_EXT_TXT);
  size_t name_len = slen;
  if (slen > ext_len &&
      strcmp(start + slen - ext_len, STORAGE_DESCRIPTOR_EXT_TXT) == 0)
    name_len = slen - ext_len;

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
      .list_files = storage_list_descriptors,
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
  kef_decrypt_page_destroy();
  if (active_browser == BROWSER_SD)
    sd_file_browser_destroy();
  else
    storage_browser_destroy();
  active_browser = BROWSER_STORAGE;
  success_callback = NULL;
}
