// Load Descriptor Storage Page — list and load descriptors from flash or SD

#include "load_descriptor_storage.h"
#include "../core/kef.h"
#include "../core/storage.h"
#include "../ui/dialog.h"
#include "shared/descriptor_loader.h"
#include "shared/kef_decrypt_page.h"
#include "shared/storage_browser.h"
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

static void (*success_callback)(void) = NULL;

/* ---------- Descriptor validation callback ---------- */

static void descriptor_validation_cb(descriptor_validation_result_t result,
                                     void *user_data) {
  (void)user_data;

  if (result == VALIDATION_SUCCESS) {
    if (success_callback)
      success_callback();
    return;
  }

  descriptor_loader_show_error(result);
  storage_browser_show();
}

/* ---------- Decrypt callbacks ---------- */

static void return_from_kef_decrypt(void) {
  kef_decrypt_page_destroy();
  storage_browser_show();
}

static void success_from_kef_decrypt(const uint8_t *data, size_t len) {
  /* Copy decrypted data BEFORE destroying the page (data is page-owned) */
  char *descriptor_str = malloc(len + 1);
  if (!descriptor_str) {
    kef_decrypt_page_destroy();
    dialog_show_error("Out of memory", NULL, 0);
    storage_browser_show();
    return;
  }
  memcpy(descriptor_str, data, len);
  descriptor_str[len] = '\0';

  kef_decrypt_page_destroy();
  storage_browser_hide();
  descriptor_loader_process_string(descriptor_str, descriptor_validation_cb,
                                   NULL);
  free(descriptor_str);
}

/* ---------- Load selected entry ---------- */

static void load_selected(int idx, const char *filename) {
  (void)idx;

  uint8_t *data = NULL;
  size_t data_len = 0;
  bool encrypted = false;

  esp_err_t ret = storage_load_descriptor(
      storage_browser_get_location(), filename, &data, &data_len, &encrypted);
  if (ret != ESP_OK) {
    dialog_show_error("Failed to load file", NULL, 0);
    return;
  }

  if (encrypted) {
    if (!kef_is_envelope(data, data_len)) {
      free(data);
      dialog_show_error("Invalid encrypted data", NULL, 0);
      return;
    }

    storage_browser_hide();
    kef_decrypt_page_create(lv_screen_active(), return_from_kef_decrypt,
                            success_from_kef_decrypt, data, data_len);
    kef_decrypt_page_show();
    free(data); /* kef_decrypt_page copies it */
  } else {
    /* Plaintext: null-terminate and process directly */
    char *descriptor_str = malloc(data_len + 1);
    if (!descriptor_str) {
      free(data);
      dialog_show_error("Out of memory", NULL, 0);
      return;
    }
    memcpy(descriptor_str, data, data_len);
    descriptor_str[data_len] = '\0';
    free(data);

    storage_browser_hide();
    descriptor_loader_process_string(descriptor_str, descriptor_validation_cb,
                                     NULL);
    free(descriptor_str);
  }
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

void load_descriptor_storage_page_show(void) { storage_browser_show(); }

void load_descriptor_storage_page_hide(void) { storage_browser_hide(); }

void load_descriptor_storage_page_destroy(void) {
  kef_decrypt_page_destroy();
  storage_browser_destroy();
  success_callback = NULL;
}
