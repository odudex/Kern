// Load Descriptor Storage Page — list and load descriptors from flash or SD

#include "load_descriptor_storage.h"
#include "../core/kef.h"
#include "../core/registry.h"
#include "../core/storage.h"
#include "../ui/dialog.h"
#include "shared/descriptor_loader.h"
#include "shared/kef_decrypt_page.h"
#include "shared/storage_browser.h"
#include <esp_log.h>
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "load_descriptor_storage";

static void (*success_callback)(void) = NULL;
static char pending_kef_id[KEF_MAX_ID_LEN + 1];
static char *pending_kef_descriptor = NULL;

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
      /* KEF path: register only after validation succeeds */
      if (pending_kef_id[0] != '\0' && pending_kef_descriptor) {
        registry_remove(pending_kef_id);
        if (!registry_add_from_string(pending_kef_id, pending_kef_descriptor,
                                      storage_browser_get_location(),
                                      /*persist=*/false))
          ESP_LOGW(TAG, "registry_add_from_string failed for '%s'",
                   pending_kef_id);
      }
      free(pending_kef_descriptor);
      pending_kef_descriptor = NULL;
      /* Descriptor is session-only — inform the user */
      dialog_show_info("Registered (this session)", NULL,
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

  /* Save descriptor for registry_add_from_string in descriptor_validation_cb */
  free(pending_kef_descriptor);
  pending_kef_descriptor = descriptor_str;
  descriptor_str = NULL;

  /* Pass non-NULL sentinel so descriptor_validation_cb shows the session-only
   * dialog */
  descriptor_loader_process_string(pending_kef_descriptor,
                                   descriptor_validation_cb, (void *)1);
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

    const uint8_t *raw_id = NULL;
    size_t raw_id_len = 0;
    if (kef_parse_header(data, data_len, &raw_id, &raw_id_len, NULL, NULL) ==
            KEF_OK &&
        raw_id != NULL && raw_id_len > 0) {
      size_t copy_len =
          raw_id_len < KEF_MAX_ID_LEN ? raw_id_len : KEF_MAX_ID_LEN;
      memcpy(pending_kef_id, raw_id, copy_len);
      pending_kef_id[copy_len] = '\0';
    } else {
      pending_kef_id[0] = '\0';
    }

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

    /* Paranoia: ensure registry has this descriptor even if registry_init
     * missed it */
    {
      const char *id_start = filename;
      size_t prefix_len = strlen(STORAGE_DESCRIPTOR_PREFIX);
      if (strncmp(id_start, STORAGE_DESCRIPTOR_PREFIX, prefix_len) == 0)
        id_start += prefix_len;

      size_t slen = strlen(id_start);
      size_t ext_len = strlen(STORAGE_DESCRIPTOR_EXT_TXT);
      size_t id_len =
          (slen > ext_len &&
           strcmp(id_start + slen - ext_len, STORAGE_DESCRIPTOR_EXT_TXT) == 0)
              ? slen - ext_len
              : slen;
      if (id_len > REGISTRY_ID_MAX_LEN - 1)
        id_len = REGISTRY_ID_MAX_LEN - 1;

      char id[REGISTRY_ID_MAX_LEN];
      memcpy(id, id_start, id_len);
      id[id_len] = '\0';

      if (!registry_find_by_id(id))
        if (!registry_add_from_string(id, descriptor_str,
                                      storage_browser_get_location(),
                                      /*persist=*/false))
          ESP_LOGW(TAG, "registry_add_from_string failed for '%s'", id);
    }

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
