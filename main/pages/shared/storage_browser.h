/*
 * Storage Browser — reusable file listing/selection component
 *
 * Lists stored items (mnemonics or descriptors) from flash or SD card.
 * Provides inline delete, wipe flash, and deferred initialization.
 * Both load pages use this as their shared skeleton.
 */

#ifndef STORAGE_BROWSER_H
#define STORAGE_BROWSER_H

#include "../../core/storage.h"
#include <lvgl.h>

typedef struct {
  const char *item_type_name; /* "mnemonic" or "descriptor" (for messages) */
  storage_location_t location;

  /* Storage operations */
  esp_err_t (*list_files)(storage_location_t, char ***, int *);
  esp_err_t (*delete_file)(storage_location_t, const char *);

  /* Display name from filename (type-specific) */
  char *(*get_display_name)(storage_location_t, const char *);

  /* Called when user selects an entry (type-specific load logic) */
  void (*load_selected)(int idx, const char *filename);

  /* Navigation */
  void (*return_cb)(void);
} storage_browser_config_t;

void storage_browser_create(lv_obj_t *parent,
                            const storage_browser_config_t *config);
void storage_browser_show(void);
void storage_browser_hide(void);
void storage_browser_destroy(void);

/** Get the current storage location configured for the browser. */
storage_location_t storage_browser_get_location(void);

#endif /* STORAGE_BROWSER_H */
