/*
 * SD File Browser — reusable browse-anywhere SD-card file picker
 *
 * Navigates SD-card directories (subfolders, paged listings, remount-on-open)
 * and hands the chosen file's path back to a caller-supplied callback. The
 * caller reads and frees the file; the browser only locates it.
 */

#ifndef SD_FILE_BROWSER_H
#define SD_FILE_BROWSER_H

#include <lvgl.h>

typedef struct {
  /* Menu title; NULL shows the current directory path (the default). */
  const char *title;
  /* Invoked when a file is picked. dir is the containing directory, name the
   * bare filename, full_path their join. None outlive the callback. */
  void (*on_file_selected)(const char *full_path, const char *dir,
                           const char *name);
  /* Invoked when the user backs out at the SD root. */
  void (*return_cb)(void);
} sd_file_browser_config_t;

void sd_file_browser_create(lv_obj_t *parent,
                            const sd_file_browser_config_t *config);
void sd_file_browser_show(void);
void sd_file_browser_hide(void);
void sd_file_browser_destroy(void);

/* Re-list the current directory (e.g. after returning from a load flow). */
void sd_file_browser_refresh(void);

#endif // SD_FILE_BROWSER_H
