#ifndef SD_CARD_H
#define SD_CARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SD_CARD_MOUNT_POINT "/sdcard"

esp_err_t sd_card_init(void);
esp_err_t sd_card_deinit(void);

/* Force a fresh remount (unmount if needed, then mount). Use when a card may
 * have been physically swapped — there is no card-detect line, so an existing
 * mount can be stale. */
esp_err_t sd_card_remount(void);

bool sd_card_is_mounted(void);

esp_err_t sd_card_write_file(const char *path, const uint8_t *data, size_t len);
esp_err_t sd_card_read_file(const char *path, uint8_t **data_out,
                            size_t *len_out);
esp_err_t sd_card_file_size(const char *path, size_t *size_out);
esp_err_t sd_card_file_exists(const char *path, bool *exists);
esp_err_t sd_card_delete_file(const char *path);

esp_err_t sd_card_list_files(const char *dir_path, char ***files_out,
                             int *count_out);

/* Lists regular files AND subdirectories of dir_path (dot-prefixed entries
 * excluded, like sd_card_list_files). On success names_out[i] is the entry
 * name and is_dir_out[i] is true when it is a directory. Free names_out with
 * sd_card_free_file_list() and is_dir_out with free(). */
esp_err_t sd_card_list_entries(const char *dir_path, char ***names_out,
                               bool **is_dir_out, int *count_out);

void sd_card_free_file_list(char **files, int count);

#ifdef __cplusplus
}
#endif

#endif
