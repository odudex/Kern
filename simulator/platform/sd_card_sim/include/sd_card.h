#ifndef SD_CARD_H
#define SD_CARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Override mount point to simulator data directory */
#define SD_CARD_MOUNT_POINT "simulator/sim_data/sdcard"

esp_err_t sd_card_init(void);
esp_err_t sd_card_deinit(void);
bool      sd_card_is_mounted(void);

esp_err_t sd_card_write_file(const char *path, const uint8_t *data, size_t len);
esp_err_t sd_card_read_file(const char *path, uint8_t **data_out, size_t *len_out);
esp_err_t sd_card_file_exists(const char *path, bool *exists);
esp_err_t sd_card_delete_file(const char *path);

esp_err_t sd_card_list_files(const char *dir_path, char ***files_out, int *count_out);
void      sd_card_free_file_list(char **files, int count);

#ifdef __cplusplus
}
#endif

#endif /* SD_CARD_H */
