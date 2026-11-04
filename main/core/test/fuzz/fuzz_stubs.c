/* Storage stand-ins for the fuzz targets: registry code never persists here. */
#include "core/storage.h"
#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>

esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  storage_descriptor_format_t format) {
  (void)loc;
  (void)id;
  (void)data;
  (void)len;
  (void)format;
  return -1;
}
esp_err_t storage_delete_descriptor(storage_location_t loc,
                                    const char *filename) {
  (void)loc;
  (void)filename;
  return -1;
}
esp_err_t storage_list_descriptors(storage_location_t loc,
                                   char ***filenames_out, int *count_out) {
  (void)loc;
  *filenames_out = NULL;
  *count_out = 0;
  return ESP_OK;
}
esp_err_t storage_load_descriptor(storage_location_t loc, const char *filename,
                                  uint8_t **data_out, size_t *len_out,
                                  storage_descriptor_format_t *format_out) {
  (void)loc;
  (void)filename;
  (void)format_out;
  *data_out = NULL;
  *len_out = 0;
  return -1;
}
void storage_free_file_list(char **files, int count) {
  (void)files;
  (void)count;
}
