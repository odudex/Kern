/* Stand-ins for the registry's persistence helpers: the BIP138 "container" is
 * the descriptor text itself and filenames follow the storage convention, so
 * tests of registry logic need neither crypto nor a filesystem. */

#include "core/bip138_backup.h"
#include "core/storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool bip138_backup_encrypt(const char *descriptor, uint8_t **blob_out,
                           size_t *blob_len) {
  if (!descriptor || !blob_out || !blob_len)
    return false;
  size_t len = strlen(descriptor);
  uint8_t *blob = malloc(len ? len : 1);
  if (!blob)
    return false;
  memcpy(blob, descriptor, len);
  *blob_out = blob;
  *blob_len = len;
  return true;
}

bool bip138_backup_decrypt_any(const uint8_t *data, size_t len,
                               char **descriptor_out, bool *approved_out) {
  if (approved_out)
    *approved_out = true;
  if (!data || !descriptor_out)
    return false;
  char *descriptor = malloc(len + 1);
  if (!descriptor)
    return false;
  memcpy(descriptor, data, len);
  descriptor[len] = '\0';
  *descriptor_out = descriptor;
  return true;
}

bool storage_descriptor_exists(storage_location_t loc, const char *id,
                               storage_descriptor_format_t format) {
  (void)loc;
  (void)id;
  (void)format;
  return false;
}

static bool has_ext(const char *filename, const char *ext) {
  size_t flen = strlen(filename);
  size_t elen = strlen(ext);
  return flen > elen && strcmp(filename + flen - elen, ext) == 0;
}

storage_descriptor_format_t storage_descriptor_format(const char *filename) {
  if (!filename)
    return STORAGE_DESCRIPTOR_TXT;
  if (has_ext(filename, STORAGE_DESCRIPTOR_EXT_BIP138_SD) ||
      has_ext(filename, STORAGE_DESCRIPTOR_EXT_BIP138))
    return STORAGE_DESCRIPTOR_BIP138;
  if (has_ext(filename, STORAGE_DESCRIPTOR_EXT_KEF))
    return STORAGE_DESCRIPTOR_KEF;
  return STORAGE_DESCRIPTOR_TXT;
}

void storage_descriptor_filename(storage_location_t loc, const char *id,
                                 storage_descriptor_format_t format, char *out,
                                 size_t out_size) {
  const char *ext = STORAGE_DESCRIPTOR_EXT_TXT;
  if (format == STORAGE_DESCRIPTOR_KEF)
    ext = STORAGE_DESCRIPTOR_EXT_KEF;
  else if (format == STORAGE_DESCRIPTOR_BIP138)
    ext = loc == STORAGE_SD ? STORAGE_DESCRIPTOR_EXT_BIP138_SD
                            : STORAGE_DESCRIPTOR_EXT_BIP138;
  snprintf(out, out_size, "%s%s%s",
           loc == STORAGE_FLASH ? STORAGE_DESCRIPTOR_PREFIX : "", id, ext);
}
