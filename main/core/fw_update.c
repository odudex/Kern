#include "fw_update.h"
#include <esp_app_desc.h>
#include <esp_app_format.h>
#include <esp_log.h>
#include <esp_ota_ops.h>
#include <esp_secure_boot.h>
#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "FW_UPDATE";

#define READ_CHUNK 8192
#define SIG_SECTOR_SIZE 4096

/* Walks the image structure and returns the offset of the appended
 * signature sector, or 0 if the layout is inconsistent with a signed
 * image of file_size bytes. */
static size_t signature_offset(FILE *f, const esp_image_header_t *hdr,
                               size_t file_size) {
  size_t pos = sizeof(esp_image_header_t);
  for (int i = 0; i < hdr->segment_count; i++) {
    esp_image_segment_header_t seg;
    if (fseek(f, pos, SEEK_SET) != 0 ||
        fread(&seg, 1, sizeof(seg), f) != sizeof(seg))
      return 0;
    pos += sizeof(seg) + seg.data_len;
    if (pos > file_size)
      return 0;
  }
  pos = (pos + 1 + 15) & ~(size_t)15; /* checksum byte, padded to 16 */
  if (hdr->hash_appended)
    pos += 32;
  size_t sig_offset =
      (pos + SIG_SECTOR_SIZE - 1) & ~(size_t)(SIG_SECTOR_SIZE - 1);
  if (file_size != sig_offset + SIG_SECTOR_SIZE)
    return 0;
  return sig_offset;
}

static int sha256_file_range(FILE *f, size_t len, uint8_t digest[32],
                             fw_update_progress_cb_t progress_cb,
                             void *user_data) {
  if (psa_crypto_init() != PSA_SUCCESS)
    return -1;
  psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
  if (psa_hash_setup(&op, PSA_ALG_SHA_256) != PSA_SUCCESS)
    return -1;
  uint8_t *buf = malloc(READ_CHUNK);
  if (!buf) {
    psa_hash_abort(&op);
    return -1;
  }
  int ret = -1;
  if (fseek(f, 0, SEEK_SET) != 0)
    goto out;
  size_t done = 0;
  while (done < len) {
    size_t want = len - done < READ_CHUNK ? len - done : READ_CHUNK;
    if (fread(buf, 1, want, f) != want)
      goto out;
    if (psa_hash_update(&op, buf, want) != PSA_SUCCESS)
      goto out;
    done += want;
    if (progress_cb)
      progress_cb((int)(done * 100 / len), user_data);
  }
  size_t out_len = 0;
  if (psa_hash_finish(&op, digest, 32, &out_len) == PSA_SUCCESS &&
      out_len == 32)
    ret = 0;
out:
  free(buf);
  if (ret != 0)
    psa_hash_abort(&op);
  return ret;
}

int fw_update_validate(const char *path, fw_update_info_t *info,
                       const char **err_out) {
  const char *err = "Invalid firmware file";
  int ret = -1;
  uint8_t *sig = NULL;

  FILE *f = fopen(path, "rb");
  if (!f) {
    *err_out = "Cannot open file";
    return -1;
  }

  if (fseek(f, 0, SEEK_END) != 0)
    goto out;
  long fsize = ftell(f);
  if (fsize <
      (long)(sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) +
             sizeof(esp_app_desc_t) + SIG_SECTOR_SIZE))
    goto out;

  esp_image_header_t hdr;
  if (fseek(f, 0, SEEK_SET) != 0 ||
      fread(&hdr, 1, sizeof(hdr), f) != sizeof(hdr))
    goto out;
  if (hdr.magic != ESP_IMAGE_HEADER_MAGIC)
    goto out;
  if (hdr.chip_id != ESP_CHIP_ID_ESP32P4) {
    err = "Not an ESP32-P4 image";
    goto out;
  }

  esp_app_desc_t desc;
  if (fseek(f, sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t),
            SEEK_SET) != 0 ||
      fread(&desc, 1, sizeof(desc), f) != sizeof(desc))
    goto out;
  if (desc.magic_word != ESP_APP_DESC_MAGIC_WORD)
    goto out;

  const esp_app_desc_t *running = esp_app_get_description();
  if (strncmp(desc.project_name, running->project_name,
              sizeof(desc.project_name)) != 0) {
    err = "Different project firmware";
    goto out;
  }
  if (desc.secure_version < running->secure_version) {
    err = "Older security version rejected";
    goto out;
  }

  size_t sig_offset = signature_offset(f, &hdr, (size_t)fsize);
  if (sig_offset == 0) {
    err = "Image is not signed";
    goto out;
  }

#if CONFIG_SECURE_SIGNED_ON_UPDATE_NO_SECURE_BOOT || CONFIG_SECURE_BOOT
  esp_image_sig_public_key_digests_t trusted = {0};
  if (!esp_secure_boot_enabled() &&
      (esp_secure_boot_get_signature_blocks_for_running_app(false, &trusted) !=
           ESP_OK ||
       trusted.num_digests == 0)) {
    err = "Running firmware is unsigned; cannot verify updates";
    goto out;
  }

  uint8_t digest[32];
  if (sha256_file_range(f, sig_offset, digest, NULL, NULL) != 0) {
    err = "Hashing failed";
    goto out;
  }

  sig = malloc(SIG_SECTOR_SIZE);
  if (!sig) {
    err = "Out of memory";
    goto out;
  }
  if (fseek(f, sig_offset, SEEK_SET) != 0 ||
      fread(sig, 1, SIG_SECTOR_SIZE, f) != SIG_SECTOR_SIZE)
    goto out;

  uint8_t verified_digest[32];
  esp_err_t verr = esp_secure_boot_verify_sbv2_signature_block(
      (const ets_secure_boot_signature_t *)sig, digest, verified_digest);
  if (verr != ESP_OK) {
    ESP_LOGW(TAG, "Signature verification failed: %s", esp_err_to_name(verr));
    err = "Signature verification failed";
    goto out;
  }
#else
  err = "Signature checking disabled in this build";
  goto out;
#endif

  if (info) {
    memset(info, 0, sizeof(*info));
    strlcpy(info->version, desc.version, sizeof(info->version));
    strlcpy(info->current_version, running->version,
            sizeof(info->current_version));
    info->secure_version = desc.secure_version;
    info->image_size = (size_t)fsize;
  }
  ret = 0;

out:
  free(sig);
  fclose(f);
  if (ret != 0)
    *err_out = err;
  return ret;
}

int fw_update_apply(const char *path, fw_update_progress_cb_t progress_cb,
                    void *user_data, const char **err_out) {
  const char *err = "Update failed";
  int ret = -1;
  uint8_t *buf = NULL;
  esp_ota_handle_t ota = 0;
  bool ota_started = false;

  FILE *f = fopen(path, "rb");
  if (!f) {
    *err_out = "Cannot open file";
    return -1;
  }

  if (fseek(f, 0, SEEK_END) != 0)
    goto out;
  long fsize = ftell(f);
  if (fsize <= 0 || fseek(f, 0, SEEK_SET) != 0)
    goto out;

  const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
  if (!next) {
    err = "No OTA partition available";
    goto out;
  }
  if ((size_t)fsize > next->size) {
    err = "Image too large for OTA partition";
    goto out;
  }

  esp_err_t e = esp_ota_begin(next, OTA_WITH_SEQUENTIAL_WRITES, &ota);
  if (e != ESP_OK) {
    ESP_LOGE(TAG, "esp_ota_begin: %s", esp_err_to_name(e));
    goto out;
  }
  ota_started = true;

  buf = malloc(READ_CHUNK);
  if (!buf) {
    err = "Out of memory";
    goto out;
  }

  size_t done = 0;
  while (done < (size_t)fsize) {
    size_t want =
        (size_t)fsize - done < READ_CHUNK ? (size_t)fsize - done : READ_CHUNK;
    if (fread(buf, 1, want, f) != want) {
      err = "SD card read failed";
      goto out;
    }
    e = esp_ota_write(ota, buf, want);
    if (e != ESP_OK) {
      ESP_LOGE(TAG, "esp_ota_write: %s", esp_err_to_name(e));
      err = "Flash write failed";
      goto out;
    }
    done += want;
    if (progress_cb)
      progress_cb((int)(done * 100 / (size_t)fsize), user_data);
  }

  e = esp_ota_end(ota);
  ota_started = false;
  if (e != ESP_OK) {
    ESP_LOGE(TAG, "esp_ota_end: %s", esp_err_to_name(e));
    err = e == ESP_ERR_OTA_VALIDATE_FAILED ? "Image verification failed"
                                           : "Update failed";
    goto out;
  }

  e = esp_ota_set_boot_partition(next);
  if (e != ESP_OK) {
    ESP_LOGE(TAG, "esp_ota_set_boot_partition: %s", esp_err_to_name(e));
    goto out;
  }
  ESP_LOGI(TAG, "Update written to %s, reboot to run it", next->label);
  ret = 0;

out:
  if (ota_started)
    esp_ota_abort(ota);
  free(buf);
  fclose(f);
  if (ret != 0)
    *err_out = err;
  return ret;
}

void fw_update_boot_confirm(void) {
  const esp_partition_t *running = esp_ota_get_running_partition();
  esp_ota_img_states_t state;
  if (running && esp_ota_get_state_partition(running, &state) == ESP_OK &&
      state == ESP_OTA_IMG_PENDING_VERIFY) {
    esp_err_t e = esp_ota_mark_app_valid_cancel_rollback();
    ESP_LOGI(TAG, "Boot confirm (cancel rollback): %s", esp_err_to_name(e));
  }
}
