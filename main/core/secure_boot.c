#include "secure_boot.h"
#include "kern_sb_digests.h"
#include "nvs_secure.h"
#include "pin.h"
#include "sbv2.h"
#include <esp_chip_info.h>
#include <esp_efuse.h>
#include <esp_efuse_table.h>
#include <esp_flash.h>
#include <esp_image_format.h>
#include <esp_log.h>
#include <esp_ota_ops.h>
#include <psa/crypto.h>
#include <sdkconfig.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = "SECURE_BOOT";

#define BOOTLOADER_OFFSET CONFIG_BOOTLOADER_OFFSET_IN_FLASH
#define BOOTLOADER_MAX_SIZE (CONFIG_PARTITION_TABLE_OFFSET - BOOTLOADER_OFFSET)

typedef enum { SLOT_EMPTY, SLOT_MATCH, SLOT_OTHER } slot_t;

static const esp_efuse_purpose_t DIGEST_PURPOSE[SECURE_BOOT_KEY_COUNT] = {
    ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0,
    ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1,
    ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST2,
};

/* Through the eFuse API, not esp_secure_boot_enabled(), so virtual eFuses
 * (sdkconfig.sbtest) see their own writes */
static bool sb_enabled(void) {
  return esp_efuse_read_field_bit(ESP_EFUSE_SECURE_BOOT_EN);
}

static slot_t read_slot(unsigned i) {
  esp_efuse_block_t blk = EFUSE_BLK_KEY0 + i;
  if (esp_efuse_get_digest_revoke(i))
    return SLOT_OTHER;
  if (esp_efuse_key_block_unused(blk))
    return SLOT_EMPTY;
  uint8_t burned[SECURE_BOOT_DIGEST_LEN];
  if (esp_efuse_get_key_purpose(blk) != DIGEST_PURPOSE[i] ||
      esp_efuse_get_key_dis_read(blk) ||
      esp_efuse_read_block(blk, burned, 0, 8 * sizeof(burned)) != ESP_OK ||
      memcmp(burned, KERN_SB_DIGESTS[i], sizeof(burned)) != 0)
    return SLOT_OTHER;
  return SLOT_MATCH;
}

/* KEY4 and KEY5 can only be read-protected while RD_DIS is writable */
static bool pin_keys_sealed(void) {
  return pin_is_configured() && pin_efuse_check() == PIN_EFUSE_PROVISIONED &&
         nvs_secure_key_check() == NVS_SECURE_KEY_PROVISIONED &&
         esp_efuse_get_key_dis_read(EFUSE_BLK_KEY4) &&
         esp_efuse_get_key_dis_read(EFUSE_BLK_KEY5);
}

static bool hardened(void) {
  size_t soft_jtag = 0;
  return esp_efuse_read_field_cnt(ESP_EFUSE_SOFT_DIS_JTAG, &soft_jtag) ==
             ESP_OK &&
         soft_jtag == ESP_EFUSE_SOFT_DIS_JTAG[0]->bit_count &&
         esp_efuse_read_field_bit(ESP_EFUSE_DIS_DIRECT_BOOT) &&
         esp_efuse_read_field_bit(ESP_EFUSE_DIS_PAD_JTAG) &&
         esp_efuse_read_field_bit(ESP_EFUSE_DIS_USB_JTAG) &&
         (esp_efuse_read_field_bit(ESP_EFUSE_ENABLE_SECURITY_DOWNLOAD) ||
          esp_efuse_read_field_bit(ESP_EFUSE_DIS_DOWNLOAD_MODE)) &&
         esp_efuse_read_field_bit(ESP_EFUSE_WR_DIS_RD_DIS);
}

static esp_err_t flash_read(uint32_t addr, void *buf, size_t len) {
  if (esp_efuse_is_flash_encryption_enabled())
    return esp_flash_read_encrypted(NULL, addr, buf, len);
  return esp_flash_read(NULL, buf, addr, len);
}

/* signed[i]: the image at addr carries a valid signature by embedded key i,
 * hashed the way the ROM hashes it (up to the 4 KiB-aligned signature
 * sector). An unparsable or unsigned image just leaves every entry false. */
static esp_err_t image_signers(uint32_t addr, uint32_t max_size,
                               bool signed_by[SECURE_BOOT_KEY_COUNT]) {
  memset(signed_by, 0, SECURE_BOOT_KEY_COUNT * sizeof(signed_by[0]));
  esp_image_metadata_t md = {0};
  esp_partition_pos_t pos = {.offset = addr, .size = max_size};
  if (esp_image_get_metadata(&pos, &md) != ESP_OK)
    return ESP_OK;
  size_t sector = sbv2_sector_offset(md.image_len);
  if (sector + SBV2_SECTOR_SIZE > max_size)
    return ESP_OK;

  uint8_t *buf = malloc(SBV2_SECTOR_SIZE);
  if (!buf || psa_crypto_init() != PSA_SUCCESS) {
    free(buf);
    return ESP_ERR_NO_MEM;
  }
  esp_err_t err = ESP_FAIL;
  uint8_t digest[SBV2_DIGEST_LEN];
  size_t digest_len = 0;
  psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
  if (psa_hash_setup(&op, PSA_ALG_SHA_256) != PSA_SUCCESS)
    goto out;
  for (size_t off = 0; off < sector; off += SBV2_SECTOR_SIZE) {
    if (flash_read(addr + off, buf, SBV2_SECTOR_SIZE) != ESP_OK ||
        psa_hash_update(&op, buf, SBV2_SECTOR_SIZE) != PSA_SUCCESS)
      goto out;
  }
  if (psa_hash_finish(&op, digest, sizeof(digest), &digest_len) !=
          PSA_SUCCESS ||
      flash_read(addr + sector, buf, SBV2_SECTOR_SIZE) != ESP_OK)
    goto out;
  for (unsigned i = 0; i < SECURE_BOOT_KEY_COUNT; i++)
    signed_by[i] = sbv2_signed_by(buf, digest, KERN_SB_DIGESTS[i]);
  err = ESP_OK;
out:
  psa_hash_abort(&op);
  free(buf);
  return err;
}

/* From v3.1 on the flash is unpowered in download mode and powering it takes
 * register writes, which secure download mode refuses: a locked chip could
 * never be flashed over USB again, bootloader included. Measured on v3.2. */
#define NO_LOCKED_USB_FLASH_REV 301

#define FAIL(code, ...)                                                        \
  do {                                                                         \
    ESP_LOGW(TAG, __VA_ARGS__);                                                \
    if (first == SECURE_BOOT_READY)                                            \
      first = (code);                                                          \
  } while (0)

/* Every check runs so the log lists all problems; the first one is returned */
static secure_boot_check_t check_ready(bool slot_in_use) {
  secure_boot_check_t first = SECURE_BOOT_READY;
#ifndef CONFIG_SECURE_BOOT
  FAIL(SECURE_BOOT_ERR_BUILD,
       "built without CONFIG_SECURE_BOOT: its bootloader does not verify "
       "apps");
#endif
  esp_chip_info_t chip;
  esp_chip_info(&chip);
  if (chip.revision >= NO_LOCKED_USB_FLASH_REV)
    FAIL(SECURE_BOOT_ERR_CHIP,
         "chip v%u.%u cannot be flashed over USB once locked",
         chip.revision / 100, chip.revision % 100);
  if (!pin_keys_sealed())
    FAIL(SECURE_BOOT_ERR_PIN, "PIN not set up, or KEY4/KEY5 not sealed");
  if (slot_in_use)
    FAIL(SECURE_BOOT_ERR_KEY_SLOTS, "KEY0-KEY2 hold other data or a revoke");

  bool app[SECURE_BOOT_KEY_COUNT], boot[SECURE_BOOT_KEY_COUNT];
  const esp_partition_t *running = esp_ota_get_running_partition();
  if (!running ||
      image_signers(running->address, running->size, app) != ESP_OK ||
      image_signers(BOOTLOADER_OFFSET, BOOTLOADER_MAX_SIZE, boot) != ESP_OK) {
    FAIL(SECURE_BOOT_ERR_READ, "could not read the firmware images");
    return first;
  }
  if (!app[0] && !app[1] && !app[2])
    FAIL(SECURE_BOOT_ERR_APP, "running app not signed by a release key");
  for (unsigned i = 0; i < SECURE_BOOT_KEY_COUNT; i++)
    if (!boot[i])
      FAIL(SECURE_BOOT_ERR_BOOTLOADER, "bootloader not signed by key %u", i);
  return first;
}

#undef FAIL

/* The whole field: esp_efuse_read_secure_version() reads only as many bits
 * as this build's anti-rollback config names. */
static uint8_t read_security_version(void) {
  uint32_t bits = 0;
  esp_efuse_read_field_blob(ESP_EFUSE_SECURE_VERSION, &bits,
                            esp_efuse_get_field_size(ESP_EFUSE_SECURE_VERSION));
  return __builtin_popcount(bits);
}

static void evaluate(secure_boot_status_t *out,
                     slot_t slots[SECURE_BOOT_KEY_COUNT]) {
  memset(out, 0, sizeof(*out));
  memcpy(out->digests, KERN_SB_DIGESTS, sizeof(out->digests));
  out->security_version = read_security_version();
  for (unsigned i = 0; i < SECURE_BOOT_KEY_COUNT; i++)
    out->revoked[i] = esp_efuse_get_digest_revoke(i);

  if (sb_enabled()) {
    for (unsigned i = 0; i < SECURE_BOOT_KEY_COUNT; i++) {
      esp_efuse_block_t blk;
      if (!esp_efuse_find_purpose(DIGEST_PURPOSE[i], &blk) ||
          esp_efuse_read_block(blk, out->digests[i], 0,
                               8 * SECURE_BOOT_DIGEST_LEN) != ESP_OK)
        memset(out->digests[i], 0, SECURE_BOOT_DIGEST_LEN);
    }
    out->state = hardened() ? SECURE_BOOT_ON : SECURE_BOOT_INCOMPLETE;
    return;
  }

  bool matched = false, in_use = false;
  for (unsigned i = 0; i < SECURE_BOOT_KEY_COUNT; i++) {
    slots[i] = read_slot(i);
    matched |= slots[i] == SLOT_MATCH;
    in_use |= slots[i] == SLOT_OTHER;
  }
  out->state = matched ? SECURE_BOOT_PARTIAL : SECURE_BOOT_OFF;
  out->check = check_ready(in_use);
}

void secure_boot_read_status(secure_boot_status_t *out) {
  slot_t slots[SECURE_BOOT_KEY_COUNT];
  evaluate(out, slots);
}

static esp_err_t burn_digests(const slot_t slots[SECURE_BOOT_KEY_COUNT]) {
  esp_efuse_batch_write_begin();
  for (unsigned i = 0; i < SECURE_BOOT_KEY_COUNT; i++) {
    if (slots[i] != SLOT_EMPTY)
      continue;
    esp_err_t err =
        esp_efuse_write_key(EFUSE_BLK_KEY0 + i, DIGEST_PURPOSE[i],
                            KERN_SB_DIGESTS[i], SECURE_BOOT_DIGEST_LEN);
    if (err != ESP_OK) {
      esp_efuse_batch_write_cancel();
      return err;
    }
  }
  return esp_efuse_batch_write_commit();
}

/* One BLK0 commit. Each write is a no-op when the bit is already burned, so
 * an interrupted run can be repeated. */
static esp_err_t burn_lockdown(void) {
  size_t soft_jtag = 0;
  size_t soft_jtag_bits = ESP_EFUSE_SOFT_DIS_JTAG[0]->bit_count;
  esp_err_t err = esp_efuse_read_field_cnt(ESP_EFUSE_SOFT_DIS_JTAG, &soft_jtag);
  if (err != ESP_OK)
    return err;

  esp_efuse_batch_write_begin();
  err = esp_efuse_write_field_bit(ESP_EFUSE_DIS_DIRECT_BOOT);
  if (err == ESP_OK)
    err = esp_efuse_write_field_bit(ESP_EFUSE_DIS_PAD_JTAG);
  if (err == ESP_OK)
    err = esp_efuse_write_field_bit(ESP_EFUSE_DIS_USB_JTAG);
  if (err == ESP_OK && soft_jtag < soft_jtag_bits)
    err = esp_efuse_write_field_cnt(ESP_EFUSE_SOFT_DIS_JTAG,
                                    soft_jtag_bits - soft_jtag);
  if (err == ESP_OK)
    err = esp_efuse_enable_rom_secure_download_mode();
  if (err == ESP_OK)
    err = esp_efuse_write_field_bit(ESP_EFUSE_SECURE_BOOT_EN);
  if (err == ESP_OK)
    err = esp_efuse_write_field_bit(ESP_EFUSE_WR_DIS_RD_DIS);
  if (err != ESP_OK) {
    esp_efuse_batch_write_cancel();
    return err;
  }
  return esp_efuse_batch_write_commit();
}

esp_err_t secure_boot_enable(void) {
  secure_boot_status_t status;
  slot_t slots[SECURE_BOOT_KEY_COUNT];
  evaluate(&status, slots);
  if (status.state == SECURE_BOOT_ON)
    return ESP_OK;
  if (status.check != SECURE_BOOT_READY)
    return ESP_ERR_INVALID_STATE;

  if (status.state != SECURE_BOOT_INCOMPLETE) {
    ESP_LOGI(TAG, "Burning release key digests");
    esp_err_t err = burn_digests(slots);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Digest burn failed: %s", esp_err_to_name(err));
      return err;
    }
    /* SECURE_BOOT_EN without all three digests in place would brick */
    for (unsigned i = 0; i < SECURE_BOOT_KEY_COUNT; i++) {
      if (read_slot(i) != SLOT_MATCH) {
        ESP_LOGE(TAG, "KEY%u does not read back digest %u", i, i);
        return ESP_FAIL;
      }
    }
  }

  ESP_LOGI(TAG, "Burning hardening set and SECURE_BOOT_EN");
  esp_err_t err = burn_lockdown();
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Lockdown burn failed: %s", esp_err_to_name(err));
    return err;
  }
  return sb_enabled() && hardened() ? ESP_OK : ESP_FAIL;
}
