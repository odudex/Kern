/* Host copy of the ESP-IDF app descriptor layout (esp_app_format). */
#pragma once
#include <stddef.h>
#include <stdint.h>

#define ESP_APP_DESC_MAGIC_WORD (0xABCD5432)

typedef struct {
  uint32_t magic_word;
  uint32_t secure_version;
  uint32_t reserv1[2];
  char version[32];
  char project_name[32];
  char time[16];
  char date[16];
  char idf_ver[32];
  uint8_t app_elf_sha256[32];
  uint16_t min_efuse_blk_rev_full;
  uint16_t max_efuse_blk_rev_full;
  uint8_t mmu_page_size;
  uint8_t spi_flash_mode;
  uint8_t reserv3[2];
  uint32_t reserv2[18];
} esp_app_desc_t;

_Static_assert(sizeof(esp_app_desc_t) == 256, "app descriptor is 256 bytes");
_Static_assert(offsetof(esp_app_desc_t, secure_version) == 4,
               "secure_version sits at offset 4");

const esp_app_desc_t *esp_app_get_description(void);
