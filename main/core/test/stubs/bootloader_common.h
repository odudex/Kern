/* Host stand-in for ESP-IDF's bootloader_common.h: only the chip revision
 * check fw_update.c calls. */
#pragma once
#include <esp_app_format.h>
#include <stdbool.h>

bool bootloader_common_check_chip_revision_validity(
    const esp_image_header_t *image_header, bool check_max_revision);
