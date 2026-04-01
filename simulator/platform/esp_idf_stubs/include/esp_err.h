#pragma once

#include <assert.h>
#include <stdio.h>
#include <stdint.h>

typedef int esp_err_t;

#define ESP_OK                          0
#define ESP_FAIL                        (-1)
#define ESP_ERR_NO_MEM                  0x101
#define ESP_ERR_INVALID_ARG             0x102
#define ESP_ERR_INVALID_STATE           0x103
#define ESP_ERR_INVALID_SIZE            0x104
#define ESP_ERR_NOT_FOUND               0x105
#define ESP_ERR_NOT_SUPPORTED           0x106
#define ESP_ERR_TIMEOUT                 0x107

/* NVS error codes */
#define ESP_ERR_NVS_BASE                0x1100
#define ESP_ERR_NVS_NOT_FOUND           0x1102
#define ESP_ERR_NVS_NO_FREE_PAGES       0x1105
#define ESP_ERR_NVS_INVALID_HANDLE      0x1109
#define ESP_ERR_NVS_NEW_VERSION_FOUND   0x1110

#define ESP_ERROR_CHECK(x) do {                                          \
    esp_err_t err_rc_ = (x);                                             \
    if (err_rc_ != ESP_OK) {                                             \
        fprintf(stderr, "ESP_ERROR_CHECK failed: %s at %s:%d (0x%x)\n", \
                esp_err_to_name(err_rc_), __FILE__, __LINE__, err_rc_);  \
        assert(0 && "ESP_ERROR_CHECK");                                  \
    }                                                                    \
} while(0)

const char *esp_err_to_name(esp_err_t code);
