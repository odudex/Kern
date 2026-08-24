#ifndef BIP_FLOW_H
#define BIP_FLOW_H

#include <lvgl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../core/descriptor_validator.h"

bool bip_flow_can_handle(const uint8_t *data, size_t len);
static inline bool bip_flow_register_validation_result_allows_response(
    descriptor_validation_result_t result) {
  return result == VALIDATION_SUCCESS || result == VALIDATION_USER_DECLINED;
}
void bip_flow_start(lv_obj_t *parent, const uint8_t *data, size_t len,
                    void (*return_cb)(void));

#endif /* BIP_FLOW_H */
