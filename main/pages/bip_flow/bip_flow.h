#ifndef BIP_FLOW_H
#define BIP_FLOW_H

#include <lvgl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../core/descriptor_validator.h"
#include <bip377.h>

#define BIP_FLOW_MAGIC "BIP377"
#define BIP_FLOW_MAGIC_LEN 6
#define BIP_FLOW_VERSION_OFFSET BIP_FLOW_MAGIC_LEN
#define BIP_FLOW_MSG_TYPE_OFFSET (BIP_FLOW_VERSION_OFFSET + 1)
#define BIP_FLOW_REQUEST_ID_OFFSET (BIP_FLOW_MSG_TYPE_OFFSET + 1)
#define BIP_FLOW_HEADER_LEN (BIP_FLOW_REQUEST_ID_OFFSET + BIP377_REQUEST_ID_LEN)

typedef struct {
  uint8_t version;
  uint8_t message_type;
  uint8_t id[BIP377_REQUEST_ID_LEN];
} bip_flow_header_t;

#define BIP_FLOW_STATUS_BIT 0x40
#define BIP_FLOW_TYPE_MASK 0x3F

// Reads the header of a request. It is unreadable without our MAGIC and the
// full REQUEST_ID, with an unknown, reserved or 0x00 TYPE, or with the error
// status: `out` then holds the header of the reply to an unreadable request,
// TYPE 0x00 and REQUEST_ID 0x0000.
static inline bool bip_flow_read_request_header(const uint8_t *data, size_t len,
                                                bip_flow_header_t *out) {
  memset(out, 0, sizeof(*out));
  out->message_type = BIP377_MESSAGE_UNREADABLE_REQUEST;
  if (!data || len < BIP_FLOW_HEADER_LEN ||
      memcmp(data, BIP_FLOW_MAGIC, BIP_FLOW_MAGIC_LEN) != 0)
    return false;
  uint8_t msg_type = data[BIP_FLOW_MSG_TYPE_OFFSET];
  uint8_t type = msg_type & BIP_FLOW_TYPE_MASK;
  if ((msg_type & BIP_FLOW_STATUS_BIT) || type < BIP377_MESSAGE_GET_INFO ||
      type > BIP377_MESSAGE_UNREGISTER_DESCRIPTOR)
    return false;
  out->version = data[BIP_FLOW_VERSION_OFFSET];
  out->message_type = type;
  memcpy(out->id, data + BIP_FLOW_REQUEST_ID_OFFSET, BIP377_REQUEST_ID_LEN);
  return true;
}

// The error a request that fails to decode with `status` answers with:
// version 0 is reserved, any other one parses as the version Kern knows, where
// a FORM the codec does not know is one Kern cannot take
static inline uint8_t bip_flow_decode_error(const bip_flow_header_t *header,
                                            int32_t status) {
  if (header->version == 0)
    return BIP377_RESPONSE_ERROR_UNSUPPORTED_VERSION;
  return status == BIP377_ERR_UNKNOWN_DESCRIPTOR_FORM
             ? BIP377_RESPONSE_ERROR_UNSUPPORTED_DESCRIPTOR_FORM
             : BIP377_RESPONSE_ERROR_MALFORMED_REQUEST;
}

bool bip_flow_can_handle(const uint8_t *data, size_t len);
// The error a failed registration answers with
static inline uint8_t
bip_flow_register_error(descriptor_validation_result_t result) {
  switch (result) {
  case VALIDATION_USER_DECLINED:
    return BIP377_RESPONSE_ERROR_USER_DECLINED;
  case VALIDATION_NETWORK_MISMATCH:
    return BIP377_RESPONSE_ERROR_NETWORK_MISMATCH;
  case VALIDATION_INTERNAL_ERROR:
    return BIP377_RESPONSE_ERROR_INTERNAL;
  default:
    return BIP377_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED;
  }
}
void bip_flow_start(lv_obj_t *parent, const uint8_t *data, size_t len,
                    void (*return_cb)(void));

#endif /* BIP_FLOW_H */
