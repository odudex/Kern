#ifndef BIP_FLOW_H
#define BIP_FLOW_H

#include <lvgl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../core/descriptor_validator.h"
#include <bip377.h>
#include <wally_psbt.h>

// The error a request that fails to decode with `status` answers with:
// version 0 is reserved, any other one parses as the version Kern knows, where
// a FORM the codec does not know is one Kern cannot take
static inline uint8_t bip_flow_decode_error(const bip377_header *header,
                                            int status) {
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
  case VALIDATION_STORE_FAILED:
    return BIP377_RESPONSE_ERROR_INTERNAL;
  default:
    return BIP377_RESPONSE_ERROR_DESCRIPTOR_REGISTRATION_FAILED;
  }
}
// PSBT_OUT_SP_V0_INFO (BIP-375): the output pays a silent payment address
#define BIP_FLOW_PSBT_OUT_SP_V0_INFO 0x09

// The error a descriptor body needing a capability Kern does not advertise
// answers with, 0 when Kern takes it: a silent payment FORM 0x03 gets 0x06, a
// musig() key 0x0E
static inline uint8_t
bip_flow_descriptor_body_error(const bip377_descriptor_body *body) {
  if (!body)
    return 0;
  if (body->tag == BIP377_DESCRIPTOR_SP_KEYS)
    return BIP377_RESPONSE_ERROR_UNSUPPORTED_DESCRIPTOR_FORM;
  // A wallet policy names its musig() keys in the policy, as musig(@0,@1)
  const char *text = body->tag == BIP377_DESCRIPTOR_BIP380
                         ? body->value.bip380
                         : body->value.bip388.policy;
  return text && strstr(text, "musig(")
             ? BIP377_RESPONSE_ERROR_UNSUPPORTED_OPERATION
             : 0;
}

// The error a request needing a capability Kern does not advertise answers
// with, 0 when Kern takes it: a descriptor body
// bip_flow_descriptor_body_error refuses
static inline uint8_t
bip_flow_unsupported_error(const bip377_request *request) {
  switch (request->message_type) {
  case BIP377_MESSAGE_REGISTER_DESCRIPTOR:
    return bip_flow_descriptor_body_error(
        request->body.register_descriptor.descriptor);
  case BIP377_MESSAGE_ADDRESS_VERIFICATION:
    return bip_flow_descriptor_body_error(
        request->body.verify_address.descriptor);
  case BIP377_MESSAGE_SIGNING:
    for (size_t i = 0; i < request->body.sign.descriptors.len; i++) {
      uint8_t error = bip_flow_descriptor_body_error(
          request->body.sign.descriptors.ptr[i].body);
      if (error)
        return error;
    }
    return 0;
  default:
    return 0;
  }
}

static inline bool bip_flow_map_has_key(const struct wally_map *map,
                                        uint8_t key) {
  for (size_t i = 0; i < map->num_items; i++) {
    if (map->items[i].key_len == 1 && map->items[i].key[0] == key)
      return true;
  }
  return false;
}

// True for a PSBT needing a capability Kern does not advertise: a silent
// payment output, or the BIP-373 participant keys of a MuSig2 key
static inline bool bip_flow_psbt_is_unsupported(const struct wally_psbt *psbt) {
  for (size_t i = 0; i < psbt->num_inputs; i++) {
    if (psbt->inputs[i].musig2_pubkeys.num_items)
      return true;
  }
  for (size_t i = 0; i < psbt->num_outputs; i++) {
    if (psbt->outputs[i].musig2_pubkeys.num_items ||
        bip_flow_map_has_key(&psbt->outputs[i].unknowns,
                             BIP_FLOW_PSBT_OUT_SP_V0_INFO))
      return true;
  }
  return false;
}

void bip_flow_start(lv_obj_t *parent, const uint8_t *data, size_t len,
                    void (*return_cb)(void));

#endif /* BIP_FLOW_H */
