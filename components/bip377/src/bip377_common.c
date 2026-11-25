#include "bip377_internal.h"

#include <string.h>

bool bip377_is_message(const uint8_t *msg, size_t len) {
  return msg && len >= BIP377_MAGIC_LEN &&
         memcmp(msg, BIP377_MAGIC, BIP377_MAGIC_LEN) == 0;
}

bool bip377_type_is_request(uint8_t type) {
  switch (type) {
  case BIP377_MESSAGE_GET_INFO:
  case BIP377_MESSAGE_GET_KEYS:
  case BIP377_MESSAGE_REGISTER_DESCRIPTOR:
  case BIP377_MESSAGE_ADDRESS_VERIFICATION:
  case BIP377_MESSAGE_SIGNING:
  case BIP377_MESSAGE_UNREGISTER_DESCRIPTOR:
    return true;
  default:
    return false;
  }
}

bool bip377_request_header(const uint8_t *msg, size_t len, bip377_header *out) {
  memset(out, 0, sizeof(*out));
  out->message_type = BIP377_MESSAGE_UNREADABLE_REQUEST;
  if (!bip377_is_message(msg, len) || len < BIP377_HEADER_LEN)
    return false;
  uint8_t msg_type = msg[BIP377_MSG_TYPE_OFFSET];
  uint8_t type = msg_type & BIP377_TYPE_MASK;
  if ((msg_type & BIP377_STATUS_ERROR) || !bip377_type_is_request(type))
    return false;
  out->version = msg[BIP377_VERSION_OFFSET];
  out->message_type = type;
  memcpy(out->id, msg + BIP377_REQUEST_ID_OFFSET, BIP377_REQUEST_ID_LEN);
  return true;
}

int bip377_string_check(const uint8_t *s, size_t len) {
  if (len && memchr(s, 0, len))
    return BIP377_ERR_STRING_NUL;

  size_t i = 0;
  while (i < len) {
    uint8_t lead = s[i];
    if (lead < 0x80) {
      i++;
      continue;
    }
    size_t tail;
    uint32_t code_point;
    uint32_t min;
    if ((lead & 0xe0) == 0xc0) {
      tail = 1;
      code_point = lead & 0x1f;
      min = 0x80;
    } else if ((lead & 0xf0) == 0xe0) {
      tail = 2;
      code_point = lead & 0x0f;
      min = 0x800;
    } else if ((lead & 0xf8) == 0xf0) {
      tail = 3;
      code_point = lead & 0x07;
      min = 0x10000;
    } else {
      return BIP377_ERR_INVALID_UTF8;
    }
    if (tail > len - i - 1)
      return BIP377_ERR_INVALID_UTF8;
    for (size_t k = 1; k <= tail; k++) {
      if ((s[i + k] & 0xc0) != 0x80)
        return BIP377_ERR_INVALID_UTF8;
      code_point = (code_point << 6) | (s[i + k] & 0x3f);
    }
    /* Overlong forms, UTF-16 surrogates and values past the last code point */
    if (code_point < min || code_point > 0x10ffff ||
        (code_point >= 0xd800 && code_point <= 0xdfff))
      return BIP377_ERR_INVALID_UTF8;
    i += tail + 1;
  }
  return BIP377_OK;
}

const char *bip377_strerror(int status) {
  switch (status) {
  case BIP377_OK:
    return "ok";
  case BIP377_ERR_TRUNCATED:
    return "the message ends before a field is fully read";
  case BIP377_ERR_NON_CANONICAL_COMPACT_SIZE:
    return "a compact size is not in its shortest form";
  case BIP377_ERR_COMPACT_SIZE_TOO_LARGE:
    return "a compact size does not fit this platform";
  case BIP377_ERR_INVALID_BOOL:
    return "a BOOL is neither 0x00 nor 0x01";
  case BIP377_ERR_INVALID_PRESENCE:
    return "a PRESENCE is neither 0x00 nor 0x01";
  case BIP377_ERR_STRING_TOO_LARGE:
    return "a string is longer than its field allows";
  case BIP377_ERR_INVALID_UTF8:
    return "a string is not valid UTF-8";
  case BIP377_ERR_STRING_NUL:
    return "a string contains a nul byte";
  case BIP377_ERR_INVALID_MAGIC:
    return "the message does not begin with MAGIC";
  case BIP377_ERR_RESERVED_VERSION:
    return "VERSION 0 is reserved";
  case BIP377_ERR_UNKNOWN_MESSAGE_TYPE:
    return "unknown message TYPE";
  case BIP377_ERR_ERROR_STATUS_ON_REQUEST:
    return "a request carries the error STATUS";
  case BIP377_ERR_UNKNOWN_DESCRIPTOR_FORM:
    return "unknown descriptor FORM";
  case BIP377_ERR_UNKNOWN_SIGN_RESPONSE_KIND:
    return "unknown Signing response KIND";
  case BIP377_ERR_GLOBAL_INPUT_INDEX:
    return "a global silent payment entry has a non-zero INPUT_INDEX";
  case BIP377_ERR_SCAN_PATH_AND_KEY:
    return "silent payment keys carry both SCAN_PATH and SCAN_KEY";
  case BIP377_ERR_NO_SCAN:
    return "silent payment keys carry neither SCAN_PATH nor SCAN_KEY";
  case BIP377_ERR_UNREADABLE_REQUEST_TYPE:
    return "TYPE 0x00 outside the reply to an unreadable request";
  case BIP377_ERR_DIRECTION_DISABLED:
    return "the message is a response, not a request";
  case BIP377_ERR_RESERVED_CAPABILITY_BITS:
    return "a reserved capability bit is set";
  case BIP377_ERR_ERROR_CODE_OUT_OF_RANGE:
    return "ERROR 0x00 is reserved";
  case BIP377_ERR_STRING_TOO_LONG:
    return "a string is longer than its field allows";
  case BIP377_ERR_DEFINED_SIGNATURE_KIND:
    return "SIG_KIND 0x00 is reserved";
  case BIP377_ERR_RESERVED_NETWORK_BITS:
    return "a reserved network bit is set";
  case BIP377_ERR_UNREADABLE_REQUEST_ERROR:
    return "the reply to an unreadable request carries ERROR 0x03";
  case BIP377_ERR_NULL_POINTER:
    return "a required pointer is NULL";
  case BIP377_ERR_UNKNOWN_TAG:
    return "a selector holds a value this version does not define";
  case BIP377_ERR_BUFFER_TOO_SMALL:
    return "the buffer is too small";
  case BIP377_ERR_BUFFER_MISALIGNED:
    return "the block is not aligned";
  case BIP377_ERR_TOO_LARGE:
    return "the message is too large for this platform";
  case BIP377_ERR_DUPLICATE_SP_SHARE:
    return "duplicate silent payment ECDH share";
  case BIP377_ERR_DUPLICATE_SP_PROOF:
    return "duplicate silent payment DLEQ proof";
  case BIP377_ERR_MISSING_SP_PROOF:
    return "a silent payment ECDH share has no DLEQ proof";
  case BIP377_ERR_MISSING_SP_SHARE:
    return "a silent payment DLEQ proof has no ECDH share";
  case BIP377_ERR_MAX_ALIAS_TOO_LARGE:
    return "MAX_ALIAS is above 32";
  case BIP377_ERR_FINGERPRINT_WHEN_NOT_READY:
    return "FINGERPRINT is present while STATE is not ready";
  case BIP377_ERR_TAPROOT_SIGNATURE_LENGTH:
    return "a taproot signature is neither 64 nor 65 bytes";
  case BIP377_ERR_UNREADABLE_REQUEST_ID:
    return "the reply to an unreadable request carries REQUEST_ID 0x0000";
  case BIP377_ERR_NUMBERED_STABLE_RELEASE:
    return "a stable release carries a pre-release NUMBER";
  case BIP377_ERR_ECDSA_SIGNATURE_LENGTH:
    return "an ECDSA signature is longer than 73 bytes";
  default:
    return "unknown error";
  }
}
