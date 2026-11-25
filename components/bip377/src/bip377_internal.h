#ifndef BIP377_INTERNAL_H
#define BIP377_INTERNAL_H

#include "bip377.h"

#define BIP377_DIRECTION_RESPONSE 0x80
#define BIP377_STATUS_ERROR 0x40
#define BIP377_TYPE_MASK 0x3f

#define BIP377_VERSION_OFFSET BIP377_MAGIC_LEN
#define BIP377_MSG_TYPE_OFFSET (BIP377_VERSION_OFFSET + 1)
#define BIP377_REQUEST_ID_OFFSET (BIP377_MSG_TYPE_OFFSET + 1)

#define BIP377_TRY(expr)                                                       \
  do {                                                                         \
    int bip377_try_status_ = (expr);                                           \
    if (bip377_try_status_ != BIP377_OK)                                       \
      return bip377_try_status_;                                               \
  } while (0)

/* True for the TYPE of a request this version defines. */
bool bip377_type_is_request(uint8_t type);

/* BIP377_OK for well-formed UTF-8 holding no NUL byte. */
int bip377_string_check(const uint8_t *s, size_t len);

#endif /* BIP377_INTERNAL_H */
