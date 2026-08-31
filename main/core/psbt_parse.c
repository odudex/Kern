#include "psbt.h"

#include <wally_psbt.h>

bool psbt_parse_payload(const uint8_t *data, size_t len,
                        struct wally_psbt **psbt_out) {
  if (!data || !psbt_out)
    return false;
  *psbt_out = NULL;

  while (len > 0 && (data[len - 1] == '\n' || data[len - 1] == '\r' ||
                     data[len - 1] == ' ' || data[len - 1] == '\t'))
    len--;

  return len > 0 &&
         wally_psbt_from_bytes(data, len, WALLY_PSBT_PARSE_FLAG_COMPLETE,
                               psbt_out) == WALLY_OK;
}
