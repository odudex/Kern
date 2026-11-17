#include "psbt.h"
#include "sp_psbt.h"

#include "kern_wally.h"
#include <wally_psbt.h>

// A BIP375 PSBT leaves silent payment output scripts to the signer
static bool parse_pending_outputs(const uint8_t *data, size_t len,
                                  struct wally_psbt **psbt_out) {
  if (kern_psbt_from_bytes(data, len,
                           WALLY_PSBT_PARSE_FLAG_LOOSE |
                               WALLY_PSBT_PARSE_FLAG_COMPLETE,
                           psbt_out) != WALLY_OK)
    return false;
  if (sp_psbt_outputs_pending(*psbt_out))
    return true;
  wally_psbt_free(*psbt_out);
  *psbt_out = NULL;
  return false;
}

bool psbt_parse_payload(const uint8_t *data, size_t len,
                        struct wally_psbt **psbt_out) {
  if (!data || !psbt_out)
    return false;
  *psbt_out = NULL;

  while (len > 0 && (data[len - 1] == '\n' || data[len - 1] == '\r' ||
                     data[len - 1] == ' ' || data[len - 1] == '\t'))
    len--;

  return len > 0 &&
         (kern_psbt_from_bytes(data, len, WALLY_PSBT_PARSE_FLAG_COMPLETE,
                               psbt_out) == WALLY_OK ||
          parse_pending_outputs(data, len, psbt_out));
}
