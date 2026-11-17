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

psbt_parse_result_t psbt_parse_payload_result(const uint8_t *data, size_t len,
                                              struct wally_psbt **psbt_out) {
  if (!data || !psbt_out)
    return PSBT_PARSE_INVALID;
  *psbt_out = NULL;

  while (len > 0 && (data[len - 1] == '\n' || data[len - 1] == '\r' ||
                     data[len - 1] == ' ' || data[len - 1] == '\t'))
    len--;
  if (len == 0)
    return PSBT_PARSE_INVALID;

  if (kern_psbt_from_bytes(data, len, WALLY_PSBT_PARSE_FLAG_COMPLETE,
                           psbt_out) != WALLY_OK &&
      !parse_pending_outputs(data, len, psbt_out))
    return PSBT_PARSE_INVALID;
  if (sp_psbt_has_outputs(*psbt_out) &&
      !sp_psbt_raw_sighash_is_all(data, len, (*psbt_out)->num_inputs)) {
    wally_psbt_free(*psbt_out);
    *psbt_out = NULL;
    return PSBT_PARSE_SP_SIGHASH;
  }
  return PSBT_PARSE_OK;
}

bool psbt_parse_payload(const uint8_t *data, size_t len,
                        struct wally_psbt **psbt_out) {
  return psbt_parse_payload_result(data, len, psbt_out) == PSBT_PARSE_OK;
}
