/* libwally amalgamation plus the BIP352 silentpayments module of the bundled
 * secp256k1-zkp, which needs the secp256k1 internals of the same translation
 * unit. */
#define ENABLE_MODULE_SILENTPAYMENTS 1
#include "upstream/src/amalgamation/combined.c"

#ifndef WALLY_NO_AMALGAMATION
#include "kern_bech32.h"

int kern_bech32m_encode(const char *hrp, uint8_t version,
                        const unsigned char *bytes, size_t bytes_len, char *out,
                        size_t out_len) {
  uint8_t data[KERN_BECH32M_MAX_LEN];
  size_t data_len = 0;
  /* Version group, then 8-bit bytes regrouped into padded 5-bit groups */
  const size_t groups = 1 + (bytes_len * 8 + 4) / 5;
  size_t hrp_len;

  if (!hrp || !bytes || !out || version > 31 || groups > sizeof(data))
    return WALLY_EINVAL;
  hrp_len = strlen(hrp);
  /* hrp, separator, data groups, 6-char checksum and NUL */
  if (hrp_len + 1 + groups + 6 + 1 > out_len)
    return WALLY_EINVAL;
  data[0] = version;
  convert_bits(data + 1, &data_len, 5, bytes, bytes_len, 8, 1);
  ++data_len;
  if (!bech32_encode(out, hrp, hrp_len, data, data_len, KERN_BECH32M_MAX_LEN,
                     true))
    return WALLY_EINVAL;
  return WALLY_OK;
}
#endif /* WALLY_NO_AMALGAMATION */
