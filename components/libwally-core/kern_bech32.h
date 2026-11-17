#pragma once
#include <stddef.h>
#include <stdint.h>

/* BIP352 caps silent payment strings at 1023 chars, past BIP173's 90. */
#define KERN_BECH32M_MAX_LEN 1023

/* Bech32m-encode `version` then `bytes` under `hrp` into `out`, which holds
 * `out_len` chars including the NUL. Returns WALLY_OK or WALLY_EINVAL. */
int kern_bech32m_encode(const char *hrp, uint8_t version,
                        const unsigned char *bytes, size_t bytes_len, char *out,
                        size_t out_len);
