#ifndef SCRIPT_TEMPLATES_H
#define SCRIPT_TEMPLATES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
  SCRIPT_TEMPLATE_P2PKH,
  SCRIPT_TEMPLATE_P2SH_P2WPKH,
  SCRIPT_TEMPLATE_P2WPKH,
  SCRIPT_TEMPLATE_P2TR,
} script_template_type_t;

#define SCRIPT_TEMPLATE_MAX_SPK_LEN 34
#define SCRIPT_TEMPLATE_P2SH_P2WPKH_REDEEM_LEN 22
#define SCRIPT_TEMPLATE_P2SH_P2WPKH_SPK_LEN 23

bool script_template_from_pubkey(script_template_type_t type,
                                 const uint8_t *pubkey, size_t pubkey_len,
                                 uint8_t *spk_out, size_t *spk_len,
                                 uint8_t *redeem_out, size_t *redeem_len);

bool script_template_pubkey_matches_spk(const uint8_t *pubkey,
                                        size_t pubkey_len,
                                        const uint8_t *target_spk,
                                        size_t target_spk_len);

char *script_template_address_from_spk(const unsigned char *script,
                                       size_t script_len, bool is_testnet);

#endif // SCRIPT_TEMPLATES_H
