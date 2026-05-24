#include "script_templates.h"

#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_script.h>

static bool p2wpkh_from_pubkey(const uint8_t *pubkey, size_t pubkey_len,
                               uint8_t *out, size_t *out_len) {
  return wally_witness_program_from_bytes(pubkey, pubkey_len,
                                          WALLY_SCRIPT_HASH160, out, 22,
                                          out_len) == WALLY_OK;
}

static bool p2pkh_from_pubkey(const uint8_t *pubkey, size_t pubkey_len,
                              uint8_t *out, size_t *out_len) {
  uint8_t pkh20[HASH160_LEN];
  if (wally_hash160(pubkey, pubkey_len, pkh20, HASH160_LEN) != WALLY_OK)
    return false;

  out[0] = 0x76;              /* OP_DUP */
  out[1] = 0xa9;              /* OP_HASH160 */
  out[2] = 0x14;              /* push 20 bytes */
  memcpy(out + 3, pkh20, 20); /* 20-byte hash160 */
  out[23] = 0x88;             /* OP_EQUALVERIFY */
  out[24] = 0xac;             /* OP_CHECKSIG */
  *out_len = 25;
  return true;
}

static bool p2sh_p2wpkh_from_pubkey(const uint8_t *pubkey, size_t pubkey_len,
                                    uint8_t *spk_out, size_t *spk_len,
                                    uint8_t *redeem_out, size_t *redeem_len) {
  uint8_t witness_prog[SCRIPT_TEMPLATE_P2SH_P2WPKH_REDEEM_LEN];
  size_t witness_prog_len = 0;
  if (!p2wpkh_from_pubkey(pubkey, pubkey_len, witness_prog,
                          &witness_prog_len) ||
      witness_prog_len != SCRIPT_TEMPLATE_P2SH_P2WPKH_REDEEM_LEN)
    return false;

  uint8_t sh20[HASH160_LEN];
  if (wally_hash160(witness_prog, witness_prog_len, sh20, HASH160_LEN) !=
      WALLY_OK)
    return false;

  spk_out[0] = 0xa9;             /* OP_HASH160 */
  spk_out[1] = 0x14;             /* push 20 bytes */
  memcpy(spk_out + 2, sh20, 20); /* 20-byte script hash */
  spk_out[22] = 0x87;            /* OP_EQUAL */
  *spk_len = SCRIPT_TEMPLATE_P2SH_P2WPKH_SPK_LEN;

  if (redeem_out && redeem_len) {
    memcpy(redeem_out, witness_prog, witness_prog_len);
    *redeem_len = witness_prog_len;
  }
  return true;
}

static bool p2tr_from_pubkey(const uint8_t *pubkey, size_t pubkey_len,
                             uint8_t *out, size_t *out_len) {
  uint8_t tweaked_pk33[EC_PUBLIC_KEY_LEN];
  if (wally_ec_public_key_bip341_tweak(pubkey, pubkey_len, NULL, 0, 0,
                                       tweaked_pk33,
                                       sizeof(tweaked_pk33)) != WALLY_OK)
    return false;

  out[0] = 0x51;                         /* OP_1 */
  out[1] = 0x20;                         /* push 32 bytes */
  memcpy(out + 2, tweaked_pk33 + 1, 32); /* x-only tweaked pubkey */
  *out_len = 34;
  return true;
}

bool script_template_from_pubkey(script_template_type_t type,
                                 const uint8_t *pubkey, size_t pubkey_len,
                                 uint8_t *spk_out, size_t *spk_len,
                                 uint8_t *redeem_out, size_t *redeem_len) {
  if (!pubkey || !spk_out || !spk_len)
    return false;
  if (redeem_len)
    *redeem_len = 0;

  switch (type) {
  case SCRIPT_TEMPLATE_P2PKH:
    return p2pkh_from_pubkey(pubkey, pubkey_len, spk_out, spk_len);
  case SCRIPT_TEMPLATE_P2SH_P2WPKH:
    return p2sh_p2wpkh_from_pubkey(pubkey, pubkey_len, spk_out, spk_len,
                                   redeem_out, redeem_len);
  case SCRIPT_TEMPLATE_P2WPKH:
    return p2wpkh_from_pubkey(pubkey, pubkey_len, spk_out, spk_len);
  case SCRIPT_TEMPLATE_P2TR:
    return p2tr_from_pubkey(pubkey, pubkey_len, spk_out, spk_len);
  }

  return false;
}

bool script_template_pubkey_matches_spk(const uint8_t *pubkey,
                                        size_t pubkey_len,
                                        const uint8_t *target_spk,
                                        size_t target_spk_len) {
  if (!pubkey || !target_spk || target_spk_len == 0)
    return false;

  static const script_template_type_t types[] = {
      SCRIPT_TEMPLATE_P2WPKH,
      SCRIPT_TEMPLATE_P2TR,
      SCRIPT_TEMPLATE_P2PKH,
      SCRIPT_TEMPLATE_P2SH_P2WPKH,
  };

  uint8_t candidate[SCRIPT_TEMPLATE_MAX_SPK_LEN];
  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    size_t candidate_len = 0;
    if (script_template_from_pubkey(types[i], pubkey, pubkey_len, candidate,
                                    &candidate_len, NULL, NULL) &&
        candidate_len == target_spk_len &&
        memcmp(candidate, target_spk, candidate_len) == 0) {
      return true;
    }
  }

  return false;
}

char *script_template_address_from_spk(const unsigned char *script,
                                       size_t script_len, bool is_testnet) {
  if (!script || script_len == 0)
    return NULL;

  size_t script_type = 0;
  if (wally_scriptpubkey_get_type(script, script_len, &script_type) != WALLY_OK)
    return NULL;

  char *address = NULL;
  const char *hrp = is_testnet ? "tb" : "bc";
  uint32_t network = is_testnet ? WALLY_NETWORK_BITCOIN_TESTNET
                                : WALLY_NETWORK_BITCOIN_MAINNET;

  if (script_type == WALLY_SCRIPT_TYPE_P2WPKH ||
      script_type == WALLY_SCRIPT_TYPE_P2WSH ||
      script_type == WALLY_SCRIPT_TYPE_P2TR) {
    if (wally_addr_segwit_from_bytes(script, script_len, hrp, 0, &address) !=
        WALLY_OK)
      return NULL;
  } else if (script_type == WALLY_SCRIPT_TYPE_P2PKH ||
             script_type == WALLY_SCRIPT_TYPE_P2SH) {
    if (wally_scriptpubkey_to_address(script, script_len, network, &address) !=
        WALLY_OK)
      return NULL;
  } else if (script_type == WALLY_SCRIPT_TYPE_OP_RETURN) {
    address = strdup("OP_RETURN");
  }

  return address;
}
