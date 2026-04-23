#include "ss_whitelist.h"
#include "key.h"
#include <stdio.h>
#include <stdlib.h> /* strtoul */
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_crypto.h>
#include <wally_descriptor.h> /* wally_descriptor_canonicalize, wally_descriptor_get_key_origin_path_str */
#include <wally_script.h>

bool ss_keypath_parse(const unsigned char *keypath_after_fp,
                      size_t keypath_len_after_fp, ss_keypath_t *out) {
  if (keypath_len_after_fp != 20)
    return false;

  uint32_t c[5];
  for (int i = 0; i < 5; i++)
    c[i] = ss_u32_le(keypath_after_fp + 4 * i);

  // First 3 must be hardened (purpose, coin, account)
  if (!ss_is_hardened(c[0]) || !ss_is_hardened(c[1]) || !ss_is_hardened(c[2]))
    return false;

  // Last 2 must NOT be hardened (chain, index)
  if (ss_is_hardened(c[3]) || ss_is_hardened(c[4]))
    return false;

  uint32_t purpose = ss_unharden(c[0]);
  ss_script_type_t script;
  switch (purpose) {
  case 44:
    script = SS_SCRIPT_P2PKH;
    break;
  case 49:
    script = SS_SCRIPT_P2SH_P2WPKH;
    break;
  case 84:
    script = SS_SCRIPT_P2WPKH;
    break;
  case 86:
    script = SS_SCRIPT_P2TR;
    break;
  default:
    return false;
  }

  out->script = script;
  out->purpose = purpose;
  out->coin = ss_unharden(c[1]);
  out->account = ss_unharden(c[2]);
  out->chain = c[3];
  out->index = c[4];
  return true;
}

bool ss_keypath_format(const ss_keypath_t *kp, char *buf, size_t buf_size) {
  int n = snprintf(buf, buf_size, "m/%u'/%u'/%u'/%u/%u", kp->purpose, kp->coin,
                   kp->account, kp->chain, kp->index);
  return n >= 0 && (size_t)n < buf_size;
}

bool ss_keypath_is_whitelisted(const ss_keypath_t *kp, bool is_testnet) {
  if (kp->purpose != 44 && kp->purpose != 49 && kp->purpose != 84 &&
      kp->purpose != 86)
    return false;

  uint32_t expected_coin = is_testnet ? 1u : 0u;
  if (kp->coin != expected_coin)
    return false;

  if (kp->account >= SS_MAX_ACCOUNT)
    return false;

  if (kp->chain > 1)
    return false;

  if (kp->index >= SS_MAX_ADDR_INDEX)
    return false;

  return true;
}

bool ss_scriptpubkey(ss_script_type_t script, uint32_t account, uint32_t chain,
                     uint32_t index, bool is_testnet, uint8_t *out,
                     size_t *out_len) {
  switch (script) {
  case SS_SCRIPT_P2WPKH: {
    ss_keypath_t kp = {
        .script = SS_SCRIPT_P2WPKH,
        .purpose = 84,
        .coin = is_testnet ? 1u : 0u,
        .account = account,
        .chain = chain,
        .index = index,
    };
    char path[SS_KEYPATH_FMT_MAX];
    if (!ss_keypath_format(&kp, path, sizeof(path)))
      return false;

    struct ext_key *derived_key = NULL;
    if (!key_get_derived_key(path, &derived_key))
      return false;

    int ret = wally_witness_program_from_bytes(
        derived_key->pub_key, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160, out, 22,
        out_len);
    bip32_key_free(derived_key);
    return ret == WALLY_OK;
  }
  case SS_SCRIPT_P2PKH: {
    ss_keypath_t kp = {
        .script = SS_SCRIPT_P2PKH,
        .purpose = 44,
        .coin = is_testnet ? 1u : 0u,
        .account = account,
        .chain = chain,
        .index = index,
    };
    char path[SS_KEYPATH_FMT_MAX];
    if (!ss_keypath_format(&kp, path, sizeof(path)))
      return false;

    struct ext_key *derived_key = NULL;
    if (!key_get_derived_key(path, &derived_key))
      return false;

    uint8_t pkh20[HASH160_LEN];
    int ret = wally_hash160(derived_key->pub_key, EC_PUBLIC_KEY_LEN, pkh20,
                            HASH160_LEN);
    bip32_key_free(derived_key);
    if (ret != WALLY_OK)
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
  case SS_SCRIPT_P2SH_P2WPKH: {
    ss_keypath_t kp = {
        .script = SS_SCRIPT_P2SH_P2WPKH,
        .purpose = 49,
        .coin = is_testnet ? 1u : 0u,
        .account = account,
        .chain = chain,
        .index = index,
    };
    char path[SS_KEYPATH_FMT_MAX];
    if (!ss_keypath_format(&kp, path, sizeof(path)))
      return false;

    struct ext_key *derived_key = NULL;
    if (!key_get_derived_key(path, &derived_key))
      return false;

    /* Build the 22-byte inner witness program (OP_0 <20-byte pkh>). */
    uint8_t witness_prog[SS_P2SH_P2WPKH_REDEEM_LEN];
    size_t witness_prog_len = 0;
    int ret = wally_witness_program_from_bytes(
        derived_key->pub_key, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160,
        witness_prog, sizeof(witness_prog), &witness_prog_len);
    bip32_key_free(derived_key);
    if (ret != WALLY_OK || witness_prog_len != SS_P2SH_P2WPKH_REDEEM_LEN)
      return false;

    /* Hash the witness program and wrap in OP_HASH160 <sh20> OP_EQUAL. */
    uint8_t sh20[HASH160_LEN];
    ret = wally_hash160(witness_prog, witness_prog_len, sh20, HASH160_LEN);
    if (ret != WALLY_OK)
      return false;

    out[0] = 0xa9;             /* OP_HASH160 */
    out[1] = 0x14;             /* push 20 bytes */
    memcpy(out + 2, sh20, 20); /* 20-byte script hash */
    out[22] = 0x87;            /* OP_EQUAL */
    *out_len = SS_P2SH_P2WPKH_SPK_LEN;
    return true;
  }
  case SS_SCRIPT_P2TR: {
    ss_keypath_t kp = {
        .script = SS_SCRIPT_P2TR,
        .purpose = 86,
        .coin = is_testnet ? 1u : 0u,
        .account = account,
        .chain = chain,
        .index = index,
    };
    char path[SS_KEYPATH_FMT_MAX];
    if (!ss_keypath_format(&kp, path, sizeof(path)))
      return false;

    struct ext_key *derived_key = NULL;
    if (!key_get_derived_key(path, &derived_key))
      return false;

    uint8_t tweaked_pk33[EC_PUBLIC_KEY_LEN];
    int ret = wally_ec_public_key_bip341_tweak(derived_key->pub_key,
                                               EC_PUBLIC_KEY_LEN, NULL, 0, 0,
                                               tweaked_pk33, EC_PUBLIC_KEY_LEN);
    bip32_key_free(derived_key);
    if (ret != WALLY_OK)
      return false;

    out[0] = 0x51;                         /* OP_1 */
    out[1] = 0x20;                         /* push 32 bytes */
    memcpy(out + 2, tweaked_pk33 + 1, 32); /* x-only tweaked pubkey */
    *out_len = 34;
    return true;
  }
  default:
    return false;
  }
}

bool ss_scriptpubkey_with_redeem(ss_script_type_t script, uint32_t account,
                                 uint32_t chain, uint32_t index,
                                 bool is_testnet, uint8_t *spk_out,
                                 size_t *spk_len, uint8_t *redeem_out,
                                 size_t *redeem_len) {
  if (script != SS_SCRIPT_P2SH_P2WPKH) {
    *redeem_len = 0;
    return ss_scriptpubkey(script, account, chain, index, is_testnet, spk_out,
                           spk_len);
  }

  ss_keypath_t kp = {
      .script = SS_SCRIPT_P2SH_P2WPKH,
      .purpose = 49,
      .coin = is_testnet ? 1u : 0u,
      .account = account,
      .chain = chain,
      .index = index,
  };
  char path[SS_KEYPATH_FMT_MAX];
  if (!ss_keypath_format(&kp, path, sizeof(path)))
    return false;

  struct ext_key *derived_key = NULL;
  if (!key_get_derived_key(path, &derived_key))
    return false;

  /* Build the 22-byte inner witness program (also the redeem script). */
  int ret = wally_witness_program_from_bytes(
      derived_key->pub_key, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160, redeem_out,
      SS_P2SH_P2WPKH_REDEEM_LEN, redeem_len);
  bip32_key_free(derived_key);
  if (ret != WALLY_OK || *redeem_len != SS_P2SH_P2WPKH_REDEEM_LEN)
    return false;

  /* Hash the redeem script and wrap in OP_HASH160 <sh20> OP_EQUAL. */
  uint8_t sh20[HASH160_LEN];
  ret = wally_hash160(redeem_out, *redeem_len, sh20, HASH160_LEN);
  if (ret != WALLY_OK)
    return false;

  spk_out[0] = 0xa9;             /* OP_HASH160 */
  spk_out[1] = 0x14;             /* push 20 bytes */
  memcpy(spk_out + 2, sh20, 20); /* 20-byte script hash */
  spk_out[22] = 0x87;            /* OP_EQUAL */
  *spk_len = SS_P2SH_P2WPKH_SPK_LEN;
  return true;
}

bool ss_address(ss_script_type_t script, uint32_t account, uint32_t chain,
                uint32_t index, bool is_testnet, char *address_out,
                size_t address_out_len) {
  uint8_t spk[34];
  size_t spk_len = 0;
  if (!ss_scriptpubkey(script, account, chain, index, is_testnet, spk,
                       &spk_len))
    return false;

  char *alloc = NULL;
  int ret;

  switch (script) {
  case SS_SCRIPT_P2WPKH:
  case SS_SCRIPT_P2TR: {
    const char *hrp = is_testnet ? "tb" : "bc";
    ret = wally_addr_segwit_from_bytes(spk, spk_len, hrp, 0, &alloc);
    break;
  }
  case SS_SCRIPT_P2PKH:
  case SS_SCRIPT_P2SH_P2WPKH: {
    uint32_t network = is_testnet ? WALLY_NETWORK_BITCOIN_TESTNET
                                  : WALLY_NETWORK_BITCOIN_MAINNET;
    ret = wally_scriptpubkey_to_address(spk, spk_len, network, &alloc);
    break;
  }
  default:
    return false;
  }

  if (ret != WALLY_OK || !alloc)
    return false;

  size_t len = strlen(alloc);
  if (len + 1 > address_out_len) {
    wally_free_string(alloc);
    return false;
  }

  memcpy(address_out, alloc, len + 1);
  wally_free_string(alloc);
  return true;
}

bool purpose_script_binding_check_strict(uint32_t purpose,
                                         ss_script_type_t outer_script) {
  switch (purpose) {
  case 44:
    return outer_script == SS_SCRIPT_P2PKH;
  case 49:
    return outer_script == SS_SCRIPT_P2SH_P2WPKH;
  case 84:
    return outer_script == SS_SCRIPT_P2WPKH;
  case 86:
    return outer_script == SS_SCRIPT_P2TR;
  default:
    return false;
  }
}

psb_result_t
purpose_script_binding_check_soft(const struct wally_descriptor *desc) {
  /* Step 1: Identify outer script type via canonical string */
  char *canon = NULL;
  if (wally_descriptor_canonicalize(desc, WALLY_MS_CANONICAL_NO_CHECKSUM,
                                    &canon) != WALLY_OK)
    return PSB_NA;

  bool is_pkh = (strncmp(canon, "pkh(", 4) == 0);
  bool is_sh_wpkh = (strncmp(canon, "sh(wpkh(", 8) == 0);
  bool is_wpkh = (strncmp(canon, "wpkh(", 5) == 0);
  bool is_tr = (strncmp(canon, "tr(", 3) == 0);
  bool is_wsh = (strncmp(canon, "wsh(", 4) == 0);
  bool is_sh_wsh = (strncmp(canon, "sh(wsh(", 7) == 0);
  wally_free_string(canon);

  /* Step 2: Parse purpose from key[0]'s origin path */
  char *path = NULL;
  if (wally_descriptor_get_key_origin_path_str(desc, 0, &path) != WALLY_OK ||
      !path || path[0] == '\0') {
    wally_free_string(path);
    return PSB_NA;
  }

  /* strtoul stops at "'" giving the unhardened purpose integer */
  char *end = NULL;
  unsigned long purpose_ul = strtoul(path, &end, 10);
  bool parse_ok = (end != path);
  wally_free_string(path);
  if (!parse_ok || purpose_ul > 0x7FFFFFFFul)
    return PSB_NA;
  uint32_t purpose = (uint32_t)purpose_ul;

  /* Step 3: Apply purpose ↔ outer-script convention table */
  switch (purpose) {
  case 44:
    return is_pkh ? PSB_OK : PSB_WARN;
  case 48:
    return (is_wsh || is_sh_wsh) ? PSB_OK : PSB_WARN;
  case 49:
    return is_sh_wpkh ? PSB_OK : PSB_WARN;
  case 84:
    return is_wpkh ? PSB_OK : PSB_WARN;
  case 86:
    return is_tr ? PSB_OK : PSB_WARN;
  default:
    return PSB_NA;
  }
}
