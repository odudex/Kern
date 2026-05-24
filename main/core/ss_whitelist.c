#include "ss_whitelist.h"
#include "key.h"
#include <stdio.h>
#include <stdlib.h> /* strtoul */
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_descriptor.h> /* wally_descriptor_canonicalize, wally_descriptor_get_key_origin_path_str */

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

static uint32_t ss_purpose_for_script(ss_script_type_t script) {
  switch (script) {
  case SS_SCRIPT_P2PKH:
    return 44;
  case SS_SCRIPT_P2SH_P2WPKH:
    return 49;
  case SS_SCRIPT_P2WPKH:
    return 84;
  case SS_SCRIPT_P2TR:
    return 86;
  default:
    return 0;
  }
}

static script_template_type_t ss_template_for_script(ss_script_type_t script) {
  switch (script) {
  case SS_SCRIPT_P2PKH:
    return SCRIPT_TEMPLATE_P2PKH;
  case SS_SCRIPT_P2SH_P2WPKH:
    return SCRIPT_TEMPLATE_P2SH_P2WPKH;
  case SS_SCRIPT_P2WPKH:
    return SCRIPT_TEMPLATE_P2WPKH;
  case SS_SCRIPT_P2TR:
  default:
    return SCRIPT_TEMPLATE_P2TR;
  }
}

static bool ss_derive_key(ss_script_type_t script, uint32_t account,
                          uint32_t chain, uint32_t index, bool is_testnet,
                          struct ext_key **key_out) {
  uint32_t purpose = ss_purpose_for_script(script);
  if (purpose == 0)
    return false;

  uint32_t path[] = {
      BIP32_PATH_HARDENED | purpose,
      BIP32_PATH_HARDENED | (is_testnet ? 1u : 0u),
      BIP32_PATH_HARDENED | account,
      chain,
      index,
  };

  return key_get_derived_key_components(path, sizeof(path) / sizeof(path[0]),
                                        key_out);
}

static bool ss_scriptpubkey_common(ss_script_type_t script, uint32_t account,
                                   uint32_t chain, uint32_t index,
                                   bool is_testnet, uint8_t *spk_out,
                                   size_t *spk_len, uint8_t *redeem_out,
                                   size_t *redeem_len) {
  if (!spk_out || !spk_len)
    return false;

  struct ext_key *derived_key = NULL;
  if (!ss_derive_key(script, account, chain, index, is_testnet, &derived_key))
    return false;

  bool ok = script_template_from_pubkey(
      ss_template_for_script(script), derived_key->pub_key, EC_PUBLIC_KEY_LEN,
      spk_out, spk_len, redeem_out, redeem_len);
  bip32_key_free(derived_key);
  return ok;
}

bool ss_scriptpubkey(ss_script_type_t script, uint32_t account, uint32_t chain,
                     uint32_t index, bool is_testnet, uint8_t *out,
                     size_t *out_len) {
  return ss_scriptpubkey_common(script, account, chain, index, is_testnet, out,
                                out_len, NULL, NULL);
}

bool ss_scriptpubkey_with_redeem(ss_script_type_t script, uint32_t account,
                                 uint32_t chain, uint32_t index,
                                 bool is_testnet, uint8_t *spk_out,
                                 size_t *spk_len, uint8_t *redeem_out,
                                 size_t *redeem_len) {
  return ss_scriptpubkey_common(script, account, chain, index, is_testnet,
                                spk_out, spk_len, redeem_out, redeem_len);
}

bool ss_address(ss_script_type_t script, uint32_t account, uint32_t chain,
                uint32_t index, bool is_testnet, char *address_out,
                size_t address_out_len) {
  uint8_t spk[34];
  size_t spk_len = 0;
  if (!ss_scriptpubkey(script, account, chain, index, is_testnet, spk,
                       &spk_len))
    return false;

  char *alloc = script_template_address_from_spk(spk, spk_len, is_testnet);
  if (!alloc)
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
