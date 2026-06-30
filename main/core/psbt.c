#include "psbt.h"
#include "bip32_path.h"
#include "key.h"
#include "psbt_internal.h"
#include "script_templates.h"
#include "wallet.h"
#include <esp_log.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>
#include <wally_map.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

static const char *TAG = "PSBT";

#ifdef PSBT_TESTING
#define PSBT_PRIVATE
#else
#define PSBT_PRIVATE static
#endif

uint64_t psbt_get_input_value(const struct wally_psbt *psbt, size_t index) {
  struct wally_tx_output *utxo = NULL;
  uint64_t value = 0;

  if (wally_psbt_get_input_best_utxo_alloc(psbt, index, &utxo) == WALLY_OK &&
      utxo) {
    value = utxo->satoshi;
    wally_tx_output_free(utxo);
  }

  return value;
}

bool psbt_input_utxo_script(const struct wally_psbt *psbt, size_t input_i,
                            unsigned char *out, size_t out_cap,
                            size_t *out_len) {
  struct wally_tx_output *witness_utxo = NULL;
  if (wally_psbt_get_input_witness_utxo_alloc(psbt, input_i, &witness_utxo) ==
          WALLY_OK &&
      witness_utxo) {
    if (witness_utxo->script_len > out_cap) {
      wally_tx_output_free(witness_utxo);
      return false;
    }
    memcpy(out, witness_utxo->script, witness_utxo->script_len);
    *out_len = witness_utxo->script_len;
    wally_tx_output_free(witness_utxo);
    return true;
  }

  struct wally_tx *tx = NULL;
  if (wally_psbt_get_input_utxo_alloc(psbt, input_i, &tx) != WALLY_OK || !tx) {
    return false;
  }

  uint32_t prevout_index = 0;
  if (wally_psbt_get_input_output_index(psbt, input_i, &prevout_index) !=
          WALLY_OK ||
      prevout_index >= tx->num_outputs) {
    wally_tx_free(tx);
    return false;
  }

  size_t script_len = tx->outputs[prevout_index].script_len;
  if (script_len > out_cap) {
    wally_tx_free(tx);
    return false;
  }

  memcpy(out, tx->outputs[prevout_index].script, script_len);
  *out_len = script_len;
  wally_tx_free(tx);
  return true;
}

static bool try_match_whitelist(const unsigned char *keypath,
                                size_t keypath_len, bool is_testnet,
                                claim_t *claim_out) {
  if (keypath_len != 4 + 5 * 4)
    return false;

  ss_keypath_t kp;
  if (!ss_keypath_parse(keypath + 4, keypath_len - 4, &kp))
    return false;

  if (!ss_keypath_is_whitelisted(&kp, is_testnet))
    return false;

  claim_out->kind = CLAIM_WHITELIST;
  claim_out->whitelist.script = kp.script;
  claim_out->whitelist.purpose = kp.purpose;
  claim_out->whitelist.coin = kp.coin;
  claim_out->whitelist.account = kp.account;
  claim_out->whitelist.chain = kp.chain;
  claim_out->whitelist.index = kp.index;

  claim_out->derived_path_len = 5;
  for (size_t i = 0; i < 5; i++)
    claim_out->derived_path[i] = ss_u32_le(keypath + 4 + i * 4);

  return true;
}

static bool try_match_registry(const unsigned char *keypath, size_t keypath_len,
                               size_t *cursor, claim_t *claim_out) {
  const registry_entry_t *entry =
      registry_match_keypath(keypath, keypath_len, cursor);
  if (!entry)
    return false;

  size_t origin_len = entry->origin_path_len;
  uint32_t mp = ss_u32_le(keypath + 4 + origin_len * 4);
  uint32_t ix = ss_u32_le(keypath + 4 + (origin_len + 1) * 4);

  claim_out->kind = CLAIM_REGISTRY;
  claim_out->registry.entry = entry;
  claim_out->registry.multi_index = mp;
  claim_out->registry.child_num = ix;

  size_t total_depth = (keypath_len - 4) / 4;
  claim_out->derived_path_len = total_depth;
  for (size_t i = 0; i < total_depth; i++)
    claim_out->derived_path[i] = ss_u32_le(keypath + 4 + i * 4);

  return true;
}

PSBT_PRIVATE bool claim_regenerate(const claim_t *claim, bool is_testnet,
                                   expected_scripts_t *out) {
  if (!claim || !out)
    return false;
  memset(out, 0, sizeof(*out));

  if (claim->kind == CLAIM_WHITELIST) {
    return ss_scriptpubkey_with_redeem(
        claim->whitelist.script, claim->whitelist.account,
        claim->whitelist.chain, claim->whitelist.index, is_testnet, out->spk,
        &out->spk_len, out->redeem, &out->redeem_len);
  }

  /* CLAIM_REGISTRY: generate scripts from descriptor via libwally */
  const registry_entry_t *e = claim->registry.entry;
  uint32_t mi = claim->registry.multi_index;
  uint32_t cn = claim->registry.child_num;

  /* depth=0 generation reuses the output buffer as workspace for the inner
   * script before hashing, so it needs max(inner_script_len, spk_len) bytes.
   * Borrow out->witness as that workspace (it is still zeroed/unused here
   * and gets overwritten by the depth=1/2 calls below), then copy the SPK.
   * libwally reports a too-small buffer as WALLY_OK with written > len and
   * the buffer untouched, hence the explicit written checks. */
  size_t spk_work_len = 0;
  if (wally_descriptor_to_script(e->desc, 0, 0, 0, mi, cn, 0, out->witness,
                                 sizeof(out->witness),
                                 &spk_work_len) != WALLY_OK ||
      spk_work_len > sizeof(out->spk))
    return false;
  memcpy(out->spk, out->witness, spk_work_len);
  out->spk_len = spk_work_len;

  size_t spk_type = 0;
  wally_scriptpubkey_get_type(out->spk, out->spk_len, &spk_type);

  if (spk_type == WALLY_SCRIPT_TYPE_P2WSH) {
    if (wally_descriptor_to_script(e->desc, 1, 0, 0, mi, cn, 0, out->witness,
                                   sizeof(out->witness),
                                   &out->witness_len) != WALLY_OK ||
        out->witness_len > sizeof(out->witness))
      return false;

  } else if (spk_type == WALLY_SCRIPT_TYPE_P2SH) {
    if (wally_descriptor_to_script(e->desc, 1, 0, 0, mi, cn, 0, out->redeem,
                                   sizeof(out->redeem),
                                   &out->redeem_len) != WALLY_OK ||
        out->redeem_len > sizeof(out->redeem))
      return false;

    /* sh(wsh(...)): if redeem is itself a P2WSH witness program,
     * depth=2 yields the inner witness script. */
    size_t redeem_type = 0;
    wally_scriptpubkey_get_type(out->redeem, out->redeem_len, &redeem_type);
    if (redeem_type == WALLY_SCRIPT_TYPE_P2WSH) {
      if (wally_descriptor_to_script(e->desc, 2, 0, 0, mi, cn, 0, out->witness,
                                     sizeof(out->witness),
                                     &out->witness_len) != WALLY_OK ||
          out->witness_len > sizeof(out->witness))
        return false;
    }
    /* sh(multi(...)): redeem is not P2WSH; out->witness_len stays 0 so the
     * stale workspace bytes left in out->witness are never read. */
  }
  /* Other types (P2WPKH, P2TR, etc.): no inner scripts needed. */

  return true;
}

static bool input_inner_scripts_match(const struct wally_psbt *psbt,
                                      size_t input_i,
                                      const expected_scripts_t *exp) {
  if (exp->redeem_len > 0) {
    unsigned char buf[PSBT_MAX_INNER_SCRIPT_LEN];
    size_t psbt_len = 0, written = 0;
    if (wally_psbt_get_input_redeem_script_len(psbt, input_i, &psbt_len) !=
            WALLY_OK ||
        psbt_len != exp->redeem_len ||
        wally_psbt_get_input_redeem_script(psbt, input_i, buf, sizeof(buf),
                                           &written) != WALLY_OK ||
        written != exp->redeem_len ||
        memcmp(buf, exp->redeem, exp->redeem_len) != 0) {
      return false;
    }
  }

  if (exp->witness_len > 0) {
    unsigned char buf[PSBT_MAX_INNER_SCRIPT_LEN];
    size_t psbt_len = 0, written = 0;
    if (wally_psbt_get_input_witness_script_len(psbt, input_i, &psbt_len) !=
            WALLY_OK ||
        psbt_len != exp->witness_len ||
        wally_psbt_get_input_witness_script(psbt, input_i, buf, sizeof(buf),
                                            &written) != WALLY_OK ||
        written != exp->witness_len ||
        memcmp(buf, exp->witness, exp->witness_len) != 0) {
      return false;
    }
  }

  return true;
}

static bool claim_matches_spk(const claim_t *claim, bool is_testnet,
                              const unsigned char *target_spk,
                              size_t target_spk_len,
                              const struct wally_psbt *input_psbt,
                              size_t input_i) {
  expected_scripts_t exp; /* zeroed by claim_regenerate */
  if (!claim_regenerate(claim, is_testnet, &exp) ||
      exp.spk_len != target_spk_len ||
      memcmp(exp.spk, target_spk, target_spk_len) != 0) {
    return false;
  }

  return !input_psbt || input_inner_scripts_match(input_psbt, input_i, &exp);
}

static bool try_match_claim(const unsigned char *keypath, size_t keypath_len,
                            bool is_testnet, const unsigned char *target_spk,
                            size_t target_spk_len,
                            const struct wally_psbt *input_psbt, size_t input_i,
                            claim_t *claim_out) {
  claim_t claim = {0};
  if (try_match_whitelist(keypath, keypath_len, is_testnet, &claim) &&
      claim_matches_spk(&claim, is_testnet, target_spk, target_spk_len,
                        input_psbt, input_i)) {
    *claim_out = claim;
    return true;
  }

  size_t cursor = 0;
  while (true) {
    memset(&claim, 0, sizeof(claim));
    if (!try_match_registry(keypath, keypath_len, &cursor, &claim))
      return false;
    if (claim_matches_spk(&claim, is_testnet, target_spk, target_spk_len,
                          input_psbt, input_i)) {
      *claim_out = claim;
      return true;
    }
  }
}

static bool keypath_matches_fingerprint(const unsigned char *keypath,
                                        size_t keypath_len,
                                        const unsigned char *fingerprint) {
  return keypath_len >= BIP32_KEY_FINGERPRINT_LEN &&
         memcmp(keypath, fingerprint, BIP32_KEY_FINGERPRINT_LEN) == 0;
}

static void remember_raw_keypath(unsigned char *dst, size_t dst_cap,
                                 size_t *dst_len, const unsigned char *src,
                                 size_t src_len) {
  if (*dst_len != 0)
    return;

  size_t copy = src_len <= dst_cap ? src_len : dst_cap;
  memcpy(dst, src, copy);
  *dst_len = copy;
}

/* Derive a key from raw_keypath, then check whether any of the four
 * standard spk shapes (p2pkh, p2sh-p2wpkh, p2wpkh, p2tr) over that
 * pubkey reproduces target_spk. Returns true on a match.
 *
 * Used by the classifier to distinguish OWNED_UNSAFE (fp + derive
 * verifies) from EXPECTED_OWNED (fp matches but derive doesn't reach
 * the spk — harness state). */
static bool derive_matches_spk(const unsigned char *raw_keypath,
                               size_t raw_keypath_len,
                               const unsigned char *target_spk,
                               size_t target_spk_len) {
  if (!target_spk || target_spk_len == 0)
    return false;

  uint32_t path[MAX_KEYPATH_TOTAL_DEPTH];
  size_t path_len = 0;
  if (!bip32_path_from_keypath(raw_keypath, raw_keypath_len, path, &path_len,
                               MAX_KEYPATH_TOTAL_DEPTH))
    return false;

  struct ext_key *derived = NULL;
  if (!key_get_derived_key_components(path, path_len, &derived))
    return false;

  bool match = script_template_pubkey_matches_spk(
      derived->pub_key, EC_PUBLIC_KEY_LEN, target_spk, target_spk_len);
  bip32_key_free(derived);
  return match;
}

input_ownership_t psbt_classify_input(const struct wally_psbt *psbt, size_t i,
                                      bool is_testnet) {
  input_ownership_t result = {0};

  unsigned char utxo_script[34];
  size_t utxo_script_len = 0;
  if (!psbt_input_utxo_script(psbt, i, utxo_script, sizeof(utxo_script),
                              &utxo_script_len))
    return result;

  unsigned char our_fp[BIP32_KEY_FINGERPRINT_LEN];
  if (!key_get_fingerprint(our_fp))
    return result;

  size_t keypaths_size = 0;
  wally_psbt_get_input_keypaths_size(psbt, i, &keypaths_size);

  for (size_t j = 0; j < keypaths_size; j++) {
    unsigned char keypath[MAX_KEYPATH_TOTAL_DEPTH * 4 + 4];
    size_t keypath_len = 0;
    if (wally_psbt_get_input_keypath(psbt, i, j, keypath, sizeof(keypath),
                                     &keypath_len) != WALLY_OK)
      continue;
    if (!keypath_matches_fingerprint(keypath, keypath_len, our_fp))
      continue;

    claim_t claim = {0};
    remember_raw_keypath(result.raw_keypath, sizeof(result.raw_keypath),
                         &result.raw_keypath_len, keypath, keypath_len);
    if (try_match_claim(keypath, keypath_len, is_testnet, utxo_script,
                        utxo_script_len, psbt, i, &claim)) {
      result.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
      result.claim = claim;
      return result;
    }
  }

  /* Taproot keypaths — libwally stores PSBT_IN_TAP_BIP32_DERIVATION entries
   * in a separate map whose value has the same `fp(4) | path(4*depth)`
   * shape as the segwit keypaths map. Iterate it and run the same
   * whitelist+registry match. */
  const struct wally_map *tp_paths = &psbt->inputs[i].taproot_leaf_paths;
  for (size_t j = 0; j < tp_paths->num_items; j++) {
    const struct wally_map_item *item = &tp_paths->items[j];
    const unsigned char *val = item->value;
    size_t val_len = item->value_len;
    if (!keypath_matches_fingerprint(val, val_len, our_fp))
      continue;

    claim_t claim = {0};
    remember_raw_keypath(result.raw_keypath, sizeof(result.raw_keypath),
                         &result.raw_keypath_len, val, val_len);
    if (try_match_claim(val, val_len, is_testnet, utxo_script, utxo_script_len,
                        NULL, 0, &claim)) {
      result.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
      result.claim = claim;
      return result;
    }
  }

  /* fp matched but no whitelist/registry claim verified. Distinguish:
   *   OWNED_UNSAFE   — derive(raw_keypath) reproduces the spk; factually
   *                     ours, just on a non-standard path
   *   EXPECTED_OWNED — derive doesn't (or can't) reproduce the spk;
   *                     harness state. The signing-policy gate uses the
   *                     matching settings to decide whether to allow signing.
   */
  if (result.raw_keypath_len > 0) {
    if (derive_matches_spk(result.raw_keypath, result.raw_keypath_len,
                           utxo_script, utxo_script_len))
      result.ownership = PSBT_OWNERSHIP_OWNED_UNSAFE;
    else
      result.ownership = PSBT_OWNERSHIP_EXPECTED_OWNED;
    return result;
  }

  return result;
}

output_ownership_t psbt_classify_output(const struct wally_psbt *psbt, size_t i,
                                        bool is_testnet) {
  output_ownership_t result = {0};

  struct wally_tx *global_tx = NULL;
  if (wally_psbt_get_global_tx_alloc(psbt, &global_tx) != WALLY_OK ||
      !global_tx)
    return result;

  if (i >= global_tx->num_outputs) {
    wally_tx_free(global_tx);
    return result;
  }

  const unsigned char *out_script = global_tx->outputs[i].script;
  size_t out_script_len = global_tx->outputs[i].script_len;

  unsigned char our_fp[BIP32_KEY_FINGERPRINT_LEN];
  if (!key_get_fingerprint(our_fp)) {
    wally_tx_free(global_tx);
    return result;
  }

  size_t keypaths_size = 0;
  wally_psbt_get_output_keypaths_size(psbt, i, &keypaths_size);

  for (size_t j = 0; j < keypaths_size; j++) {
    unsigned char keypath[MAX_KEYPATH_TOTAL_DEPTH * 4 + 4];
    size_t keypath_len = 0;
    if (wally_psbt_get_output_keypath(psbt, i, j, keypath, sizeof(keypath),
                                      &keypath_len) != WALLY_OK)
      continue;
    if (!keypath_matches_fingerprint(keypath, keypath_len, our_fp))
      continue;

    claim_t claim = {0};
    remember_raw_keypath(result.raw_keypath, sizeof(result.raw_keypath),
                         &result.raw_keypath_len, keypath, keypath_len);
    if (try_match_claim(keypath, keypath_len, is_testnet, out_script,
                        out_script_len, NULL, 0, &claim)) {
      result.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
      result.source = claim;
      wally_tx_free(global_tx);
      return result;
    }
  }

  /* Taproot outputs — like the input classifier, libwally stores
   * PSBT_OUT_TAP_BIP32_DERIVATION entries in a separate map whose value has
   * the same fp(4)|path shape as the segwit keypaths. Without this, taproot
   * change/self-transfer outputs are mistaken for external spends. */
  const struct wally_map *tp_paths = &psbt->outputs[i].taproot_leaf_paths;
  for (size_t j = 0; j < tp_paths->num_items; j++) {
    const struct wally_map_item *item = &tp_paths->items[j];
    const unsigned char *val = item->value;
    size_t val_len = item->value_len;
    if (!keypath_matches_fingerprint(val, val_len, our_fp))
      continue;

    claim_t claim = {0};
    remember_raw_keypath(result.raw_keypath, sizeof(result.raw_keypath),
                         &result.raw_keypath_len, val, val_len);
    if (try_match_claim(val, val_len, is_testnet, out_script, out_script_len,
                        NULL, 0, &claim)) {
      result.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
      result.source = claim;
      wally_tx_free(global_tx);
      return result;
    }
  }

  /* fp matched but no whitelist/registry claim verified. Same harness
   * split as the input classifier: OWNED_UNSAFE if derive verifies,
   * EXPECTED_OWNED otherwise. */
  if (result.raw_keypath_len > 0) {
    if (derive_matches_spk(result.raw_keypath, result.raw_keypath_len,
                           out_script, out_script_len))
      result.ownership = PSBT_OWNERSHIP_OWNED_UNSAFE;
    else
      result.ownership = PSBT_OWNERSHIP_EXPECTED_OWNED;
  }

  wally_tx_free(global_tx);
  return result;
}

static bool check_keypath_network(const unsigned char *keypath,
                                  size_t keypath_len, bool *is_testnet) {
  if (keypath_len < 12) {
    return false;
  }

  uint32_t coin_type;
  memcpy(&coin_type, keypath + 8, sizeof(uint32_t));
  uint32_t coin_value = coin_type & 0x7FFFFFFF;

  if (coin_value == 0 || coin_value == 1) {
    *is_testnet = (coin_value == 1);
    return true;
  }

  return false;
}

bool psbt_detect_network(const struct wally_psbt *psbt) {
  if (!psbt) {
    return false;
  }

  unsigned char keypath[100];
  size_t keypath_len, keypaths_size;
  bool is_testnet;

  // Check outputs first
  size_t num_outputs = 0;
  wally_psbt_get_num_outputs(psbt, &num_outputs);

  for (size_t i = 0; i < num_outputs; i++) {
    if (wally_psbt_get_output_keypaths_size(psbt, i, &keypaths_size) ==
            WALLY_OK &&
        keypaths_size > 0 &&
        wally_psbt_get_output_keypath(psbt, i, 0, keypath, sizeof(keypath),
                                      &keypath_len) == WALLY_OK &&
        check_keypath_network(keypath, keypath_len, &is_testnet)) {
      return is_testnet;
    }
    // Taproot outputs store derivation in a separate map (PSBT_OUT_TAP_BIP32),
    // whose value has the same fp(4)|path shape as the segwit keypaths.
    const struct wally_map *tp = &psbt->outputs[i].taproot_leaf_paths;
    if (tp->num_items > 0 &&
        check_keypath_network(tp->items[0].value, tp->items[0].value_len,
                              &is_testnet)) {
      return is_testnet;
    }
  }

  // Check inputs as fallback
  size_t num_inputs = 0;
  wally_psbt_get_num_inputs(psbt, &num_inputs);

  for (size_t i = 0; i < num_inputs; i++) {
    if (wally_psbt_get_input_keypaths_size(psbt, i, &keypaths_size) ==
            WALLY_OK &&
        keypaths_size > 0 &&
        wally_psbt_get_input_keypath(psbt, i, 0, keypath, sizeof(keypath),
                                     &keypath_len) == WALLY_OK &&
        check_keypath_network(keypath, keypath_len, &is_testnet)) {
      return is_testnet;
    }
    const struct wally_map *tp = &psbt->inputs[i].taproot_leaf_paths;
    if (tp->num_items > 0 &&
        check_keypath_network(tp->items[0].value, tp->items[0].value_len,
                              &is_testnet)) {
      return is_testnet;
    }
  }

  return false; // Default to mainnet
}

static bool extract_account_from_keypath(const unsigned char *keypath,
                                         size_t keypath_len,
                                         uint32_t *account_out) {
  if (keypath_len < 16) {
    return false;
  }

  uint32_t account;
  memcpy(&account, keypath + 12, sizeof(uint32_t));

  // Remove hardened bit to get actual account number
  *account_out = account & 0x7FFFFFFF;
  return true;
}

int32_t psbt_detect_account(const struct wally_psbt *psbt) {
  if (!psbt) {
    return -1;
  }

  unsigned char keypath[100];
  size_t keypath_len, keypaths_size;
  uint32_t detected_account = 0;
  bool found = false;

  // Check outputs first (more reliable for change outputs)
  size_t num_outputs = 0;
  wally_psbt_get_num_outputs(psbt, &num_outputs);

  for (size_t i = 0; i < num_outputs; i++) {
    if (wally_psbt_get_output_keypaths_size(psbt, i, &keypaths_size) ==
            WALLY_OK &&
        keypaths_size > 0 &&
        wally_psbt_get_output_keypath(psbt, i, 0, keypath, sizeof(keypath),
                                      &keypath_len) == WALLY_OK) {
      uint32_t account;
      if (extract_account_from_keypath(keypath, keypath_len, &account)) {
        if (!found) {
          detected_account = account;
          found = true;
        } else if (account != detected_account) {
          // Inconsistent accounts found
          return -1;
        }
      }
    }
  }

  // Check inputs as fallback
  size_t num_inputs = 0;
  wally_psbt_get_num_inputs(psbt, &num_inputs);

  for (size_t i = 0; i < num_inputs; i++) {
    if (wally_psbt_get_input_keypaths_size(psbt, i, &keypaths_size) ==
            WALLY_OK &&
        keypaths_size > 0 &&
        wally_psbt_get_input_keypath(psbt, i, 0, keypath, sizeof(keypath),
                                     &keypath_len) == WALLY_OK) {
      uint32_t account;
      if (extract_account_from_keypath(keypath, keypath_len, &account)) {
        if (!found) {
          detected_account = account;
          found = true;
        } else if (account != detected_account) {
          // Inconsistent accounts found
          return -1;
        }
      }
    }
  }

  return found ? (int32_t)detected_account : -1;
}

char *psbt_scriptpubkey_to_address(const unsigned char *script,
                                   size_t script_len, bool is_testnet) {
  return script_template_address_from_spk(script, script_len, is_testnet);
}

bool psbt_format_keypath(const unsigned char *raw_keypath,
                         size_t raw_keypath_len, char *buf, size_t buf_size) {
  return bip32_path_format_keypath(raw_keypath, raw_keypath_len, buf, buf_size,
                                   MAX_KEYPATH_TOTAL_DEPTH);
}

size_t psbt_sign(struct wally_psbt *psbt, bool is_testnet,
                 psbt_sign_policy_t policy) {
  if (!psbt) {
    ESP_LOGE(TAG, "Invalid PSBT");
    return 0;
  }

  size_t num_inputs = 0;
  if (wally_psbt_get_num_inputs(psbt, &num_inputs) != WALLY_OK) {
    ESP_LOGE(TAG, "Failed to get number of inputs");
    return 0;
  }

  size_t signatures_added = 0;

  /* Cache shared sighash midstates so per-input signing is O(n), not O(n^2). */
  wally_psbt_signing_cache_enable(psbt, 0);

  for (size_t i = 0; i < num_inputs; i++) {
    input_ownership_t ownership = psbt_classify_input(psbt, i, is_testnet);

    if (ownership.ownership == PSBT_OWNERSHIP_EXTERNAL)
      continue;
    if (ownership.ownership == PSBT_OWNERSHIP_OWNED_UNSAFE &&
        !policy.allow_unsafe) {
      ESP_LOGW(TAG,
               "Skipping input %zu: OWNED_UNSAFE without permissive policy", i);
      continue;
    }
    if (ownership.ownership == PSBT_OWNERSHIP_EXPECTED_OWNED &&
        !policy.allow_expected_owned) {
      ESP_LOGW(
          TAG,
          "Skipping input %zu: EXPECTED_OWNED without expected-owned policy",
          i);
      continue;
    }

    const uint32_t *path = NULL;
    size_t path_len = 0;
    uint32_t raw_comps[MAX_KEYPATH_TOTAL_DEPTH];

    if (ownership.ownership == PSBT_OWNERSHIP_OWNED_SAFE) {
      path = ownership.claim.derived_path;
      path_len = ownership.claim.derived_path_len;
    } else {
      /* OWNED_UNSAFE / EXPECTED_OWNED — policy already vetted above; derive
       * from the raw path supplied in the PSBT. */
      if (!bip32_path_from_keypath(ownership.raw_keypath,
                                   ownership.raw_keypath_len, raw_comps,
                                   &path_len, MAX_KEYPATH_TOTAL_DEPTH))
        continue;
      path = raw_comps;
    }

    if (!path || path_len > MAX_KEYPATH_TOTAL_DEPTH) {
      ESP_LOGE(TAG, "Invalid signing path for input %zu", i);
      continue;
    }

    struct ext_key *derived_key = NULL;
    if (!key_get_derived_key_components(path, path_len, &derived_key)) {
      ESP_LOGE(TAG, "Failed to derive key for input %zu", i);
      continue;
    }

    int ret = wally_psbt_sign(psbt, derived_key->priv_key + 1,
                              EC_PRIVATE_KEY_LEN, EC_FLAG_GRIND_R);
    bip32_key_free(derived_key);

    if (ret == WALLY_OK) {
      signatures_added++;
    } else {
      ESP_LOGE(TAG, "Failed to sign input %zu: %d", i, ret);
    }
  }

  wally_psbt_signing_cache_disable(psbt);

  return signatures_added;
}

struct wally_psbt *psbt_trim(const struct wally_psbt *psbt) {
  if (!psbt) {
    return NULL;
  }

  struct wally_tx *global_tx = NULL;
  if (wally_psbt_get_global_tx_alloc(psbt, &global_tx) != WALLY_OK ||
      !global_tx) {
    return NULL;
  }

  struct wally_psbt *trimmed = NULL;
  if (wally_psbt_from_tx(global_tx, 0, 0, &trimmed) != WALLY_OK) {
    wally_tx_free(global_tx);
    return NULL;
  }
  wally_tx_free(global_tx);

  size_t num_inputs = 0;
  wally_psbt_get_num_inputs(psbt, &num_inputs);

  for (size_t i = 0; i < num_inputs; i++) {
    // Copy partial signatures using direct map access
    size_t sigs_size = 0;
    if (wally_psbt_get_input_signatures_size(psbt, i, &sigs_size) == WALLY_OK &&
        sigs_size > 0) {
      // Access the signatures map directly from the source PSBT input
      const struct wally_map *sig_map = &psbt->inputs[i].signatures;
      for (size_t j = 0; j < sig_map->num_items; j++) {
        const struct wally_map_item *item = &sig_map->items[j];
        if (item->key && item->key_len > 0 && item->value &&
            item->value_len > 0) {
          wally_psbt_add_input_signature(trimmed, i, item->key, item->key_len,
                                         item->value, item->value_len);
        }
      }
    }

    // Copy final witness if present
    struct wally_tx_witness_stack *witness = NULL;
    if (wally_psbt_get_input_final_witness_alloc(psbt, i, &witness) ==
            WALLY_OK &&
        witness) {
      wally_psbt_set_input_final_witness(trimmed, i, witness);
      wally_tx_witness_stack_free(witness);
    }

    // Copy final scriptsig if present
    size_t scriptsig_len = 0;
    if (wally_psbt_get_input_final_scriptsig_len(psbt, i, &scriptsig_len) ==
            WALLY_OK &&
        scriptsig_len > 0) {
      unsigned char *scriptsig = malloc(scriptsig_len);
      if (scriptsig) {
        size_t written = 0;
        if (wally_psbt_get_input_final_scriptsig(
                psbt, i, scriptsig, scriptsig_len, &written) == WALLY_OK) {
          wally_psbt_set_input_final_scriptsig(trimmed, i, scriptsig, written);
        }
        free(scriptsig);
      }
    }

    // Copy witness UTXO if present
    struct wally_tx_output *witness_utxo = NULL;
    if (wally_psbt_get_input_witness_utxo_alloc(psbt, i, &witness_utxo) ==
            WALLY_OK &&
        witness_utxo) {
      wally_psbt_set_input_witness_utxo(trimmed, i, witness_utxo);
      wally_tx_output_free(witness_utxo);
    }

    // Copy non-witness UTXO if present (for legacy inputs)
    struct wally_tx *utxo = NULL;
    if (wally_psbt_get_input_utxo_alloc(psbt, i, &utxo) == WALLY_OK && utxo) {
      wally_psbt_set_input_utxo(trimmed, i, utxo);
      wally_tx_free(utxo);
    }

    // Copy redeem script if present (P2SH)
    size_t redeem_len = 0;
    if (wally_psbt_get_input_redeem_script_len(psbt, i, &redeem_len) ==
            WALLY_OK &&
        redeem_len > 0) {
      unsigned char *redeem = malloc(redeem_len);
      if (redeem) {
        size_t written = 0;
        if (wally_psbt_get_input_redeem_script(psbt, i, redeem, redeem_len,
                                               &written) == WALLY_OK) {
          wally_psbt_set_input_redeem_script(trimmed, i, redeem, written);
        }
        free(redeem);
      }
    }

    // Copy witness script if present (P2WSH)
    size_t witness_script_len = 0;
    if (wally_psbt_get_input_witness_script_len(psbt, i, &witness_script_len) ==
            WALLY_OK &&
        witness_script_len > 0) {
      unsigned char *witness_script = malloc(witness_script_len);
      if (witness_script) {
        size_t written = 0;
        if (wally_psbt_get_input_witness_script(psbt, i, witness_script,
                                                witness_script_len,
                                                &written) == WALLY_OK) {
          wally_psbt_set_input_witness_script(trimmed, i, witness_script,
                                              written);
        }
        free(witness_script);
      }
    }

    // Copy taproot key signature if present
    size_t tap_sig_len = 0;
    if (wally_psbt_get_input_taproot_signature_len(psbt, i, &tap_sig_len) ==
            WALLY_OK &&
        tap_sig_len > 0) {
      unsigned char tap_sig[65];
      size_t written = 0;
      if (wally_psbt_get_input_taproot_signature(
              psbt, i, tap_sig, sizeof(tap_sig), &written) == WALLY_OK) {
        wally_psbt_set_input_taproot_signature(trimmed, i, tap_sig, written);
      }
    }

    // Copy taproot script-path signatures (TAP_SCRIPT_SIG). These live in a
    // separate map from the key-path signature above; without this, script-path
    // (tapscript) spends would export with no signature.
    const struct wally_map *tap_sigs = &psbt->inputs[i].taproot_leaf_signatures;
    for (size_t j = 0; j < tap_sigs->num_items; j++) {
      const struct wally_map_item *item = &tap_sigs->items[j];
      if (item->key && item->key_len > 0 && item->value &&
          item->value_len > 0) {
        wally_psbt_input_add_taproot_leaf_signature(
            &trimmed->inputs[i], item->key, item->key_len, item->value,
            item->value_len);
      }
    }
  }

  return trimmed;
}
