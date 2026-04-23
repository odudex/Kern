#include "psbt.h"
#include "key.h"
#include "settings.h"
#include "wallet.h"
#include <esp_log.h>
#include <stdio.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>
#include <wally_map.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

static const char *TAG = "PSBT";

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

bool try_match_whitelist(const unsigned char *keypath, size_t keypath_len,
                         bool is_testnet, claim_t *claim_out) {
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

bool try_match_registry(const unsigned char *keypath, size_t keypath_len,
                        size_t *cursor, claim_t *claim_out) {
  registry_entry_t *entry =
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

bool claim_regenerate(const claim_t *claim, bool is_testnet,
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
  registry_entry_t *e = claim->registry.entry;
  uint32_t mi = claim->registry.multi_index;
  uint32_t cn = claim->registry.child_num;

  /* depth=0 generation reuses the output buffer as workspace for the inner
   * script before hashing, so it needs max(inner_script_len, spk_len) bytes.
   * Use a 520-byte local buffer (P2SH redeem script max) then copy the SPK. */
  uint8_t spk_work[520];
  size_t spk_work_len = 0;
  if (wally_descriptor_to_script(e->desc, 0, 0, 0, mi, cn, 0, spk_work,
                                 sizeof(spk_work), &spk_work_len) != WALLY_OK)
    return false;
  if (spk_work_len > sizeof(out->spk))
    return false;
  memcpy(out->spk, spk_work, spk_work_len);
  out->spk_len = spk_work_len;

  size_t spk_type = 0;
  wally_scriptpubkey_get_type(out->spk, out->spk_len, &spk_type);

  if (spk_type == WALLY_SCRIPT_TYPE_P2WSH) {
    if (wally_descriptor_to_script(e->desc, 1, 0, 0, mi, cn, 0, out->witness,
                                   sizeof(out->witness),
                                   &out->witness_len) != WALLY_OK)
      return false;

  } else if (spk_type == WALLY_SCRIPT_TYPE_P2SH) {
    if (wally_descriptor_to_script(e->desc, 1, 0, 0, mi, cn, 0, out->redeem,
                                   sizeof(out->redeem),
                                   &out->redeem_len) != WALLY_OK)
      return false;

    /* sh(wsh(...)): if redeem is itself a P2WSH witness program,
     * depth=2 yields the inner witness script. */
    size_t redeem_type = 0;
    wally_scriptpubkey_get_type(out->redeem, out->redeem_len, &redeem_type);
    if (redeem_type == WALLY_SCRIPT_TYPE_P2WSH) {
      if (wally_descriptor_to_script(e->desc, 2, 0, 0, mi, cn, 0, out->witness,
                                     sizeof(out->witness),
                                     &out->witness_len) != WALLY_OK)
        return false;
    }
    /* sh(multi(...)): redeem is not P2WSH; out->witness_len stays 0. */
  }
  /* Other types (P2WPKH, P2TR, etc.): no inner scripts needed. */

  return true;
}

/* Format a BIP32 path from raw `fp(4) | path(4*depth)` bytes into the
 * "m/.../...'/.../..." form consumed by key_get_derived_key. Mirrors
 * the public psbt_format_keypath helper but keeps it inlined here so
 * the classifier doesn't depend on call ordering. */
static bool raw_keypath_to_string(const unsigned char *raw, size_t raw_len,
                                  char *buf, size_t buf_size) {
  if (!raw || !buf || buf_size == 0)
    return false;
  if (raw_len < BIP32_KEY_FINGERPRINT_LEN ||
      (raw_len - BIP32_KEY_FINGERPRINT_LEN) % 4 != 0)
    return false;
  size_t n = (raw_len - BIP32_KEY_FINGERPRINT_LEN) / 4;
  if (n > MAX_KEYPATH_TOTAL_DEPTH)
    return false;
  int w = snprintf(buf, buf_size, "m");
  if (w < 0 || (size_t)w >= buf_size)
    return false;
  size_t pos = (size_t)w;
  for (size_t k = 0; k < n; k++) {
    uint32_t c = ss_u32_le(raw + BIP32_KEY_FINGERPRINT_LEN + k * 4);
    int written =
        ss_is_hardened(c)
            ? snprintf(buf + pos, buf_size - pos, "/%u'", ss_unharden(c))
            : snprintf(buf + pos, buf_size - pos, "/%u", c);
    if (written < 0 || pos + (size_t)written >= buf_size)
      return false;
    pos += (size_t)written;
  }
  return true;
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

  char path[128];
  if (!raw_keypath_to_string(raw_keypath, raw_keypath_len, path, sizeof(path)))
    return false;

  struct ext_key *derived = NULL;
  if (!key_get_derived_key(path, &derived))
    return false;

  bool match = false;
  uint8_t cand[34];
  size_t cand_len = 0;

  /* P2WPKH: OP_0 <hash160(pub)> */
  if (!match &&
      wally_witness_program_from_bytes(derived->pub_key, EC_PUBLIC_KEY_LEN,
                                       WALLY_SCRIPT_HASH160, cand, sizeof(cand),
                                       &cand_len) == WALLY_OK &&
      cand_len == target_spk_len && memcmp(cand, target_spk, cand_len) == 0)
    match = true;

  /* P2TR: OP_1 <push 32> <bip341-tweaked xonly> */
  if (!match) {
    uint8_t tweaked[EC_PUBLIC_KEY_LEN];
    if (wally_ec_public_key_bip341_tweak(derived->pub_key, EC_PUBLIC_KEY_LEN,
                                         NULL, 0, 0, tweaked,
                                         sizeof(tweaked)) == WALLY_OK) {
      cand[0] = 0x51;
      cand[1] = 0x20;
      memcpy(cand + 2, tweaked + 1, 32);
      cand_len = 34;
      if (cand_len == target_spk_len && memcmp(cand, target_spk, cand_len) == 0)
        match = true;
    }
  }

  /* P2PKH: OP_DUP OP_HASH160 <push 20> <hash160(pub)> OP_EQUALVERIFY
   * OP_CHECKSIG */
  if (!match) {
    uint8_t pkh20[HASH160_LEN];
    if (wally_hash160(derived->pub_key, EC_PUBLIC_KEY_LEN, pkh20,
                      HASH160_LEN) == WALLY_OK) {
      cand[0] = 0x76;
      cand[1] = 0xa9;
      cand[2] = 0x14;
      memcpy(cand + 3, pkh20, 20);
      cand[23] = 0x88;
      cand[24] = 0xac;
      cand_len = 25;
      if (cand_len == target_spk_len && memcmp(cand, target_spk, cand_len) == 0)
        match = true;
    }
  }

  /* P2SH-P2WPKH: OP_HASH160 <push 20> <hash160(witness_program)> OP_EQUAL */
  if (!match) {
    uint8_t witprog[22];
    size_t witprog_len = 0;
    if (wally_witness_program_from_bytes(
            derived->pub_key, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160, witprog,
            sizeof(witprog), &witprog_len) == WALLY_OK &&
        witprog_len == 22) {
      uint8_t sh20[HASH160_LEN];
      if (wally_hash160(witprog, witprog_len, sh20, HASH160_LEN) == WALLY_OK) {
        cand[0] = 0xa9;
        cand[1] = 0x14;
        memcpy(cand + 2, sh20, 20);
        cand[22] = 0x87;
        cand_len = 23;
        if (cand_len == target_spk_len &&
            memcmp(cand, target_spk, cand_len) == 0)
          match = true;
      }
    }
  }

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

  bool seen_our_fp = false;

  for (size_t j = 0; j < keypaths_size; j++) {
    unsigned char keypath[MAX_KEYPATH_TOTAL_DEPTH * 4 + 4];
    size_t keypath_len = 0;
    if (wally_psbt_get_input_keypath(psbt, i, j, keypath, sizeof(keypath),
                                     &keypath_len) != WALLY_OK)
      continue;
    if (keypath_len < BIP32_KEY_FINGERPRINT_LEN ||
        memcmp(keypath, our_fp, BIP32_KEY_FINGERPRINT_LEN) != 0)
      continue;

    if (!seen_our_fp) {
      seen_our_fp = true;
      size_t copy = keypath_len <= sizeof(result.raw_keypath)
                        ? keypath_len
                        : sizeof(result.raw_keypath);
      memcpy(result.raw_keypath, keypath, copy);
      result.raw_keypath_len = copy;
    }

    /* A. Try whitelist claim */
    claim_t claim = {0};
    if (try_match_whitelist(keypath, keypath_len, is_testnet, &claim)) {
      expected_scripts_t exp = {0};
      if (claim_regenerate(&claim, is_testnet, &exp) &&
          exp.spk_len == utxo_script_len &&
          memcmp(exp.spk, utxo_script, utxo_script_len) == 0) {
        bool ok = true;
        if (exp.redeem_len > 0) {
          unsigned char buf[256];
          size_t psbt_len = 0, written = 0;
          ok = wally_psbt_get_input_redeem_script_len(psbt, i, &psbt_len) ==
                   WALLY_OK &&
               psbt_len == exp.redeem_len &&
               wally_psbt_get_input_redeem_script(psbt, i, buf, sizeof(buf),
                                                  &written) == WALLY_OK &&
               written == exp.redeem_len &&
               memcmp(buf, exp.redeem, exp.redeem_len) == 0;
        }
        if (ok && exp.witness_len > 0) {
          unsigned char buf[256];
          size_t psbt_len = 0, written = 0;
          ok = wally_psbt_get_input_witness_script_len(psbt, i, &psbt_len) ==
                   WALLY_OK &&
               psbt_len == exp.witness_len &&
               wally_psbt_get_input_witness_script(psbt, i, buf, sizeof(buf),
                                                   &written) == WALLY_OK &&
               written == exp.witness_len &&
               memcmp(buf, exp.witness, exp.witness_len) == 0;
        }
        if (ok) {
          result.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
          result.claim = claim;
          return result;
        }
      }
    }

    /* B. Try registry claims (cursor-paginated) */
    size_t cursor = 0;
    while (true) {
      memset(&claim, 0, sizeof(claim));
      if (!try_match_registry(keypath, keypath_len, &cursor, &claim))
        break;
      expected_scripts_t exp = {0};
      if (!claim_regenerate(&claim, is_testnet, &exp) ||
          exp.spk_len != utxo_script_len ||
          memcmp(exp.spk, utxo_script, utxo_script_len) != 0)
        continue;
      bool ok = true;
      if (exp.redeem_len > 0) {
        unsigned char buf[256];
        size_t psbt_len = 0, written = 0;
        ok = wally_psbt_get_input_redeem_script_len(psbt, i, &psbt_len) ==
                 WALLY_OK &&
             psbt_len == exp.redeem_len &&
             wally_psbt_get_input_redeem_script(psbt, i, buf, sizeof(buf),
                                                &written) == WALLY_OK &&
             written == exp.redeem_len &&
             memcmp(buf, exp.redeem, exp.redeem_len) == 0;
      }
      if (ok && exp.witness_len > 0) {
        unsigned char buf[256];
        size_t psbt_len = 0, written = 0;
        ok = wally_psbt_get_input_witness_script_len(psbt, i, &psbt_len) ==
                 WALLY_OK &&
             psbt_len == exp.witness_len &&
             wally_psbt_get_input_witness_script(psbt, i, buf, sizeof(buf),
                                                 &written) == WALLY_OK &&
             written == exp.witness_len &&
             memcmp(buf, exp.witness, exp.witness_len) == 0;
      }
      if (ok) {
        result.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
        result.claim = claim;
        return result;
      }
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
    if (val_len < BIP32_KEY_FINGERPRINT_LEN ||
        memcmp(val, our_fp, BIP32_KEY_FINGERPRINT_LEN) != 0)
      continue;

    if (!seen_our_fp) {
      seen_our_fp = true;
      size_t copy = val_len <= sizeof(result.raw_keypath)
                        ? val_len
                        : sizeof(result.raw_keypath);
      memcpy(result.raw_keypath, val, copy);
      result.raw_keypath_len = copy;
    }

    claim_t claim = {0};
    if (try_match_whitelist(val, val_len, is_testnet, &claim)) {
      expected_scripts_t exp = {0};
      if (claim_regenerate(&claim, is_testnet, &exp) &&
          exp.spk_len == utxo_script_len &&
          memcmp(exp.spk, utxo_script, utxo_script_len) == 0) {
        /* P2TR has no redeem/witness script, so no extra byte-compare needed.
         */
        result.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
        result.claim = claim;
        return result;
      }
    }

    /* Registry side is unlikely to use taproot keypaths in practice (the
     * registered-descriptor flow builds the standard keypaths map), but
     * paginate anyway for completeness. */
    size_t cursor = 0;
    while (true) {
      memset(&claim, 0, sizeof(claim));
      if (!try_match_registry(val, val_len, &cursor, &claim))
        break;
      expected_scripts_t exp = {0};
      if (claim_regenerate(&claim, is_testnet, &exp) &&
          exp.spk_len == utxo_script_len &&
          memcmp(exp.spk, utxo_script, utxo_script_len) == 0) {
        result.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
        result.claim = claim;
        return result;
      }
    }
  }

  /* fp matched but no whitelist/registry claim verified. Distinguish:
   *   OWNED_UNSAFE   — derive(raw_keypath) reproduces the spk; factually
   *                     ours, just on a non-standard path
   *   EXPECTED_OWNED — derive doesn't (or can't) reproduce the spk;
   *                     harness state. The signing-policy gate in scan.c
   *                     uses the matching settings to decide whether to
   *                     allow signing. */
  if (seen_our_fp) {
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
    if (keypath_len < BIP32_KEY_FINGERPRINT_LEN ||
        memcmp(keypath, our_fp, BIP32_KEY_FINGERPRINT_LEN) != 0)
      continue;

    if (result.raw_keypath_len == 0) {
      size_t copy = keypath_len <= sizeof(result.raw_keypath)
                        ? keypath_len
                        : sizeof(result.raw_keypath);
      memcpy(result.raw_keypath, keypath, copy);
      result.raw_keypath_len = copy;
    }

    claim_t claim = {0};
    if (try_match_whitelist(keypath, keypath_len, is_testnet, &claim)) {
      expected_scripts_t exp = {0};
      if (claim_regenerate(&claim, is_testnet, &exp) &&
          exp.spk_len == out_script_len &&
          memcmp(exp.spk, out_script, out_script_len) == 0) {
        result.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
        result.source = claim;
        wally_tx_free(global_tx);
        return result;
      }
    }

    size_t cursor = 0;
    while (true) {
      memset(&claim, 0, sizeof(claim));
      if (!try_match_registry(keypath, keypath_len, &cursor, &claim))
        break;
      expected_scripts_t exp = {0};
      if (claim_regenerate(&claim, is_testnet, &exp) &&
          exp.spk_len == out_script_len &&
          memcmp(exp.spk, out_script, out_script_len) == 0) {
        result.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
        result.source = claim;
        wally_tx_free(global_tx);
        return result;
      }
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
  if (!script || script_len == 0) {
    return NULL;
  }

  size_t script_type = 0;
  if (wally_scriptpubkey_get_type(script, script_len, &script_type) !=
      WALLY_OK) {
    return NULL;
  }

  char *address = NULL;
  const char *hrp = is_testnet ? "tb" : "bc";
  uint32_t network = is_testnet ? WALLY_NETWORK_BITCOIN_TESTNET
                                : WALLY_NETWORK_BITCOIN_MAINNET;

  if (script_type == WALLY_SCRIPT_TYPE_P2WPKH ||
      script_type == WALLY_SCRIPT_TYPE_P2WSH ||
      script_type == WALLY_SCRIPT_TYPE_P2TR) {
    if (wally_addr_segwit_from_bytes(script, script_len, hrp, 0, &address) !=
        WALLY_OK) {
      return NULL;
    }
  } else if (script_type == WALLY_SCRIPT_TYPE_P2PKH ||
             script_type == WALLY_SCRIPT_TYPE_P2SH) {
    if (wally_scriptpubkey_to_address(script, script_len, network, &address) !=
        WALLY_OK) {
      return NULL;
    }
  } else if (script_type == WALLY_SCRIPT_TYPE_OP_RETURN) {
    address = strdup("OP_RETURN");
  }

  return address;
}

/* Format a BIP32 path from uint32 components (hardened = high bit set) into
 * the "m/44'/0'/0'/0/5" form consumed by key_get_derived_key(). */
static bool format_derived_path(const uint32_t *comps, size_t n, char *buf,
                                size_t buf_size) {
  int w = snprintf(buf, buf_size, "m");
  if (w < 0 || (size_t)w >= buf_size)
    return false;
  size_t pos = (size_t)w;
  for (size_t k = 0; k < n; k++) {
    int written =
        ss_is_hardened(comps[k])
            ? snprintf(buf + pos, buf_size - pos, "/%u'", ss_unharden(comps[k]))
            : snprintf(buf + pos, buf_size - pos, "/%u", comps[k]);
    if (written < 0 || pos + (size_t)written >= buf_size)
      return false;
    pos += (size_t)written;
  }
  return true;
}

bool psbt_format_keypath(const unsigned char *raw_keypath,
                         size_t raw_keypath_len, char *buf, size_t buf_size) {
  if (!raw_keypath || !buf || buf_size == 0)
    return false;
  if (raw_keypath_len < BIP32_KEY_FINGERPRINT_LEN ||
      (raw_keypath_len - BIP32_KEY_FINGERPRINT_LEN) % 4 != 0)
    return false;
  size_t n = (raw_keypath_len - BIP32_KEY_FINGERPRINT_LEN) / 4;
  if (n > MAX_KEYPATH_TOTAL_DEPTH)
    return false;
  uint32_t comps[MAX_KEYPATH_TOTAL_DEPTH];
  for (size_t k = 0; k < n; k++)
    comps[k] = ss_u32_le(raw_keypath + BIP32_KEY_FINGERPRINT_LEN + k * 4);
  return format_derived_path(comps, n, buf, buf_size);
}

size_t psbt_sign(struct wally_psbt *psbt, bool is_testnet) {
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

  for (size_t i = 0; i < num_inputs; i++) {
    input_ownership_t ownership = psbt_classify_input(psbt, i, is_testnet);

    if (ownership.ownership == PSBT_OWNERSHIP_EXTERNAL)
      continue;

    char path[128];
    bool have_path = false;

    if (ownership.ownership == PSBT_OWNERSHIP_OWNED_SAFE) {
      /* Both CLAIM_WHITELIST and CLAIM_REGISTRY populate derived_path with
       * the raw BIP32 uint32 components; format directly into a path string. */
      have_path = format_derived_path(ownership.claim.derived_path,
                                      ownership.claim.derived_path_len, path,
                                      sizeof(path));
    } else {
      /* OWNED_UNSAFE / EXPECTED_OWNED — the scan.c policy gate has already
       * cleared the relevant setting; here we just derive from the raw path. */
      if (ownership.raw_keypath_len < BIP32_KEY_FINGERPRINT_LEN ||
          (ownership.raw_keypath_len - BIP32_KEY_FINGERPRINT_LEN) % 4 != 0)
        continue;
      size_t n_comps =
          (ownership.raw_keypath_len - BIP32_KEY_FINGERPRINT_LEN) / 4;
      if (n_comps > MAX_KEYPATH_TOTAL_DEPTH)
        continue;
      uint32_t raw_comps[MAX_KEYPATH_TOTAL_DEPTH];
      for (size_t k = 0; k < n_comps; k++)
        raw_comps[k] = ss_u32_le(ownership.raw_keypath +
                                 BIP32_KEY_FINGERPRINT_LEN + k * 4);
      have_path = format_derived_path(raw_comps, n_comps, path, sizeof(path));
    }

    if (!have_path) {
      ESP_LOGE(TAG, "Failed to format signing path for input %zu", i);
      continue;
    }

    struct ext_key *derived_key = NULL;
    if (!key_get_derived_key(path, &derived_key)) {
      ESP_LOGE(TAG, "Failed to derive key for path: %s", path);
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
  }

  return trimmed;
}
