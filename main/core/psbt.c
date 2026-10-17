#include "psbt.h"
#include "bip32_path.h"
#include "key.h"
#include "psbt_internal.h"
#include "script_templates.h"
#include "wallet.h"
#include <esp_log.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
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

/* Locate the output a non_witness_utxo claims to fund, after checking that the
 * transaction really is the one this input spends. libwally applies the same
 * txid check when it signs any ECDSA or taproot key-path input that carries a
 * non_witness_utxo, though not for a taproot script path, and never on the
 * path that reports amounts, so the fee could be read off a fabricated
 * previous transaction that signing would later reject. */
static const struct wally_tx_output *
verified_prevout(const struct wally_psbt *psbt, size_t index,
                 const struct wally_tx *prev) {
  unsigned char declared[WALLY_TXHASH_LEN];
  unsigned char actual[WALLY_TXHASH_LEN];
  uint32_t vout = 0;

  if (wally_psbt_get_input_previous_txid(psbt, index, declared,
                                         sizeof(declared)) != WALLY_OK ||
      wally_tx_get_txid(prev, actual, sizeof(actual)) != WALLY_OK ||
      memcmp(declared, actual, sizeof(actual)) != 0)
    return NULL;

  if (wally_psbt_get_input_output_index(psbt, index, &vout) != WALLY_OK ||
      vout >= prev->num_outputs)
    return NULL;

  return &prev->outputs[vout];
}

static bool prevout_matches_witness(const struct wally_tx_output *prevout,
                                    const struct wally_tx_output *witness) {
  return prevout->satoshi == witness->satoshi &&
         prevout->script_len == witness->script_len &&
         (prevout->script_len == 0 ||
          memcmp(prevout->script, witness->script, prevout->script_len) == 0);
}

psbt_input_amount_t psbt_get_input_amount(const struct wally_psbt *psbt,
                                          size_t index) {
  psbt_input_amount_t result = {.status = PSBT_AMOUNT_MISSING, .value = 0};

  struct wally_tx_output *witness = NULL;
  if (wally_psbt_get_input_witness_utxo_alloc(psbt, index, &witness) !=
      WALLY_OK)
    witness = NULL;

  struct wally_tx *prev = NULL;
  if (wally_psbt_get_input_utxo_alloc(psbt, index, &prev) != WALLY_OK)
    prev = NULL;

  if (prev) {
    const struct wally_tx_output *prevout = verified_prevout(psbt, index, prev);
    if (!prevout) {
      /* A previous transaction was supplied but it is not the one being
       * spent. Nothing here is trustworthy; fall back to the witness value
       * only so the review screen still shows the number signing would use. */
      result.status = PSBT_AMOUNT_INVALID;
      result.value = witness ? witness->satoshi : 0;
    } else if (witness && !prevout_matches_witness(prevout, witness)) {
      result.status = PSBT_AMOUNT_INVALID;
      result.value = prevout->satoshi; /* the proven side wins for display */
    } else {
      result.status = PSBT_AMOUNT_PROVEN;
      result.value = prevout->satoshi;
    }
  } else if (witness) {
    result.status = PSBT_AMOUNT_ASSERTED;
    result.value = witness->satoshi;
  }

  if (witness)
    wally_tx_output_free(witness);
  if (prev)
    wally_tx_free(prev);

  return result;
}

void psbt_audit_input_amounts(const struct wally_psbt *psbt,
                              psbt_amount_audit_t *out) {
  if (!out)
    return;

  memset(out, 0, sizeof(*out));
  if (!psbt || wally_psbt_get_num_inputs(psbt, &out->num_inputs) != WALLY_OK)
    out->num_inputs = 0;

  out->first_unproven = out->num_inputs;
  out->first_invalid = out->num_inputs;
  out->first_missing = out->num_inputs;

  for (size_t i = 0; i < out->num_inputs; i++) {
    psbt_input_amount_t amount = psbt_get_input_amount(psbt, i);
    out->total += amount.value;
    switch (amount.status) {
    case PSBT_AMOUNT_PROVEN:
      out->proven++;
      continue;
    case PSBT_AMOUNT_ASSERTED:
      out->asserted++;
      break;
    case PSBT_AMOUNT_INVALID:
      out->invalid++;
      if (out->first_invalid == out->num_inputs)
        out->first_invalid = i;
      break;
    case PSBT_AMOUNT_MISSING:
      out->missing++;
      if (out->first_missing == out->num_inputs)
        out->first_missing = i;
      break;
    }
    if (out->first_unproven == out->num_inputs)
      out->first_unproven = i;
  }
}

bool psbt_input_is_taproot(const struct wally_psbt *psbt, size_t i) {
  uint32_t type = 0;
  return psbt &&
         wally_psbt_get_input_signature_type(psbt, i, &type) == WALLY_OK &&
         type == WALLY_SIGTYPE_SW_V1;
}

bool psbt_fee_is_trusted_for_signing(const struct wally_psbt *psbt,
                                     const psbt_amount_audit_t *audit,
                                     const bool *signing) {
  if (psbt_fee_is_trusted(audit))
    return true;
  if (!psbt || !signing || audit->num_inputs == 0 || audit->invalid ||
      audit->missing)
    return false;
  bool any = false;
  for (size_t i = 0; i < audit->num_inputs; i++) {
    if (!signing[i])
      continue;
    size_t sighash = 0;
    if (wally_psbt_get_input_sighash(psbt, i, &sighash) != WALLY_OK)
      sighash = 0;
    if (!psbt_input_is_taproot(psbt, i) ||
        !psbt_sighash_is_supported((uint32_t)sighash))
      return false;
    any = true;
  }
  return any;
}

uint64_t psbt_get_input_value(const struct wally_psbt *psbt, size_t index) {
  return psbt_get_input_amount(psbt, index).value;
}

/* 21 million BTC. libwally already rejects a transaction whose outputs exceed
 * the supply, so this only backstops a total assembled some other way -- but
 * it is what keeps the sum below from silently wrapping. */
#define PSBT_MAX_SATOSHI (21000000ull * WALLY_SATOSHI_PER_BTC)

bool psbt_total_output_value(const struct wally_psbt *psbt, uint64_t *out) {
  if (!psbt || !out)
    return false;
  *out = 0;

  struct wally_tx *tx = psbt_tx_alloc(psbt);
  if (!tx)
    return false;

  uint64_t total = 0;
  bool ok = true;
  for (size_t i = 0; i < tx->num_outputs && ok; i++) {
    uint64_t value = tx->outputs[i].satoshi;
    if (value > PSBT_MAX_SATOSHI || total > PSBT_MAX_SATOSHI - value)
      ok = false;
    else
      total += value;
  }
  wally_tx_free(tx);

  if (ok)
    *out = total;
  return ok;
}

struct wally_tx *psbt_tx_alloc(const struct wally_psbt *psbt) {
  struct wally_tx *tx = NULL;
  if (!psbt ||
      wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx) != WALLY_OK)
    return NULL;
  return tx;
}

/* True when this PSBT keeps BIP-370's tx-modifiable flags. v0 has no such
 * field: it is implicitly modifiable until finalized. */
static bool psbt_is_v2(const struct wally_psbt *psbt) {
  size_t version = 0;
  return psbt && wally_psbt_get_version(psbt, &version) == WALLY_OK &&
         version == WALLY_PSBT_VERSION_2;
}

/* Bitcoin Core's IsWitnessProgram: OP_0 or OP_1..OP_16, then a single push of
 * 2..40 bytes making up the whole script. */
static bool spk_is_witness_program(const unsigned char *spk, size_t spk_len) {
  if (spk_len < 4 || spk_len > 42)
    return false;
  if (spk[0] != OP_0 && (spk[0] < OP_1 || spk[0] > OP_16))
    return false;
  return (size_t)spk[1] + 2 == spk_len;
}

uint64_t psbt_output_dust_threshold(const unsigned char *spk, size_t spk_len) {
  if (!spk || !spk_len || spk[0] == OP_RETURN)
    return 0; /* provably unspendable: never dust */

  /* Core's GetDustThreshold: the serialized output plus the cheapest input
   * that could spend it, priced at the 3000 sat/kvB dust relay fee. The input
   * side is 67 bytes for a witness program (the witness is discounted) and
   * 148 for everything else. Yields the familiar 294 / 330 / 546 thresholds. */
  size_t size = 8 + 1 + spk_len; /* value + script length + script */
  size += spk_is_witness_program(spk, spk_len) ? 67 : 148;
  return (uint64_t)size * 3000u / 1000u;
}

bool psbt_sighash_is_supported(uint32_t sighash) {
  /* 0 is both the "no PSBT_IN_SIGHASH_TYPE field" encoding and taproot's
   * SIGHASH_DEFAULT; either way libwally signs with ALL semantics. */
  return sighash == 0 || sighash == WALLY_SIGHASH_ALL;
}

const char *psbt_sighash_name(uint32_t sighash) {
  switch (sighash) {
  case 0:
    return "DEFAULT";
  case WALLY_SIGHASH_ALL:
    return "ALL";
  case WALLY_SIGHASH_NONE:
    return "NONE";
  case WALLY_SIGHASH_SINGLE:
    return "SINGLE";
  case WALLY_SIGHASH_ALL | WALLY_SIGHASH_ANYONECANPAY:
    return "ALL|ANYONECANPAY";
  case WALLY_SIGHASH_NONE | WALLY_SIGHASH_ANYONECANPAY:
    return "NONE|ANYONECANPAY";
  case WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY:
    return "SINGLE|ANYONECANPAY";
  default:
    return "unknown";
  }
}

void psbt_audit_sighash(const struct wally_psbt *psbt,
                        psbt_sighash_audit_t *out) {
  if (!out)
    return;

  memset(out, 0, sizeof(*out));
  if (!psbt || wally_psbt_get_num_inputs(psbt, &out->num_inputs) != WALLY_OK)
    out->num_inputs = 0;

  out->first_unsupported = out->num_inputs;

  for (size_t i = 0; i < out->num_inputs; i++) {
    size_t sighash = 0;
    if (wally_psbt_get_input_sighash(psbt, i, &sighash) != WALLY_OK)
      sighash = 0;
    if (psbt_sighash_is_supported((uint32_t)sighash))
      continue;

    if (!out->unsupported) {
      out->first_unsupported = i;
      out->first_sighash = (uint32_t)sighash;
    }
    out->unsupported++;
  }
}

uint32_t psbt_fee_percent(uint64_t fee, uint64_t total_input) {
  if (!total_input)
    return 0;
  return (uint32_t)((fee * 100u) / total_input);
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
                                uint32_t max_index, claim_t *claim_out) {
  if (keypath_len != 4 + 5 * 4)
    return false;

  ss_keypath_t kp;
  if (!ss_keypath_parse(keypath + 4, keypath_len - 4, &kp))
    return false;

  if (!ss_keypath_is_whitelisted(&kp, is_testnet, max_index))
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
                               registry_match_cursor_t *cursor,
                               claim_t *claim_out) {
  uint32_t multi_index = 0, child_num = 0;
  const registry_entry_t *entry = registry_match_keypath(
      keypath, keypath_len, cursor, &multi_index, &child_num);
  if (!entry)
    return false;

  claim_out->kind = CLAIM_REGISTRY;
  claim_out->registry.entry = entry;
  claim_out->registry.multi_index = multi_index;
  claim_out->registry.child_num = child_num;

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
                            bool is_testnet, uint32_t max_index,
                            const unsigned char *target_spk,
                            size_t target_spk_len,
                            const struct wally_psbt *input_psbt, size_t input_i,
                            claim_t *claim_out) {
  claim_t claim = {0};
  if (try_match_whitelist(keypath, keypath_len, is_testnet, max_index,
                          &claim) &&
      claim_matches_spk(&claim, is_testnet, target_spk, target_spk_len,
                        input_psbt, input_i)) {
    *claim_out = claim;
    return true;
  }

  registry_match_cursor_t cursor = {0};
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
  if (*dst_len != 0 || src_len > dst_cap)
    return;
  memcpy(dst, src, src_len);
  *dst_len = src_len;
}

/* A keypath map value (fingerprint, then path) that names our seed and is
 * short enough to be a path Kern derives. A longer one cannot be ours. */
static bool keypath_is_candidate(const struct wally_map_item *item,
                                 const unsigned char *our_fp) {
  return item->value_len <= MAX_KEYPATH_TOTAL_DEPTH * 4 + 4 &&
         keypath_matches_fingerprint(item->value, item->value_len, our_fp);
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

  /* PSBT_IN_BIP32_DERIVATION, then PSBT_IN_TAP_BIP32_DERIVATION: both map a
   * public key to fp(4) | path(4*depth). Only the first carries scripts to
   * check against the claim. */
  const struct wally_map *maps[] = {&psbt->inputs[i].keypaths,
                                    &psbt->inputs[i].taproot_leaf_paths};
  for (size_t m = 0; m < sizeof(maps) / sizeof(maps[0]); m++) {
    for (size_t j = 0; j < maps[m]->num_items; j++) {
      const struct wally_map_item *item = &maps[m]->items[j];
      if (!keypath_is_candidate(item, our_fp))
        continue;

      claim_t claim = {0};
      remember_raw_keypath(result.raw_keypath, sizeof(result.raw_keypath),
                           &result.raw_keypath_len, item->value,
                           item->value_len);
      if (try_match_claim(item->value, item->value_len, is_testnet,
                          SS_ADDR_INDEX_UNCAPPED, utxo_script, utxo_script_len,
                          m == 0 ? psbt : NULL, i, &claim)) {
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

/* The whitelist caps output indexes inside ss_keypath_is_whitelisted. A
 * registry claim has no such check: past the cap the output is still provably
 * ours, but no wallet scanning with a gap limit would find it, so it needs the
 * same Permissive opt-in as single-sig change past the cap. */
static void set_output_claim(output_ownership_t *result, const claim_t *claim,
                             const unsigned char *keypath, size_t keypath_len) {
  result->source = *claim;
  if (claim->kind == CLAIM_REGISTRY &&
      claim->registry.child_num >= SS_MAX_OUT_ADDR_INDEX) {
    result->ownership = PSBT_OWNERSHIP_OWNED_UNSAFE;
    result->raw_keypath_len = 0;
    remember_raw_keypath(result->raw_keypath, sizeof(result->raw_keypath),
                         &result->raw_keypath_len, keypath, keypath_len);
    return;
  }
  result->ownership = PSBT_OWNERSHIP_OWNED_SAFE;
}

output_ownership_t psbt_classify_output(const struct wally_psbt *psbt, size_t i,
                                        bool is_testnet) {
  output_ownership_t result = {0};

  struct wally_tx *global_tx = psbt_tx_alloc(psbt);
  if (!global_tx)
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

  /* PSBT_OUT_BIP32_DERIVATION, then PSBT_OUT_TAP_BIP32_DERIVATION: without
   * the second, taproot change and self-transfers read as external spends. */
  const struct wally_map *maps[] = {&psbt->outputs[i].keypaths,
                                    &psbt->outputs[i].taproot_leaf_paths};
  for (size_t m = 0; m < sizeof(maps) / sizeof(maps[0]); m++) {
    for (size_t j = 0; j < maps[m]->num_items; j++) {
      const struct wally_map_item *item = &maps[m]->items[j];
      if (!keypath_is_candidate(item, our_fp))
        continue;

      claim_t claim = {0};
      remember_raw_keypath(result.raw_keypath, sizeof(result.raw_keypath),
                           &result.raw_keypath_len, item->value,
                           item->value_len);
      if (try_match_claim(item->value, item->value_len, is_testnet,
                          SS_MAX_OUT_ADDR_INDEX, out_script, out_script_len,
                          NULL, 0, &claim)) {
        set_output_claim(&result, &claim, item->value, item->value_len);
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

bool psbt_claims_share_policy(const claim_t *a, const claim_t *b) {
  if (!a || !b || a->kind != b->kind)
    return false;
  if (a->kind == CLAIM_REGISTRY)
    return a->registry.entry && a->registry.entry == b->registry.entry;
  return a->whitelist.purpose == b->whitelist.purpose &&
         a->whitelist.coin == b->whitelist.coin &&
         a->whitelist.account == b->whitelist.account;
}

// Only a hardened purpose'/coin' prefix names a coin type: a taproot internal
// key derived from an unspendable xpub sits at a bare /0/0, which would read
// as coin 0.
static bool check_keypath_network(const unsigned char *keypath,
                                  size_t keypath_len, bool *is_testnet) {
  if (keypath_len < 12) {
    return false;
  }

  uint32_t purpose = bip32_path_u32_le(keypath + 4);
  uint32_t coin_type = bip32_path_u32_le(keypath + 8);
  if (!bip32_path_is_hardened(purpose) || !bip32_path_is_hardened(coin_type)) {
    return false;
  }

  uint32_t coin_value = bip32_path_unharden(coin_type);
  if (coin_value == 0 || coin_value == 1) {
    *is_testnet = (coin_value == 1);
    return true;
  }

  return false;
}

// Keypaths and taproot_leaf_paths values share the fp(4) | path(4*depth) shape.
static bool map_detect_network(const struct wally_map *keypaths,
                               bool *is_testnet) {
  for (size_t i = 0; i < keypaths->num_items; i++) {
    if (check_keypath_network(keypaths->items[i].value,
                              keypaths->items[i].value_len, is_testnet)) {
      return true;
    }
  }
  return false;
}

bool psbt_detect_network(const struct wally_psbt *psbt) {
  if (!psbt) {
    return false;
  }

  bool is_testnet;

  // Check outputs first
  for (size_t i = 0; i < psbt->num_outputs; i++) {
    if (map_detect_network(&psbt->outputs[i].keypaths, &is_testnet) ||
        map_detect_network(&psbt->outputs[i].taproot_leaf_paths, &is_testnet)) {
      return is_testnet;
    }
  }

  // Check inputs as fallback
  for (size_t i = 0; i < psbt->num_inputs; i++) {
    if (map_detect_network(&psbt->inputs[i].keypaths, &is_testnet) ||
        map_detect_network(&psbt->inputs[i].taproot_leaf_paths, &is_testnet)) {
      return is_testnet;
    }
  }

  return false; // Default to mainnet
}

char *psbt_scriptpubkey_to_address(const unsigned char *script,
                                   size_t script_len, bool is_testnet) {
  return script_template_address_from_spk(script, script_len, is_testnet);
}

char *psbt_output_destination(const unsigned char *spk, size_t spk_len,
                              bool is_testnet, psbt_destination_kind_t *kind) {
  *kind = PSBT_DEST_ADDRESS;
  char *dest = script_template_address_from_spk(spk, spk_len, is_testnet);
  if (dest || !spk || !spk_len)
    return dest;

  *kind = PSBT_DEST_UNKNOWN_WITNESS;
  if (spk_is_witness_program(spk, spk_len) &&
      wally_addr_segwit_from_bytes(spk, spk_len, is_testnet ? "tb" : "bc", 0,
                                   &dest) == WALLY_OK)
    return dest;

  *kind = PSBT_DEST_SCRIPT;
  if (wally_hex_from_bytes(spk, spk_len, &dest) != WALLY_OK)
    return NULL;
  return dest;
}

bool psbt_format_keypath(const unsigned char *raw_keypath,
                         size_t raw_keypath_len, char *buf, size_t buf_size) {
  return bip32_path_format_keypath(raw_keypath, raw_keypath_len, buf, buf_size,
                                   MAX_KEYPATH_TOTAL_DEPTH);
}

/* Every place libwally can park a signature for one input: the ECDSA map, the
 * taproot key-path field, and the taproot script-path leaf map. Counted before
 * and after each signing call so `signed_ok` reflects signatures that actually
 * landed, not calls that merely returned WALLY_OK. */
static bool tap_key_sig_present(const struct wally_psbt *psbt, size_t i) {
  size_t n = 0;
  return wally_psbt_get_input_taproot_signature_len(psbt, i, &n) == WALLY_OK &&
         n;
}

static size_t input_signature_count(const struct wally_psbt *psbt, size_t i) {
  size_t count = 0;
  size_t n = 0;

  if (wally_psbt_get_input_signatures_size(psbt, i, &n) == WALLY_OK)
    count += n;
  if (tap_key_sig_present(psbt, i))
    count++;
  count += psbt->inputs[i].taproot_leaf_signatures.num_items;

  return count;
}

/* How one input classified, whether the policy refused it, and -- for a
 * refused input -- the signature state to hand back exactly as it arrived.
 *
 * wally_psbt_sign() walks every input in the PSBT and signs any whose keypath
 * map names the public key it was handed, so classifying an input per-loop
 * does not by itself decide what gets signed. An input we refused -- including
 * one classified EXTERNAL because its fingerprint is wrong -- still picks up a
 * signature if it lists a key used elsewhere in the same transaction. Signing
 * a whole PSBT cannot enforce a per-input gate, so snapshot before and restore
 * after. */
typedef struct {
  input_ownership_t owner;
  bool denied;    /* policy refused this input */
  bool tracked;   /* a snapshot was taken (denied and it names some key) */
  bool attempted; /* policy cleared it and a signing key was derived */
  /* Signature count before the pass began. One wally_psbt_sign() call signs
   * every input naming the key it was given, so an input can already be
   * signed by the time its own turn comes round -- two inputs on one address
   * are the common case. Only a baseline taken before any signing can tell
   * "already signed by us" from "never signed". */
  size_t sig_baseline;
  bool had_tap_key_sig;
  size_t sig_count;
  struct wally_map signatures;
  struct wally_map leaf_signatures;
  struct wally_map fields;
  /* Every key this input was signed with, for the completeness check. */
  unsigned char signing_pubkeys[REGISTRY_MAX_OWN_KEYS][EC_PUBLIC_KEY_LEN];
  size_t num_signing_pubkeys;
} input_plan_t;

/* Safe on an untouched plan, and safe twice, so every exit can run it over
 * the whole array without tracking how far the classify loop got. */
static void release_input_state(input_plan_t *plan) {
  wally_map_clear(&plan->signatures);
  wally_map_clear(&plan->leaf_signatures);
  wally_map_clear(&plan->fields);
  plan->tracked = false;
}

static bool capture_input_state(const struct wally_psbt *psbt, size_t i,
                                input_plan_t *plan) {
  const struct wally_psbt_input *inp = &psbt->inputs[i];

  /* With no derivation info there is no public key for libwally to match on,
   * so the input cannot pick up a signature and needs no snapshot. */
  if (!inp->keypaths.num_items && !inp->taproot_leaf_paths.num_items)
    return true;

  if (wally_map_assign(&plan->signatures, &inp->signatures) != WALLY_OK ||
      wally_map_assign(&plan->leaf_signatures, &inp->taproot_leaf_signatures) !=
          WALLY_OK ||
      wally_map_assign(&plan->fields, &inp->psbt_fields) != WALLY_OK) {
    release_input_state(plan);
    return false;
  }

  plan->sig_count = input_signature_count(psbt, i);
  plan->tracked = true;
  return true;
}

static void restore_input_state(struct wally_psbt *psbt, size_t i,
                                input_plan_t *plan,
                                psbt_sign_result_t *result) {
  if (!plan->tracked)
    return;

  if (input_signature_count(psbt, i) != plan->sig_count) {
    ESP_LOGW(TAG, "Discarding signature added to policy-denied input %zu", i);
    if (result)
      result->blocked++;
  }

  wally_map_assign(&psbt->inputs[i].signatures, &plan->signatures);
  wally_map_assign(&psbt->inputs[i].taproot_leaf_signatures,
                   &plan->leaf_signatures);
  wally_map_assign(&psbt->inputs[i].psbt_fields, &plan->fields);
  release_input_state(plan);
}

typedef struct {
  uint32_t path[MAX_KEYPATH_TOTAL_DEPTH];
  size_t len;
} signing_path_t;

static bool add_signing_path(signing_path_t *paths, size_t *count,
                             const uint32_t *path, size_t len) {
  if (*count >= REGISTRY_MAX_OWN_KEYS || len > MAX_KEYPATH_TOTAL_DEPTH)
    return false;
  for (size_t i = 0; i < *count; i++)
    if (paths[i].len == len &&
        memcmp(paths[i].path, path, len * sizeof(uint32_t)) == 0)
      return false;
  memcpy(paths[*count].path, path, len * sizeof(uint32_t));
  paths[*count].len = len;
  (*count)++;
  return true;
}

/* The keys to sign an input with. A registry claim proves every own key of
 * its descriptor at the claim's (multi_index, child_num), not only the one
 * whose keypath matched: when one seed holds keys in two multipath groups
 * (a primary <0;1> and a recovery <2;3> path), both are in the script. Keys
 * the PSBT merely lists are never signed with. */
static size_t input_signing_paths(const input_ownership_t *own,
                                  signing_path_t *paths) {
  size_t count = 0;
  if (own->ownership != PSBT_OWNERSHIP_OWNED_SAFE) {
    /* OWNED_UNSAFE / EXPECTED_OWNED: the policy already vetted the raw path
     * supplied in the PSBT. */
    uint32_t raw[MAX_KEYPATH_TOTAL_DEPTH];
    size_t len = 0;
    if (bip32_path_from_keypath(own->raw_keypath, own->raw_keypath_len, raw,
                                &len, MAX_KEYPATH_TOTAL_DEPTH))
      add_signing_path(paths, &count, raw, len);
    return count;
  }

  add_signing_path(paths, &count, own->claim.derived_path,
                   own->claim.derived_path_len);
  if (own->claim.kind != CLAIM_REGISTRY || !own->claim.registry.entry)
    return count;
  const registry_entry_t *e = own->claim.registry.entry;
  for (size_t k = 0; k < e->num_own_keys; k++) {
    uint32_t path[MAX_KEYPATH_TOTAL_DEPTH];
    size_t len = 0;
    if (registry_own_key_path(&e->own_keys[k], own->claim.registry.multi_index,
                              own->claim.registry.child_num, path, &len))
      add_signing_path(paths, &count, path, len);
  }
  return count;
}

static bool map_has_key(const struct wally_map *map, const unsigned char *key,
                        size_t key_len) {
  size_t idx = 0;
  return wally_map_find(map, key, key_len, &idx) == WALLY_OK && idx != 0;
}

static bool leaf_signed_by(const struct wally_psbt_input *inp,
                           const unsigned char *xonly) {
  const struct wally_map *sigs = &inp->taproot_leaf_signatures;
  for (size_t i = 0; i < sigs->num_items; i++)
    if (sigs->items[i].key_len > EC_XONLY_PUBLIC_KEY_LEN &&
        memcmp(sigs->items[i].key, xonly, EC_XONLY_PUBLIC_KEY_LEN) == 0)
      return true;
  return false;
}

/* Whether every key this input was signed with that the PSBT also lists for
 * it now has a signature there. A listed key left unsigned means part of the
 * policy, a second multipath group say, could not be signed. */
static bool input_signed_by_listed_keys(const struct wally_psbt *psbt, size_t i,
                                        const input_plan_t *plan) {
  const struct wally_psbt_input *inp = &psbt->inputs[i];
  unsigned char internal[EC_XONLY_PUBLIC_KEY_LEN];
  size_t internal_len = 0;
  bool has_internal =
      wally_psbt_get_input_taproot_internal_key(
          psbt, i, internal, sizeof(internal), &internal_len) == WALLY_OK &&
      internal_len == sizeof(internal);
  for (size_t k = 0; k < plan->num_signing_pubkeys; k++) {
    const unsigned char *pub = plan->signing_pubkeys[k];
    const unsigned char *xonly = pub + 1;
    if (map_has_key(&inp->keypaths, pub, EC_PUBLIC_KEY_LEN) &&
        !map_has_key(&inp->signatures, pub, EC_PUBLIC_KEY_LEN))
      return false;
    if (map_has_key(&inp->taproot_leaf_paths, xonly, EC_XONLY_PUBLIC_KEY_LEN) &&
        !leaf_signed_by(inp, xonly) &&
        !(has_internal && memcmp(internal, xonly, sizeof(internal)) == 0 &&
          tap_key_sig_present(psbt, i)))
      return false;
  }
  return true;
}

/* True when `policy` clears this input for signing. */
static bool input_is_signable(const struct wally_psbt *psbt, size_t i,
                              psbt_ownership_t ownership,
                              psbt_sign_policy_t policy) {
  if (ownership == PSBT_OWNERSHIP_EXTERNAL)
    return false;

  /* libwally honours whatever sighash byte the PSBT declares. Under anything
   * but ALL/DEFAULT the signature outlives the transaction that was reviewed,
   * so refuse here as well as in the UI gate. */
  size_t sighash = 0;
  if (wally_psbt_get_input_sighash(psbt, i, &sighash) != WALLY_OK)
    sighash = 0;
  if (!psbt_sighash_is_supported((uint32_t)sighash)) {
    ESP_LOGW(TAG, "Skipping input %zu: unsupported sighash 0x%02x", i,
             (unsigned)sighash);
    return false;
  }

  if (ownership == PSBT_OWNERSHIP_OWNED_UNSAFE && !policy.allow_unsafe) {
    ESP_LOGW(TAG, "Skipping input %zu: OWNED_UNSAFE without permissive policy",
             i);
    return false;
  }
  if (ownership == PSBT_OWNERSHIP_EXPECTED_OWNED &&
      !policy.allow_expected_owned) {
    ESP_LOGW(TAG,
             "Skipping input %zu: EXPECTED_OWNED without expected-owned policy",
             i);
    return false;
  }
  return true;
}

/* libwally decides whether and how to key-path sign a taproot input from the
 * PSBT's TAP_INTERNAL_KEY, leaf hashes and TAP_MERKLE_ROOT, and never checks
 * the tweaked key against the output key the input spends. A stray or missing
 * merkle root yields a signature for some other key, which finalizers still
 * prefer over a valid script-path one. Verify each new key-path signature
 * against the output key and drop those that fail. */
static bool key_path_sig_verifies(struct wally_psbt *psbt, size_t i,
                                  const struct wally_tx *tx) {
  unsigned char spk[34], sig[EC_SIGNATURE_LEN + 1], hash[SHA256_LEN];
  size_t spk_len = 0, sig_len = 0;
  return psbt_input_utxo_script(psbt, i, spk, sizeof(spk), &spk_len) &&
         spk_len == sizeof(spk) && spk[0] == OP_1 && spk[1] == 32 &&
         wally_psbt_get_input_taproot_signature(psbt, i, sig, sizeof(sig),
                                                &sig_len) == WALLY_OK &&
         sig_len >= EC_SIGNATURE_LEN && sig_len <= sizeof(sig) &&
         wally_psbt_get_input_signature_hash(psbt, i, tx, NULL, 0, 0, hash,
                                             sizeof(hash)) == WALLY_OK &&
         wally_ec_sig_verify(spk + 2, EC_XONLY_PUBLIC_KEY_LEN, hash,
                             sizeof(hash), EC_FLAG_SCHNORR, sig,
                             EC_SIGNATURE_LEN) == WALLY_OK;
}

static void drop_unverified_key_path_sigs(struct wally_psbt *psbt,
                                          const input_plan_t *plan,
                                          size_t num_inputs,
                                          psbt_sign_result_t *result) {
  struct wally_tx *tx = NULL;
  for (size_t i = 0; i < num_inputs; i++) {
    if (plan[i].denied || plan[i].had_tap_key_sig ||
        !tap_key_sig_present(psbt, i))
      continue;
    if (!tx && !(tx = psbt_tx_alloc(psbt)))
      break;
    if (key_path_sig_verifies(psbt, i, tx))
      continue;
    ESP_LOGW(TAG,
             "Dropping key-path signature that fails to verify on input %zu",
             i);
    wally_psbt_set_input_taproot_signature(psbt, i, NULL, 0);
    if (result)
      result->bad_keypath++;
  }
  if (tx) {
    wally_tx_free(tx);
    return;
  }
  /* Without the transaction no signature can be checked: drop them all. */
  for (size_t i = 0; i < num_inputs; i++) {
    if (plan[i].denied || plan[i].had_tap_key_sig ||
        !tap_key_sig_present(psbt, i))
      continue;
    wally_psbt_set_input_taproot_signature(psbt, i, NULL, 0);
    if (result)
      result->bad_keypath++;
  }
}

size_t psbt_sign(struct wally_psbt *psbt, bool is_testnet,
                 psbt_sign_policy_t policy, psbt_sign_result_t *result) {
  if (result)
    memset(result, 0, sizeof(*result));

  if (!psbt) {
    ESP_LOGE(TAG, "Invalid PSBT");
    return 0;
  }

  size_t num_inputs = 0;
  if (wally_psbt_get_num_inputs(psbt, &num_inputs) != WALLY_OK || !num_inputs) {
    ESP_LOGE(TAG, "Failed to get number of inputs");
    return 0;
  }

  input_plan_t *plan = calloc(num_inputs, sizeof(*plan));
  if (!plan) {
    ESP_LOGE(TAG, "Out of memory classifying %zu inputs", num_inputs);
    return 0;
  }

  size_t signatures_added = 0;

  /* Classify everything up front, then freeze the inputs we will not sign.
   * Bailing on a snapshot failure rather than signing unprotected. */
  bool signable_any = false;
  for (size_t i = 0; i < num_inputs; i++) {
    plan[i].owner = psbt_classify_input(psbt, i, is_testnet);
    if (input_is_signable(psbt, i, plan[i].owner.ownership, policy)) {
      signable_any = true;
      plan[i].sig_baseline = input_signature_count(psbt, i);
      plan[i].had_tap_key_sig = tap_key_sig_present(psbt, i);
      continue;
    }
    plan[i].denied = true;
    if (!capture_input_state(psbt, i, &plan[i])) {
      ESP_LOGE(TAG, "Failed to snapshot denied input %zu; refusing to sign", i);
      goto cleanup;
    }
  }

  if (!signable_any)
    goto cleanup;

  /* Cache shared sighash midstates so per-input signing is O(n), not O(n^2). */
  wally_psbt_signing_cache_enable(psbt, 0);

  for (size_t i = 0; i < num_inputs; i++) {
    input_ownership_t ownership = plan[i].owner;

    if (plan[i].denied)
      continue;

    signing_path_t paths[REGISTRY_MAX_OWN_KEYS];
    size_t num_paths = input_signing_paths(&ownership, paths);
    if (!num_paths)
      ESP_LOGE(TAG, "Invalid signing path for input %zu", i);

    struct ext_key *keys[REGISTRY_MAX_OWN_KEYS] = {0};
    for (size_t p = 0; p < num_paths; p++) {
      if (!key_get_derived_key_components(paths[p].path, paths[p].len,
                                          &keys[p])) {
        ESP_LOGE(TAG, "Failed to derive key %zu for input %zu", p, i);
        continue;
      }
      plan[i].attempted = true;
      memcpy(plan[i].signing_pubkeys[plan[i].num_signing_pubkeys++],
             keys[p]->pub_key, EC_PUBLIC_KEY_LEN);
    }

    /* libwally stops looking at an input's taproot keys once it holds a
     * key-path signature, so every leaf key signs before the internal key. */
    unsigned char internal[EC_XONLY_PUBLIC_KEY_LEN];
    size_t internal_len = 0;
    bool has_internal =
        wally_psbt_get_input_taproot_internal_key(
            psbt, i, internal, sizeof(internal), &internal_len) == WALLY_OK &&
        internal_len == sizeof(internal);
    for (int last = 0; last <= 1; last++) {
      for (size_t p = 0; p < num_paths; p++) {
        if (!keys[p])
          continue;
        bool is_internal =
            has_internal &&
            memcmp(keys[p]->pub_key + 1, internal, sizeof(internal)) == 0;
        if (is_internal != (last == 1))
          continue;
        int ret = wally_psbt_sign(psbt, keys[p]->priv_key + 1,
                                  EC_PRIVATE_KEY_LEN, EC_FLAG_GRIND_R);
        if (ret == WALLY_OK)
          signatures_added++;
        else
          ESP_LOGE(TAG, "Failed to sign input %zu: %d", i, ret);
      }
    }
    for (size_t p = 0; p < num_paths; p++)
      bip32_key_free(keys[p]);
  }

  drop_unverified_key_path_sigs(psbt, plan, num_inputs, result);
  wally_psbt_signing_cache_disable(psbt);

  for (size_t i = 0; i < num_inputs; i++)
    restore_input_state(psbt, i, &plan[i], result);

  /* Tally against the final PSBT rather than per call: what matters is
   * whether an input we cleared ended the pass holding a new signature, by
   * every key of ours it lists. */
  if (result) {
    for (size_t i = 0; i < num_inputs; i++) {
      if (!plan[i].attempted)
        continue;
      result->attempted++;
      if (input_signature_count(psbt, i) <= plan[i].sig_baseline)
        continue;
      if (input_signed_by_listed_keys(psbt, i, &plan[i]))
        result->signed_ok++;
      else
        result->missing_keys++;
    }
  }

cleanup:
  for (size_t i = 0; i < num_inputs; i++)
    release_input_state(&plan[i]);
  free(plan);

  return signatures_added;
}

/* A v0 PSBT is trimmed by rebuilding it from its transaction, but that
 * constructor only produces v0: a v2 one would either export downgraded or be
 * upgraded back, and the upgrade rewrites the tx-modifiable flags to fully
 * modifiable, undoing the signer rules applied above. A v2 PSBT also carries
 * its transaction in its inputs and outputs, sequences and required locktimes
 * included, where a rebuild could lose a field and with it the txid. So a copy
 * is trimmed in place, of what weighs: previous transactions, key origins,
 * scripts the coordinator has and unknown fields. The small fields the v0 path
 * also drops (sighash type, taproot merkle root, preimages) stay. */
static struct wally_psbt *psbt_trim_v2(const struct wally_psbt *psbt) {
  struct wally_psbt *trimmed = NULL;
  if (wally_psbt_clone_alloc(psbt, 0, &trimmed) != WALLY_OK)
    return NULL;

  wally_map_clear(&trimmed->global_xpubs);
  wally_map_clear(&trimmed->unknowns);

  for (size_t i = 0; i < trimmed->num_inputs; i++) {
    struct wally_psbt_input *in = &trimmed->inputs[i];
    wally_psbt_input_set_utxo(in, NULL);
    wally_psbt_input_set_taproot_internal_key(in, NULL, 0);
    wally_map_clear(&in->keypaths);
    wally_map_clear(&in->taproot_leaf_hashes);
    wally_map_clear(&in->taproot_leaf_paths);
    wally_map_clear(&in->taproot_leaf_scripts);
    wally_map_clear(&in->unknowns);
  }

  for (size_t i = 0; i < trimmed->num_outputs; i++) {
    struct wally_psbt_output *out = &trimmed->outputs[i];
    wally_psbt_output_set_redeem_script(out, NULL, 0);
    wally_psbt_output_set_witness_script(out, NULL, 0);
    wally_psbt_output_set_taproot_internal_key(out, NULL, 0);
    wally_map_clear(&out->keypaths);
    wally_map_clear(&out->taproot_leaf_hashes);
    wally_map_clear(&out->taproot_leaf_paths);
    wally_map_clear(&out->taproot_tree);
    wally_map_clear(&out->unknowns);
  }

  return trimmed;
}

struct wally_psbt *psbt_trim(const struct wally_psbt *psbt) {
  if (!psbt) {
    return NULL;
  }

  if (psbt_is_v2(psbt)) {
    return psbt_trim_v2(psbt);
  }

  struct wally_tx *global_tx = psbt_tx_alloc(psbt);
  if (!global_tx) {
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
