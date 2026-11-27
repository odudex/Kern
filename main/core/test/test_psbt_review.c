/* Host unit tests for core/psbt_review.c: output role classification
 * (change vs self-transfer vs unsafe/expected/spend), policy formatting,
 * and full review summary assembly. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

#include "core/key.h"
#include "core/psbt.h"
#include "core/psbt_review.h"
#include "core/registry.h"
#include "core/settings.h"
#include "core/storage.h"
#include "core/wallet.h"

/* --- Stubs (same minimal host setup as test_psbt_classify) --- */
esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  storage_descriptor_format_t format) {
  (void)loc;
  (void)id;
  (void)data;
  (void)len;
  (void)format;
  return ESP_OK;
}
esp_err_t storage_delete_descriptor(storage_location_t loc,
                                    const char *filename) {
  (void)loc;
  (void)filename;
  return ESP_OK;
}
esp_err_t storage_list_descriptors(storage_location_t loc,
                                   char ***filenames_out, int *count_out) {
  (void)loc;
  if (filenames_out)
    *filenames_out = NULL;
  if (count_out)
    *count_out = 0;
  return ESP_OK;
}
esp_err_t storage_load_descriptor(storage_location_t loc, const char *filename,
                                  uint8_t **data_out, size_t *len_out,
                                  storage_descriptor_format_t *format_out) {
  (void)loc;
  (void)filename;
  if (data_out)
    *data_out = NULL;
  if (len_out)
    *len_out = 0;
  if (format_out)
    *format_out = STORAGE_DESCRIPTOR_TXT;
  return -1;
}
void storage_free_file_list(char **files, int count) {
  (void)files;
  (void)count;
}
wallet_network_t wallet_get_network(void) { return WALLET_NETWORK_MAINNET; }
bool settings_get_permissive_signing(void) { return false; }

static int failures = 0;

static void check(const char *name, bool cond) {
  if (!cond) {
    fprintf(stderr, "FAIL: %s\n", name);
    failures++;
  }
}

static const char *TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about";

static claim_t make_ss_claim(ss_script_type_t script, uint32_t purpose,
                             uint32_t account, uint32_t chain, uint32_t index) {
  claim_t c = {0};
  c.kind = CLAIM_WHITELIST;
  c.whitelist.script = script;
  c.whitelist.purpose = purpose;
  c.whitelist.coin = 0;
  c.whitelist.account = account;
  c.whitelist.chain = chain;
  c.whitelist.index = index;
  return c;
}

static psbt_review_input_t make_safe_input(claim_t claim) {
  psbt_review_input_t in = {0};
  in.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
  in.claim = claim;
  return in;
}

static output_ownership_t make_safe_output_own(claim_t claim) {
  output_ownership_t own = {0};
  own.ownership = PSBT_OWNERSHIP_OWNED_SAFE;
  own.source = claim;
  return own;
}

/* Build a raw keypath (4-byte fingerprint + N LE uint32 components). */
static size_t encode_raw_keypath(uint8_t *out, const uint32_t *path, size_t n) {
  out[0] = 0x73;
  out[1] = 0xc5;
  out[2] = 0xda;
  out[3] = 0x0a;
  for (size_t i = 0; i < n; i++) {
    uint32_t v = path[i];
    out[4 + i * 4 + 0] = (uint8_t)(v & 0xff);
    out[4 + i * 4 + 1] = (uint8_t)((v >> 8) & 0xff);
    out[4 + i * 4 + 2] = (uint8_t)((v >> 16) & 0xff);
    out[4 + i * 4 + 3] = (uint8_t)((v >> 24) & 0xff);
  }
  return 4 + n * 4;
}

static void test_format_claim_policy(void) {
  char buf[64];
  claim_t c = make_ss_claim(SS_SCRIPT_P2WPKH, 84, 3, 0, 0);
  psbt_review_format_claim_policy(&c, buf, sizeof(buf));
  check("format native segwit policy",
        strcmp(buf, "Native SegWit @ account 3") == 0);

  c = make_ss_claim(SS_SCRIPT_P2TR, 86, 0, 1, 5);
  psbt_review_format_claim_policy(&c, buf, sizeof(buf));
  check("format taproot policy", strcmp(buf, "Taproot @ account 0") == 0);

  registry_entry_t entry = {0};
  snprintf(entry.id, sizeof(entry.id), "desc_12345678");
  claim_t rc = {0};
  rc.kind = CLAIM_REGISTRY;
  rc.registry.entry = &entry;
  psbt_review_format_claim_policy(&rc, buf, sizeof(buf));
  check("format registry policy falls back to id",
        strcmp(buf, "desc_12345678") == 0);

  snprintf(entry.label, sizeof(entry.label), "Vault 2-of-3");
  psbt_review_format_claim_policy(&rc, buf, sizeof(buf));
  check("format registry policy prefers label",
        strcmp(buf, "Vault 2-of-3") == 0);
}

static void test_classify_output_roles(void) {
  psbt_review_input_t inputs[1];
  inputs[0] = make_safe_input(make_ss_claim(SS_SCRIPT_P2WPKH, 84, 0, 0, 7));

  /* Same wallet, change chain -> CHANGE */
  psbt_review_output_t out = {0};
  psbt_review_classify_output(
      inputs, 1,
      make_safe_output_own(make_ss_claim(SS_SCRIPT_P2WPKH, 84, 0, 1, 12)),
      &out);
  check("same account change chain is CHANGE", out.type == PSBT_OUTPUT_CHANGE);
  check("change sets change_chain and index",
        out.change_chain && out.address_index == 12);
  check("change formats policy",
        strcmp(out.policy, "Native SegWit @ account 0") == 0);

  /* Same wallet, receive chain -> SELF_TRANSFER */
  memset(&out, 0, sizeof(out));
  psbt_review_classify_output(
      inputs, 1,
      make_safe_output_own(make_ss_claim(SS_SCRIPT_P2WPKH, 84, 0, 0, 2)), &out);
  check("same account receive chain is SELF_TRANSFER",
        out.type == PSBT_OUTPUT_SELF_TRANSFER && !out.change_chain &&
            out.address_index == 2);

  /* Different account, change chain -> SELF_TRANSFER (not silent change!) */
  memset(&out, 0, sizeof(out));
  psbt_review_classify_output(
      inputs, 1,
      make_safe_output_own(make_ss_claim(SS_SCRIPT_P2WPKH, 84, 1, 1, 0)), &out);
  check("cross-account change chain is SELF_TRANSFER",
        out.type == PSBT_OUTPUT_SELF_TRANSFER && out.change_chain);

  /* Different script type, same account, change chain -> SELF_TRANSFER */
  memset(&out, 0, sizeof(out));
  psbt_review_classify_output(
      inputs, 1,
      make_safe_output_own(make_ss_claim(SS_SCRIPT_P2TR, 86, 0, 1, 0)), &out);
  check("cross-script change chain is SELF_TRANSFER",
        out.type == PSBT_OUTPUT_SELF_TRANSFER);

  /* Registry descriptor: same entry multi_index=1 -> CHANGE, multi_index=0 ->
   * SELF_TRANSFER, different entry multi_index=1 -> SELF_TRANSFER */
  registry_entry_t desc_a = {0};
  registry_entry_t desc_b = {0};
  snprintf(desc_a.id, sizeof(desc_a.id), "vault_a");
  snprintf(desc_b.id, sizeof(desc_b.id), "vault_b");

  claim_t reg_in = {
      .kind = CLAIM_REGISTRY,
      .registry = {.entry = &desc_a, .multi_index = 0, .child_num = 3}};
  psbt_review_input_t reg_inputs[1] = {make_safe_input(reg_in)};

  claim_t reg_chg = {
      .kind = CLAIM_REGISTRY,
      .registry = {.entry = &desc_a, .multi_index = 1, .child_num = 4}};
  memset(&out, 0, sizeof(out));
  psbt_review_classify_output(reg_inputs, 1, make_safe_output_own(reg_chg),
                              &out);
  check("same descriptor change branch is CHANGE",
        out.type == PSBT_OUTPUT_CHANGE && out.change_chain &&
            out.address_index == 4);

  claim_t reg_recv = {
      .kind = CLAIM_REGISTRY,
      .registry = {.entry = &desc_a, .multi_index = 0, .child_num = 9}};
  memset(&out, 0, sizeof(out));
  psbt_review_classify_output(reg_inputs, 1, make_safe_output_own(reg_recv),
                              &out);
  check("same descriptor receive branch is SELF_TRANSFER",
        out.type == PSBT_OUTPUT_SELF_TRANSFER && !out.change_chain);

  claim_t reg_other = {
      .kind = CLAIM_REGISTRY,
      .registry = {.entry = &desc_b, .multi_index = 1, .child_num = 1}};
  memset(&out, 0, sizeof(out));
  psbt_review_classify_output(reg_inputs, 1, make_safe_output_own(reg_other),
                              &out);
  check("different descriptor change branch is SELF_TRANSFER",
        out.type == PSBT_OUTPUT_SELF_TRANSFER);

  /* OWNED_UNSAFE and EXPECTED_OWNED format their keypath */
  uint32_t path[] = {BIP32_INITIAL_HARDENED_CHILD + 84,
                     BIP32_INITIAL_HARDENED_CHILD + 0,
                     BIP32_INITIAL_HARDENED_CHILD + 200, 0, 1};
  output_ownership_t unsafe_own = {0};
  unsafe_own.ownership = PSBT_OWNERSHIP_OWNED_UNSAFE;
  unsafe_own.raw_keypath_len =
      encode_raw_keypath(unsafe_own.raw_keypath, path, 5);
  memset(&out, 0, sizeof(out));
  psbt_review_classify_output(inputs, 1, unsafe_own, &out);
  check("OWNED_UNSAFE classifies and formats path",
        out.type == PSBT_OUTPUT_OWNED_UNSAFE &&
            strcmp(out.path, "m/84'/0'/200'/0/1") == 0);

  output_ownership_t exp_own = unsafe_own;
  exp_own.ownership = PSBT_OWNERSHIP_EXPECTED_OWNED;
  memset(&out, 0, sizeof(out));
  psbt_review_classify_output(inputs, 1, exp_own, &out);
  check("EXPECTED_OWNED classifies and formats path",
        out.type == PSBT_OUTPUT_EXPECTED_OWNED &&
            strcmp(out.path, "m/84'/0'/200'/0/1") == 0);

  /* EXTERNAL -> SPEND */
  output_ownership_t ext_own = {0};
  ext_own.ownership = PSBT_OWNERSHIP_EXTERNAL;
  memset(&out, 0, sizeof(out));
  psbt_review_classify_output(inputs, 1, ext_own, &out);
  check("EXTERNAL classifies as SPEND", out.type == PSBT_OUTPUT_SPEND);
}

/* Build a P2WPKH scriptPubKey for a derived key at `path`. */
static bool derive_p2wpkh(const char *path, unsigned char spk[22],
                          unsigned char pubkey[EC_PUBLIC_KEY_LEN]) {
  struct ext_key *k = NULL;
  if (!key_get_derived_key(path, &k))
    return false;
  memcpy(pubkey, k->pub_key, EC_PUBLIC_KEY_LEN);
  size_t written = 0;
  int ret = wally_witness_program_from_bytes(
      k->pub_key, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160, spk, 22, &written);
  bip32_key_free(k);
  return ret == WALLY_OK && written == 22;
}

static void test_collect_end_to_end(void) {
  check("load test mnemonic", key_load_from_mnemonic(TEST_MNEMONIC, "", false));

  unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
  check("get fingerprint", key_get_fingerprint(fp));

  unsigned char in_spk[22], in_pub[EC_PUBLIC_KEY_LEN];
  unsigned char chg_spk[22], chg_pub[EC_PUBLIC_KEY_LEN];
  unsigned char recv_spk[22], recv_pub[EC_PUBLIC_KEY_LEN];
  check("derive input key", derive_p2wpkh("m/84'/0'/0'/0/0", in_spk, in_pub));
  check("derive change key",
        derive_p2wpkh("m/84'/0'/0'/1/0", chg_spk, chg_pub));
  check("derive self-transfer key",
        derive_p2wpkh("m/84'/0'/1'/1/0", recv_spk, recv_pub));

  /* External spend script (all 0x11 pubkey hash -> valid P2WPKH, dust value) */
  unsigned char ext_spk[22] = {0x00, 0x14};
  memset(ext_spk + 2, 0x11, 20);

  struct wally_tx *tx = NULL;
  check("alloc tx", wally_tx_init_alloc(2, 850000, 1, 3, &tx) == WALLY_OK);

  unsigned char txhash[32] = {0xaa};
  /* sequence 0xfffffffd signals BIP-125 RBF */
  check("add tx input",
        wally_tx_add_raw_input(tx, txhash, sizeof(txhash), 0, 0xfffffffdu, NULL,
                               0, NULL, 0) == WALLY_OK);
  /* Output 0: spend of 200 sats (below P2WPKH dust threshold 294 sats) */
  check("add spend output",
        wally_tx_add_raw_output(tx, 200, ext_spk, sizeof(ext_spk), 0) ==
            WALLY_OK);
  /* Output 1: change back to m/84'/0'/0'/1/0 (50000 sats) */
  check("add change output",
        wally_tx_add_raw_output(tx, 50000, chg_spk, sizeof(chg_spk), 0) ==
            WALLY_OK);
  /* Output 2: cross-account change m/84'/0'/1'/1/0 (40000 sats ->
   * self-transfer) */
  check("add self-transfer output",
        wally_tx_add_raw_output(tx, 40000, recv_spk, sizeof(recv_spk), 0) ==
            WALLY_OK);

  struct wally_psbt *psbt = NULL;
  check("init psbt", wally_psbt_init_alloc(WALLY_PSBT_VERSION_0, 1, 3, 0, 0,
                                           &psbt) == WALLY_OK);
  check("set global tx", wally_psbt_set_global_tx(psbt, tx) == WALLY_OK);
  wally_tx_free(tx);

  /* Input 0 witness_utxo (100000 sats) + keypath m/84'/0'/0'/0/0 */
  struct wally_tx_output *utxo = NULL;
  check("alloc utxo", wally_tx_output_init_alloc(100000, in_spk, sizeof(in_spk),
                                                 &utxo) == WALLY_OK);
  check("set input witness_utxo",
        wally_psbt_set_input_witness_utxo(psbt, 0, utxo) == WALLY_OK);
  wally_tx_output_free(utxo);

  uint32_t in_path[] = {BIP32_INITIAL_HARDENED_CHILD + 84,
                        BIP32_INITIAL_HARDENED_CHILD + 0,
                        BIP32_INITIAL_HARDENED_CHILD + 0, 0, 0};
  check("add input keypath",
        wally_psbt_add_input_keypath(psbt, 0, in_pub, sizeof(in_pub), fp,
                                     sizeof(fp), in_path, 5) == WALLY_OK);

  uint32_t chg_path[] = {BIP32_INITIAL_HARDENED_CHILD + 84,
                         BIP32_INITIAL_HARDENED_CHILD + 0,
                         BIP32_INITIAL_HARDENED_CHILD + 0, 1, 0};
  check("add output 1 keypath",
        wally_psbt_add_output_keypath(psbt, 1, chg_pub, sizeof(chg_pub), fp,
                                      sizeof(fp), chg_path, 5) == WALLY_OK);

  uint32_t recv_path[] = {BIP32_INITIAL_HARDENED_CHILD + 84,
                          BIP32_INITIAL_HARDENED_CHILD + 0,
                          BIP32_INITIAL_HARDENED_CHILD + 1, 1, 0};
  check("add output 2 keypath",
        wally_psbt_add_output_keypath(psbt, 2, recv_pub, sizeof(recv_pub), fp,
                                      sizeof(fp), recv_path, 5) == WALLY_OK);

  psbt_owners_t owners;
  check("classify owners", psbt_review_classify_owners(psbt, false, &owners));

  psbt_review_t rev;
  check("collect review data", psbt_review_collect(psbt, false, &owners, &rev));

  check("totals and fee", rev.total_input == 100000 &&
                              rev.total_output == 90200 && rev.fee == 9800);
  check("single-input fee is trusted", rev.fee_trusted);
  check("locktime and RBF captured", rev.locktime == 850000 && rev.signals_rbf);
  check("dust output detected", rev.dust_count == 1 && rev.first_dust == 0 &&
                                    rev.first_dust_value == 200);
  check("no external inputs", rev.external_inputs == 0);
  check("input 0 policy",
        strcmp(rev.inputs[0].policy, "Native SegWit @ account 0") == 0);
  check("output 0 is SPEND with dust",
        rev.outputs[0].type == PSBT_OUTPUT_SPEND && rev.outputs[0].is_dust &&
            rev.outputs[0].address != NULL);
  check("output 1 is CHANGE",
        rev.outputs[1].type == PSBT_OUTPUT_CHANGE && !rev.outputs[1].is_dust);
  check("output 2 is SELF_TRANSFER (account 1)",
        rev.outputs[2].type == PSBT_OUTPUT_SELF_TRANSFER &&
            strcmp(rev.outputs[2].policy, "Native SegWit @ account 1") == 0);

  psbt_review_free(&rev);
  psbt_review_free_owners(&owners);
  wally_psbt_free(psbt);
  key_unload();
}

int main(void) {
  if (wally_init(0) != WALLY_OK) {
    fprintf(stderr, "wally_init failed\n");
    return 1;
  }
  test_format_claim_policy();
  test_classify_output_roles();
  test_collect_end_to_end();

  if (failures) {
    fprintf(stderr, "psbt_review: %d failures\n", failures);
    return 1;
  }
  printf("psbt_review tests passed\n");
  return 0;
}
