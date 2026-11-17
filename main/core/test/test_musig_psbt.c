/*
 * MuSig2 PSBT tests (core/musig_psbt.c).
 *
 * Runs against the real key, wallet, registry and nonce cache modules with the
 * BIP39 test mnemonic loaded on testnet; sessions live in the simulator's NVS
 * under a fresh temp directory. Our participant is the account 86'/1'/0'; the
 * cosigner is the account 86'/1'/1' of the same seed, given another
 * fingerprint so the registry takes it for a foreign key, and the test signs
 * for it with libwally's own MuSig2 PSBT functions.
 */

#include "core/key.h"
#include "core/musig_psbt.h"
#include "core/nonce_cache.h"
#include "core/psbt_internal.h"
#include "core/registry.h"
#include "core/sp_psbt.h"
#include "core/storage.h"
#include "core/wallet.h"
#include "esp_err.h"
#include "sim_nvs.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>
#include <wally_map.h>
#include <wally_musig.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

static int tests_run = 0;
static int tests_failed = 0;

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

/* ---------- storage stubs (registry persistence is never reached) ----------
 */

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
  *filenames_out = NULL;
  *count_out = 0;
  return ESP_OK;
}

esp_err_t storage_load_descriptor(storage_location_t loc, const char *filename,
                                  uint8_t **data_out, size_t *len_out,
                                  storage_descriptor_format_t *format_out) {
  (void)loc;
  (void)filename;
  *data_out = NULL;
  *len_out = 0;
  *format_out = STORAGE_DESCRIPTOR_TXT;
  return -1;
}

void storage_free_file_list(char **files, int count) {
  (void)files;
  (void)count;
}

/* ---------- fixtures ---------- */

static const char *TEST_MNEMONIC = "abandon abandon abandon abandon abandon "
                                   "abandon abandon abandon abandon abandon "
                                   "abandon about";
#define FP "73c5da0a"
#define OURS "m/86'/1'/0'"
#define COSIGNER "m/86'/1'/1'"
#define CHILD 3
#define AMOUNT 50000

/* musig() of the participant keys at 0/CHILD */
#define DERIVE_THEN_AGGREGATE                                                  \
  "tr(musig([" FP "/86'/1'/0']%s/<0;1>/*,[deadbeef/86'/1'/1']%s/<0;1>/*))"
/* musig() of the account keys, derived at 0/CHILD after aggregation */
#define AGGREGATE_THEN_DERIVE                                                  \
  "tr(musig([" FP "/86'/1'/0']%s,[deadbeef/86'/1'/1']%s)/<0;1>/*)"

/* The same on a recovery path's <2;3> */
#define AGGREGATE_THEN_DERIVE_RECOVERY                                         \
  "tr(musig([" FP "/86'/1'/0']%s,[deadbeef/86'/1'/1']%s)/<2;3>/*)"
/* musig() of the participant keys at 2/CHILD or 3/CHILD */
#define DERIVE_THEN_AGGREGATE_RECOVERY                                         \
  "tr(musig([" FP "/86'/1'/0']%s/<2;3>/*,[deadbeef/86'/1'/1']%s/<2;3>/*))"

static const unsigned char OUR_FP[4] = {0x73, 0xc5, 0xda, 0x0a};
static const unsigned char SYNTHETIC_FP[4] = {0xaa, 0xbb, 0xcc, 0xdd};

static char descriptor_buf[1024];

static const char *xpub_at(const char *path, char *out, size_t len) {
  char *xpub = NULL;
  if (!key_get_xpub(path, &xpub))
    return "";
  snprintf(out, len, "%s", xpub);
  wally_free_string(xpub);
  return out;
}

static bool register_descriptor(const char *fmt) {
  char ours[128], cosigner[128];
  snprintf(descriptor_buf, sizeof(descriptor_buf), fmt,
           xpub_at(OURS, ours, sizeof(ours)),
           xpub_at(COSIGNER, cosigner, sizeof(cosigner)));
  registry_clear();
  return registry_add_from_string("m", descriptor_buf, STORAGE_FLASH, false);
}

/* fp | path little endian, as PSBT_IN_TAP_BIP32_DERIVATION carries it */
static size_t origin(const unsigned char *fp, const uint32_t *path, size_t len,
                     unsigned char *out) {
  memcpy(out, fp, 4);
  for (size_t i = 0; i < len; i++)
    for (size_t b = 0; b < 4; b++)
      out[4 + 4 * i + b] = (unsigned char)(path[i] >> (8 * b));
  return 4 + 4 * len;
}

static size_t script_at(uint32_t multi_index, uint32_t child_num,
                        unsigned char *spk) {
  unsigned char work[PSBT_MAX_INNER_SCRIPT_LEN];
  size_t written = 0;
  if (wally_descriptor_to_script(registry_get(0)->desc, 0, 0, 0, multi_index,
                                 child_num, 0, work, sizeof(work),
                                 &written) != WALLY_OK ||
      written != WALLY_SCRIPTPUBKEY_P2TR_LEN)
    return 0;
  memcpy(spk, work, written);
  return written;
}

static bool claims(const unsigned char *fp, uint32_t multi_index,
                   uint32_t child_num, const unsigned char *spk, size_t spk_len,
                   claim_t *claim) {
  const uint32_t path[] = {multi_index, child_num};
  unsigned char value[4 + 4 * 2];
  struct wally_map map;
  wally_map_init(1, NULL, &map);
  wally_map_add(&map, spk + 2, 32, value, origin(fp, path, 2, value));
  bool claimed = musig_psbt_claim(&map, spk, spk_len, claim);
  wally_map_clear(&map);
  return claimed;
}

/* ---------- claim ---------- */

static void test_claim(void) {
  check("musig() descriptor registers",
        register_descriptor(AGGREGATE_THEN_DERIVE));
  const registry_entry_t *entry = registry_get(0);
  unsigned char receive[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  unsigned char change[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  size_t receive_len = script_at(0, 5, receive);
  size_t change_len = script_at(1, 5, change);
  check("scripts generate", receive_len && change_len);

  claim_t claim;
  check("receive script claimed at 0/5",
        claims(SYNTHETIC_FP, 0, 5, receive, receive_len, &claim) &&
            claim.kind == CLAIM_MUSIG && claim.registry.entry == entry &&
            claim.registry.multi_index == 0 && claim.registry.child_num == 5);
  check("change script claimed at 1/5",
        claims(SYNTHETIC_FP, 1, 5, change, change_len, &claim) &&
            claim.registry.multi_index == 1 && claim.registry.child_num == 5);
  check("receive script with a change origin refused",
        !claims(SYNTHETIC_FP, 1, 5, receive, receive_len, &claim));
  check("receive script with another child refused",
        !claims(SYNTHETIC_FP, 0, 6, receive, receive_len, &claim));
  check("hardened child refused",
        !claims(SYNTHETIC_FP, 0, 0x80000005, receive, receive_len, &claim));
  check("multipath index past the descriptor's refused",
        !claims(SYNTHETIC_FP, 2, 5, receive, receive_len, &claim));
  check("hardened step before the child refused",
        !claims(SYNTHETIC_FP, 0x80000000, 5, receive, receive_len, &claim));
  unsigned char p2wpkh[22] = {0x00, 0x14};
  check("non-taproot script refused",
        !claims(SYNTHETIC_FP, 0, 5, p2wpkh, sizeof(p2wpkh), &claim));

  check("musig() descriptor on <2;3> registers",
        register_descriptor(AGGREGATE_THEN_DERIVE_RECOVERY));
  entry = registry_get(0);
  receive_len = script_at(0, 5, receive);
  change_len = script_at(1, 5, change);
  check("<2;3> scripts generate", receive_len && change_len);
  check("<2;3> script at 2/5 claimed at tuple position 0",
        claims(SYNTHETIC_FP, 2, 5, receive, receive_len, &claim) &&
            claim.kind == CLAIM_MUSIG && claim.registry.entry == entry &&
            claim.registry.multi_index == 0 && claim.registry.child_num == 5);
  check("<2;3> script at 3/5 claimed at tuple position 1",
        claims(SYNTHETIC_FP, 3, 5, change, change_len, &claim) &&
            claim.registry.multi_index == 1 && claim.registry.child_num == 5);
  check("<2;3> script with another child refused",
        !claims(SYNTHETIC_FP, 3, 6, change, change_len, &claim));
  check("<2;3> receive script with a 3/5 origin refused",
        !claims(SYNTHETIC_FP, 3, 5, receive, receive_len, &claim));
  check("<2;3> receive script with a 0/5 origin refused",
        !claims(SYNTHETIC_FP, 0, 5, receive, receive_len, &claim));

  char ours[128];
  snprintf(descriptor_buf, sizeof(descriptor_buf),
           "tr([" FP "/86'/1'/0']%s/<0;1>/*)",
           xpub_at(OURS, ours, sizeof(ours)));
  registry_clear();
  check("plain taproot descriptor registers",
        registry_add_from_string("t", descriptor_buf, STORAGE_FLASH, false));
  receive_len = script_at(0, 5, receive);
  check("a descriptor without our musig() claims nothing",
        receive_len && !claims(OUR_FP, 0, 5, receive, receive_len, &claim));
  registry_clear();
}

/* ---------- signing ---------- */

/* A key of the test seed, with its private key. */
static struct ext_key *key_at(const char *path) {
  struct ext_key *key = NULL;
  return key_get_derived_key(path, &key) ? key : NULL;
}

/* The key at descriptor key index `index`, at 0/`child_num`, as libwally
 * derives it from the registered descriptor: a musig()'s derived aggregate. */
static bool descriptor_key_at(uint32_t index, uint32_t child_num,
                              unsigned char *pub_out) {
  struct ext_key key;
  bool ok = wally_descriptor_derive_bip32_key(
                registry_get(0)->desc, index, 0, 0, child_num,
                BIP32_FLAG_KEY_PUBLIC, &key) == WALLY_OK;
  if (ok)
    memcpy(pub_out, key.pub_key, EC_PUBLIC_KEY_LEN);
  wally_bzero(&key, sizeof(key));
  return ok;
}

typedef struct {
  struct wally_psbt *psbt;
  unsigned char ours[EC_PUBLIC_KEY_LEN];
  unsigned char cosigner[EC_PUBLIC_KEY_LEN];
  unsigned char cosigner_sk[EC_PRIVATE_KEY_LEN];
  /* the KeyAgg key of PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS */
  unsigned char aggregate[EC_PUBLIC_KEY_LEN];
  /* the aggregate of the key path's BIP-373 keys: the output key */
  unsigned char output[EC_PUBLIC_KEY_LEN];
} fixture_t;

static void fixture_free(fixture_t *f) {
  wally_psbt_free(f->psbt);
  wally_bzero(f->cosigner_sk, sizeof(f->cosigner_sk));
  memset(f, 0, sizeof(*f));
}

static bool fixture_keys(const char *ours_path, const char *cosigner_path,
                         fixture_t *f) {
  struct ext_key *ours = key_at(ours_path);
  struct ext_key *cosigner = key_at(cosigner_path);
  bool ok = ours && cosigner;
  if (ok) {
    memcpy(f->ours, ours->pub_key, EC_PUBLIC_KEY_LEN);
    memcpy(f->cosigner, cosigner->pub_key, EC_PUBLIC_KEY_LEN);
    memcpy(f->cosigner_sk, cosigner->priv_key + 1, EC_PRIVATE_KEY_LEN);
  }
  bip32_key_free(ours);
  bip32_key_free(cosigner);
  return ok;
}

/* A one-input PSBT spending the registered descriptor's script at
 * 0/`child_num`, with the PSBT_IN_TAP_BIP32_DERIVATION `origin` of the x-only
 * `key` the claim reads. */
static bool spend_alloc(uint32_t child_num, const unsigned char *key,
                        const unsigned char *origin, size_t origin_len,
                        struct wally_psbt **psbt_out) {
  unsigned char spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  size_t spk_len = script_at(0, child_num, spk);
  static const unsigned char txid[32] = {7};
  struct wally_tx *tx = NULL;
  struct wally_tx_output *utxo = NULL;
  bool ok =
      spk_len && wally_psbt_init_alloc(0, 1, 1, 1, 0, psbt_out) == WALLY_OK &&
      wally_tx_init_alloc(2, 0, 1, 1, &tx) == WALLY_OK &&
      wally_tx_add_raw_input(tx, txid, sizeof(txid), 0, 0xfffffffd, NULL, 0,
                             NULL, 0) == WALLY_OK &&
      wally_tx_add_raw_output(tx, AMOUNT - 500, spk, spk_len, 0) == WALLY_OK &&
      wally_psbt_set_global_tx(*psbt_out, tx) == WALLY_OK &&
      wally_tx_output_init_alloc(AMOUNT, spk, spk_len, &utxo) == WALLY_OK &&
      wally_psbt_set_input_witness_utxo(*psbt_out, 0, utxo) == WALLY_OK &&
      wally_map_add(&(*psbt_out)->inputs[0].taproot_leaf_paths, key, 32, origin,
                    origin_len) == WALLY_OK &&
      /* libwally serializes an origin only beside its leaf hashes, none here */
      wally_map_merkle_path_add(&(*psbt_out)->inputs[0].taproot_leaf_hashes,
                                key, 32, NULL, 0) == WALLY_OK;
  wally_tx_free(tx);
  wally_tx_output_free(utxo);
  return ok;
}

/* A one-input PSBT spending the registered descriptor's script at 0/CHILD.
 * `origin` is the PSBT_IN_TAP_BIP32_DERIVATION value the claim reads, and
 * `asked` says whether the input asks for MuSig2 with a 0x1a. */
static bool fixture(const char *ours_path, const char *cosigner_path,
                    const unsigned char *origin, size_t origin_len, bool asked,
                    fixture_t *f) {
  memset(f, 0, sizeof(*f));
  if (!fixture_keys(ours_path, cosigner_path, f))
    return false;

  unsigned char keys[2 * EC_PUBLIC_KEY_LEN], xonly[32];
  bool ours_first = memcmp(f->ours, f->cosigner, EC_PUBLIC_KEY_LEN) < 0;
  memcpy(keys, ours_first ? f->ours : f->cosigner, EC_PUBLIC_KEY_LEN);
  memcpy(keys + EC_PUBLIC_KEY_LEN, ours_first ? f->cosigner : f->ours,
         EC_PUBLIC_KEY_LEN);
  struct wally_musig_keyagg_cache *cache = NULL;
  bool aggregated = wally_musig_pubkey_agg(keys, sizeof(keys), xonly,
                                           sizeof(xonly), &cache) == WALLY_OK &&
                    wally_musig_pubkey_get(cache, f->aggregate,
                                           EC_PUBLIC_KEY_LEN) == WALLY_OK;
  wally_musig_keyagg_cache_free(cache);
  if (!aggregated)
    return false;

  bool ok = spend_alloc(CHILD, f->ours + 1, origin, origin_len, &f->psbt);
  if (ok && asked)
    ok = wally_psbt_input_add_musig2_participant_pubkeys(
             &f->psbt->inputs[0], f->aggregate, EC_PUBLIC_KEY_LEN, keys,
             sizeof(keys)) == WALLY_OK;
  return ok;
}

/* The output key of a tr() without a script tree: the internal key libwally
 * derives, tweaked, checked against the spent script. */
static bool key_path_output(fixture_t *f) {
  unsigned char internal[EC_PUBLIC_KEY_LEN];
  unsigned char spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  return descriptor_key_at(0, CHILD, internal) && script_at(0, CHILD, spk) &&
         wally_ec_public_key_bip341_tweak(internal, sizeof(internal), NULL, 0,
                                          0, f->output,
                                          sizeof(f->output)) == WALLY_OK &&
         memcmp(f->output + 1, spk + 2, EC_XONLY_PUBLIC_KEY_LEN) == 0;
}

static bool has_entry(const struct wally_map *map, const unsigned char *a,
                      const unsigned char *b) {
  unsigned char key[2 * EC_PUBLIC_KEY_LEN];
  size_t found = 0;
  memcpy(key, a, EC_PUBLIC_KEY_LEN);
  memcpy(key + EC_PUBLIC_KEY_LEN, b, EC_PUBLIC_KEY_LEN);
  return wally_map_find(map, key, sizeof(key), &found) == WALLY_OK && found;
}

static musig_step_t step_of(struct wally_psbt *psbt) {
  musig_plan_t plan;
  if (musig_psbt_plan(psbt, NULL, &plan) != MUSIG_PSBT_OK)
    return (musig_step_t)-1;
  musig_step_t step = plan.step;
  musig_plan_free(&plan);
  return step;
}

static musig_psbt_result_t check_session(struct wally_psbt *psbt) {
  musig_plan_t plan;
  musig_psbt_result_t result = musig_psbt_plan(psbt, NULL, &plan);
  if (result == MUSIG_PSBT_OK)
    result = musig_psbt_check_session(psbt, &plan);
  musig_plan_free(&plan);
  return result;
}

static musig_psbt_result_t sign(struct wally_psbt *psbt, size_t *added) {
  musig_plan_t plan;
  *added = 0;
  musig_psbt_result_t result = musig_psbt_plan(psbt, NULL, &plan);
  if (result == MUSIG_PSBT_OK)
    result = musig_psbt_sign(psbt, &plan, added);
  musig_plan_free(&plan);
  return result;
}

static musig_psbt_result_t check_request(const struct wally_psbt *psbt) {
  unsigned char bytes[4096];
  size_t len = 0;
  if (wally_psbt_to_bytes(psbt, 0, bytes, sizeof(bytes), &len) != WALLY_OK ||
      len > sizeof(bytes))
    return (musig_psbt_result_t)-1;
  return musig_psbt_check_request(bytes, len, true);
}

#define MAX_PARTICIPANTS 3

static int compare_keys(const void *a, const void *b) {
  return memcmp(a, b, EC_PUBLIC_KEY_LEN);
}

/* BIP-327 key aggregation of `n` keys in BIP-390 order, then the BIP-328
 * tweaks of `steps` from the synthetic xpub of the aggregate, written here
 * apart from musig_psbt.c's own. */
static struct wally_musig_keyagg_cache *key_agg(const unsigned char *keys,
                                                size_t n, const uint32_t *steps,
                                                size_t num_steps) {
  unsigned char sorted[MAX_PARTICIPANTS * EC_PUBLIC_KEY_LEN], xonly[32];
  unsigned char aggregate[EC_PUBLIC_KEY_LEN], data[37], hmac[64];
  unsigned char chain_code[32];
  struct wally_musig_keyagg_cache *cache = NULL;
  struct ext_key *synthetic = NULL;
  if (n > MAX_PARTICIPANTS)
    return NULL;
  memcpy(sorted, keys, n * EC_PUBLIC_KEY_LEN);
  qsort(sorted, n, EC_PUBLIC_KEY_LEN, compare_keys);
  bool ok =
      wally_musig_pubkey_agg(sorted, n * EC_PUBLIC_KEY_LEN, xonly,
                             sizeof(xonly), &cache) == WALLY_OK &&
      wally_musig_pubkey_get(cache, aggregate, sizeof(aggregate)) == WALLY_OK &&
      wally_musig_pubkey_to_xpub(aggregate, sizeof(aggregate),
                                 BIP32_VER_TEST_PUBLIC, &synthetic) == WALLY_OK;
  if (ok) {
    memcpy(chain_code, synthetic->chain_code, sizeof(chain_code));
    memcpy(data, aggregate, EC_PUBLIC_KEY_LEN);
  }
  bip32_key_free(synthetic);
  for (size_t i = 0; ok && i < num_steps; i++) {
    data[33] = (unsigned char)(steps[i] >> 24);
    data[34] = (unsigned char)(steps[i] >> 16);
    data[35] = (unsigned char)(steps[i] >> 8);
    data[36] = (unsigned char)steps[i];
    ok = wally_hmac_sha512(chain_code, sizeof(chain_code), data, sizeof(data),
                           hmac, sizeof(hmac)) == WALLY_OK &&
         wally_musig_pubkey_ec_tweak_add(cache, hmac, 32, data, 33) == WALLY_OK;
    memcpy(chain_code, hmac + 32, sizeof(chain_code));
  }
  if (!ok) {
    wally_musig_keyagg_cache_free(cache);
    return NULL;
  }
  return cache;
}

/* The BIP-341 tweak of a key aggregation to sign the key path, by the
 * output's `merkle_root`, NULL without a script tree. */
static bool tap_tweak(struct wally_musig_keyagg_cache *cache,
                      const unsigned char *merkle_root) {
  unsigned char internal[EC_PUBLIC_KEY_LEN], output[EC_PUBLIC_KEY_LEN];
  unsigned char data[2 * SHA256_LEN], tweak[SHA256_LEN];
  size_t data_len = EC_XONLY_PUBLIC_KEY_LEN;
  if (wally_musig_pubkey_get(cache, internal, sizeof(internal)) != WALLY_OK)
    return false;
  memcpy(data, internal + 1, EC_XONLY_PUBLIC_KEY_LEN);
  if (merkle_root) {
    memcpy(data + data_len, merkle_root, SHA256_LEN);
    data_len += SHA256_LEN;
  }
  return wally_bip340_tagged_hash(data, data_len, "TapTweak", tweak,
                                  sizeof(tweak)) == WALLY_OK &&
         wally_musig_pubkey_xonly_tweak_add(cache, tweak, sizeof(tweak), output,
                                            sizeof(output)) == WALLY_OK;
}

/* The key path's BIP-341 sighash, of the input's PSBT_IN_SIGHASH_TYPE. */
static bool key_path_sighash(struct wally_psbt *psbt, unsigned char *sighash) {
  struct wally_tx *tx = psbt_tx_alloc(psbt);
  bool ok = tx && wally_psbt_get_input_signature_hash(
                      psbt, 0, tx, NULL, 0, 0, sighash, SHA256_LEN) == WALLY_OK;
  wally_tx_free(tx);
  return ok;
}

/* A cosigner of a musig(), and its secret nonce once it gave one. */
typedef struct {
  const unsigned char *pub;
  const unsigned char *sk;
  struct wally_musig_secnonce *secnonce;
} cosigner_t;

/* A BIP-327 nonce of the cosigner, bound to nothing, added under the BIP-373
 * key of `aggregate` and `leaf_hash`, NULL on the key path; its secret nonce
 * is kept. */
static bool cosigner_nonce(struct wally_psbt *psbt, cosigner_t *c,
                           const unsigned char *aggregate,
                           const unsigned char *leaf_hash) {
  unsigned char rand[32] = {0x42, c->pub[1], aggregate[1]};
  unsigned char nonce[WALLY_MUSIG_PUBNONCE_LEN];
  struct wally_musig_pubnonce *pubnonce = NULL;
  bool ok =
      wally_musig_nonce_gen(rand, sizeof(rand), c->sk, EC_PRIVATE_KEY_LEN,
                            c->pub, EC_PUBLIC_KEY_LEN, NULL, NULL, 0, NULL, 0,
                            &c->secnonce, &pubnonce) == WALLY_OK &&
      wally_musig_pubnonce_serialize(pubnonce, nonce, sizeof(nonce)) ==
          WALLY_OK &&
      wally_psbt_input_add_musig2_pubnonce(
          &psbt->inputs[0], c->pub, EC_PUBLIC_KEY_LEN, aggregate,
          EC_PUBLIC_KEY_LEN, leaf_hash, leaf_hash ? SHA256_LEN : 0, nonce,
          sizeof(nonce)) == WALLY_OK;
  wally_musig_pubnonce_free(pubnonce);
  return ok;
}

/* The fixture's cosigner nonce, its secret nonce dropped. */
static bool add_cosigner_nonce(fixture_t *f, const unsigned char *aggregate,
                               const unsigned char *leaf_hash) {
  cosigner_t cosigner = {.pub = f->cosigner, .sk = f->cosigner_sk};
  bool ok = cosigner_nonce(f->psbt, &cosigner, aggregate, leaf_hash);
  wally_musig_secnonce_free(cosigner.secnonce);
  return ok;
}

/* The value of the PSBT's BIP-373 entry `participant | aggregate
 * [| leaf_hash]`, or NULL when the map has none of `value_len` bytes. */
static const unsigned char *entry(const struct wally_map *map,
                                  const unsigned char *participant,
                                  const unsigned char *aggregate,
                                  const unsigned char *leaf_hash,
                                  size_t value_len) {
  unsigned char key[2 * EC_PUBLIC_KEY_LEN + SHA256_LEN];
  size_t key_len = 2 * EC_PUBLIC_KEY_LEN, index = 0;
  memcpy(key, participant, EC_PUBLIC_KEY_LEN);
  memcpy(key + EC_PUBLIC_KEY_LEN, aggregate, EC_PUBLIC_KEY_LEN);
  if (leaf_hash) {
    memcpy(key + key_len, leaf_hash, SHA256_LEN);
    key_len += SHA256_LEN;
  }
  if (wally_map_find(map, key, key_len, &index) != WALLY_OK || !index ||
      map->items[index - 1].value_len != value_len)
    return NULL;
  return map->items[index - 1].value;
}

/* The BIP-340 signature of every participant: our partial signature the PSBT
 * carries under the BIP-373 key of `aggregate` and `leaf_hash`, and each
 * cosigner's made on the nonces it carries under that key with `cache`, the
 * key aggregation that signs. It must verify against `aggregate` for
 * `sighash`. */
static bool signature_verifies(const struct wally_psbt *psbt,
                               const unsigned char *ours, cosigner_t *cosigners,
                               size_t num_cosigners,
                               struct wally_musig_keyagg_cache *cache,
                               const unsigned char *aggregate,
                               const unsigned char *leaf_hash,
                               const unsigned char *sighash) {
  const struct wally_psbt_input *input = &psbt->inputs[0];
  size_t n = num_cosigners + 1;
  unsigned char nonces[MAX_PARTICIPANTS * WALLY_MUSIG_PUBNONCE_LEN];
  unsigned char partial_sigs[MAX_PARTICIPANTS * WALLY_MUSIG_PARTIAL_SIG_LEN];
  unsigned char sig[64];
  const unsigned char *our_nonce =
      entry(&input->musig2_pubnonces, ours, aggregate, leaf_hash,
            WALLY_MUSIG_PUBNONCE_LEN);
  const unsigned char *our_partial_sig =
      entry(&input->musig2_partial_sigs, ours, aggregate, leaf_hash,
            WALLY_MUSIG_PARTIAL_SIG_LEN);
  bool ok = n <= MAX_PARTICIPANTS && our_nonce && our_partial_sig;
  if (ok) {
    memcpy(nonces, our_nonce, WALLY_MUSIG_PUBNONCE_LEN);
    memcpy(partial_sigs, our_partial_sig, WALLY_MUSIG_PARTIAL_SIG_LEN);
  }
  for (size_t i = 0; ok && i < num_cosigners; i++) {
    const unsigned char *nonce =
        entry(&input->musig2_pubnonces, cosigners[i].pub, aggregate, leaf_hash,
              WALLY_MUSIG_PUBNONCE_LEN);
    ok = nonce != NULL;
    if (ok)
      memcpy(nonces + (i + 1) * WALLY_MUSIG_PUBNONCE_LEN, nonce,
             WALLY_MUSIG_PUBNONCE_LEN);
  }

  struct wally_musig_aggnonce *aggnonce = NULL;
  struct wally_musig_session *session = NULL;
  ok = ok &&
       wally_musig_nonce_agg(nonces, n * WALLY_MUSIG_PUBNONCE_LEN, n,
                             &aggnonce) == WALLY_OK &&
       wally_musig_nonce_process(aggnonce, sighash, SHA256_LEN, cache, NULL, 0,
                                 &session) == WALLY_OK;
  for (size_t i = 0; ok && i < num_cosigners; i++) {
    struct wally_musig_partial_sig *partial_sig = NULL;
    ok = wally_musig_partial_sign(cosigners[i].secnonce, cosigners[i].sk,
                                  EC_PRIVATE_KEY_LEN, cache, session,
                                  &partial_sig) == WALLY_OK &&
         wally_musig_partial_sig_serialize(
             partial_sig, partial_sigs + (i + 1) * WALLY_MUSIG_PARTIAL_SIG_LEN,
             WALLY_MUSIG_PARTIAL_SIG_LEN) == WALLY_OK;
    wally_musig_partial_sig_free(partial_sig);
  }
  ok =
      ok &&
      wally_musig_partial_sig_agg(partial_sigs, n * WALLY_MUSIG_PARTIAL_SIG_LEN,
                                  n, session, sig, sizeof(sig)) == WALLY_OK &&
      wally_ec_sig_verify(aggregate + 1, EC_XONLY_PUBLIC_KEY_LEN, sighash,
                          SHA256_LEN, EC_FLAG_SCHNORR, sig,
                          sizeof(sig)) == WALLY_OK;
  wally_musig_session_free(session);
  wally_musig_aggnonce_free(aggnonce);
  return ok;
}

/* The fixture's two participants aggregated, then derived along `steps`
 * (BIP-328) when the musig() has a path. */
static struct wally_musig_keyagg_cache *
fixture_key_agg(const fixture_t *f, const uint32_t *steps, size_t num_steps) {
  unsigned char participants[2 * EC_PUBLIC_KEY_LEN];
  memcpy(participants, f->ours, EC_PUBLIC_KEY_LEN);
  memcpy(participants + EC_PUBLIC_KEY_LEN, f->cosigner, EC_PUBLIC_KEY_LEN);
  return key_agg(participants, 2, steps, num_steps);
}

/* The fixture's key path signature verifies: see signature_verifies(). */
static bool key_path_verifies(fixture_t *f, cosigner_t *cosigner,
                              const uint32_t *steps, size_t num_steps) {
  unsigned char sighash[SHA256_LEN];
  struct wally_musig_keyagg_cache *cache = fixture_key_agg(f, steps, num_steps);
  bool ok = cache && tap_tweak(cache, NULL) &&
            key_path_sighash(f->psbt, sighash) &&
            signature_verifies(f->psbt, f->ours, cosigner, 1, cache, f->output,
                               NULL, sighash);
  wally_musig_keyagg_cache_free(cache);
  return ok;
}

/* Derive then aggregate: the cosigner signs with libwally's BIP-327
 * functions, every BIP-373 entry keyed by the output key as Bitcoin Core and
 * Ledger key it, and the aggregate must be a BIP-340 signature of the output
 * key. */
static void test_two_rounds(void) {
  check("derive then aggregate registers",
        register_descriptor(DERIVE_THEN_AGGREGATE));
  const uint32_t path[] = {0x80000056, 0x80000001, 0x80000000, 0, CHILD};
  unsigned char value[4 + 4 * 5];
  size_t value_len = origin(OUR_FP, path, 5, value);
  fixture_t f;
  check("PSBT builds",
        fixture(OURS "/0/3", COSIGNER "/0/3", value, value_len, true, &f) &&
            key_path_output(&f));

  musig_plan_t plan;
  check("plan has our one signature, keyed by the output key, in round 1",
        musig_psbt_plan(f.psbt, NULL, &plan) == MUSIG_PSBT_OK &&
            plan.num_slots == 1 && plan.step == MUSIG_STEP_PUB_NONCES &&
            memcmp(plan.slots[0].participant, f.ours, EC_PUBLIC_KEY_LEN) == 0 &&
            memcmp(plan.slots[0].aggregate, f.output, EC_PUBLIC_KEY_LEN) == 0 &&
            plan.slots[0].key_expression_index == 0);
  musig_plan_free(&plan);

  size_t added = 0;
  check(
      "round 1 adds our public nonce under the output key",
      sign(f.psbt, &added) == MUSIG_PSBT_OK && added == 1 &&
          has_entry(&f.psbt->inputs[0].musig2_pubnonces, f.ours, f.output) &&
          !has_entry(&f.psbt->inputs[0].musig2_pubnonces, f.ours, f.aggregate));
  check("round 1 signs nothing",
        f.psbt->inputs[0].musig2_partial_sigs.num_items == 0);
  struct wally_psbt *trimmed = psbt_trim(f.psbt);
  check("a trimmed answer keeps our public nonce",
        trimmed &&
            has_entry(&trimmed->inputs[0].musig2_pubnonces, f.ours, f.output));
  wally_psbt_free(trimmed);
  check("our participant is ours, the cosigner's is not",
        musig_psbt_is_own_participant(f.psbt, 0, f.ours) &&
            !musig_psbt_is_own_participant(f.psbt, 0, f.cosigner));
  check("waiting for the cosigner's nonce asks nothing of us",
        step_of(f.psbt) == MUSIG_STEP_NOTHING &&
            check_request(f.psbt) == MUSIG_PSBT_ERR_NOTHING);
  check("a cosigner nonce under the KeyAgg key is not the key path's",
        add_cosigner_nonce(&f, f.aggregate, NULL) &&
            step_of(f.psbt) == MUSIG_STEP_NOTHING);

  cosigner_t cosigner = {.pub = f.cosigner, .sk = f.cosigner_sk};
  check("cosigner adds its nonce under the output key",
        cosigner_nonce(f.psbt, &cosigner, f.output, NULL));
  check("every nonce in: round 2 on the held session",
        step_of(f.psbt) == MUSIG_STEP_PARTIAL_SIGS &&
            check_session(f.psbt) == MUSIG_PSBT_OK &&
            check_request(f.psbt) == MUSIG_PSBT_OK);
  check(
      "round 2 adds our partial signature under the output key",
      sign(f.psbt, &added) == MUSIG_PSBT_OK && added == 1 &&
          has_entry(&f.psbt->inputs[0].musig2_partial_sigs, f.ours, f.output));
  check("the session is consumed: no second signature",
        check_session(f.psbt) == MUSIG_PSBT_ERR_SESSION &&
            check_request(f.psbt) == MUSIG_PSBT_ERR_SESSION &&
            sign(f.psbt, &added) == MUSIG_PSBT_ERR_SESSION && added == 0);

  check("the partial signatures make a BIP-340 signature of the output key",
        key_path_verifies(&f, &cosigner, NULL, 0));
  wally_musig_secnonce_free(cosigner.secnonce);
  fixture_free(&f);

  check("PSBT without 0x1a builds",
        fixture(OURS "/0/3", COSIGNER "/0/3", value, value_len, false, &f));
  check("an input without 0x1a asks no MuSig2 signature",
        step_of(f.psbt) == MUSIG_STEP_NONE &&
            check_request(f.psbt) == MUSIG_PSBT_OK);
  fixture_free(&f);
  registry_clear();
}

/* SIGHASH_ALL: the partial signatures sign the message of the input's type,
 * the aggregator appends the type byte. */
static void test_sighash_all(void) {
  check("derive then aggregate registers",
        register_descriptor(DERIVE_THEN_AGGREGATE));
  const uint32_t path[] = {0x80000056, 0x80000001, 0x80000000, 0, CHILD};
  unsigned char value[4 + 4 * 5];
  size_t value_len = origin(OUR_FP, path, 5, value);
  fixture_t f;
  check("PSBT with SIGHASH_ALL builds",
        fixture(OURS "/0/3", COSIGNER "/0/3", value, value_len, true, &f) &&
            key_path_output(&f) &&
            wally_psbt_set_input_sighash(f.psbt, 0, WALLY_SIGHASH_ALL) ==
                WALLY_OK);
  size_t added = 0;
  cosigner_t cosigner = {.pub = f.cosigner, .sk = f.cosigner_sk};
  check("round 1, then the cosigner's nonce",
        sign(f.psbt, &added) == MUSIG_PSBT_OK && added == 1 &&
            cosigner_nonce(f.psbt, &cosigner, f.output, NULL));
  check("round 2 signs the SIGHASH_ALL message",
        sign(f.psbt, &added) == MUSIG_PSBT_OK && added == 1);
  check("the partial signatures make a signature of the SIGHASH_ALL message",
        key_path_verifies(&f, &cosigner, NULL, 0));
  wally_musig_secnonce_free(cosigner.secnonce);
  fixture_free(&f);

  check("PSBT with SIGHASH_NONE builds",
        fixture(OURS "/0/3", COSIGNER "/0/3", value, value_len, true, &f) &&
            key_path_output(&f) &&
            wally_psbt_set_input_sighash(f.psbt, 0, WALLY_SIGHASH_NONE) ==
                WALLY_OK &&
            sign(f.psbt, &added) == MUSIG_PSBT_OK &&
            add_cosigner_nonce(&f, f.output, NULL));
  check("SIGHASH_NONE is refused, as Kern refuses it for every signature",
        sign(f.psbt, &added) == MUSIG_PSBT_ERR_INVALID && added == 0);
  fixture_free(&f);
  registry_clear();
}

/* Beside silent payment outputs psbt_sign signs with SIGHASH_ALL, and keeps
 * the field on an input given a public nonce or partial signature: neither
 * carries a sighash byte, so the aggregator reads it from the PSBT. */
static void test_sighash_all_beside_silent_payments(void) {
  check("derive then aggregate registers",
        register_descriptor(DERIVE_THEN_AGGREGATE));
  const uint32_t path[] = {0x80000056, 0x80000001, 0x80000000, 0, CHILD};
  unsigned char value[4 + 4 * 5];
  size_t value_len = origin(OUR_FP, path, 5, value);
  static const unsigned char info_key[] = {PSBT_OUT_SP_V0_INFO};
  unsigned char info[2 * EC_PUBLIC_KEY_LEN] = {0};
  fixture_t f;
  check("PSBT with a silent payment output builds",
        fixture(OURS "/0/3", COSIGNER "/0/3", value, value_len, true, &f) &&
            key_path_output(&f) &&
            wally_map_add(&f.psbt->outputs[0].unknowns, info_key,
                          sizeof(info_key), info, sizeof(info)) == WALLY_OK);
  psbt_sign_policy_t policy = {0};
  size_t sighash = 0;
  check("round 1 keeps SIGHASH_ALL on the input given our public nonce",
        psbt_sign(f.psbt, true, policy, NULL) == 1 &&
            has_entry(&f.psbt->inputs[0].musig2_pubnonces, f.ours, f.output) &&
            wally_psbt_get_input_sighash(f.psbt, 0, &sighash) == WALLY_OK &&
            sighash == WALLY_SIGHASH_ALL);
  fixture_free(&f);
  registry_clear();
}

/* Aggregate then derive: our slot exists only when the BIP-328 tweaks give
 * libwally's output key for the descriptor. */
static void test_aggregate_then_derive(void) {
  check("aggregate then derive registers",
        register_descriptor(AGGREGATE_THEN_DERIVE));
  const uint32_t path[] = {0, CHILD};
  unsigned char value[4 + 4 * 2];
  fixture_t f;
  check("PSBT builds",
        fixture(OURS, COSIGNER, value, origin(SYNTHETIC_FP, path, 2, value),
                true, &f) &&
            key_path_output(&f));
  size_t added = 0;
  check("round 1 adds our public nonce under the output key",
        step_of(f.psbt) == MUSIG_STEP_PUB_NONCES &&
            sign(f.psbt, &added) == MUSIG_PSBT_OK && added == 1 &&
            has_entry(&f.psbt->inputs[0].musig2_pubnonces, f.ours, f.output));
  cosigner_t cosigner = {.pub = f.cosigner, .sk = f.cosigner_sk};
  check("cosigner nonce added",
        cosigner_nonce(f.psbt, &cosigner, f.output, NULL));
  check(
      "round 2 adds our partial signature under the output key",
      step_of(f.psbt) == MUSIG_STEP_PARTIAL_SIGS &&
          sign(f.psbt, &added) == MUSIG_PSBT_OK && added == 1 &&
          has_entry(&f.psbt->inputs[0].musig2_partial_sigs, f.ours, f.output));
  check("the partial signatures make a BIP-340 signature of the output key",
        key_path_verifies(&f, &cosigner, path, 2));
  wally_musig_secnonce_free(cosigner.secnonce);
  fixture_free(&f);
  registry_clear();
}

static bool issue_session(const unsigned char *session_id, uint8_t *ref_out,
                          unsigned char *nonce_out) {
  bnc_issuance request = {.inputs = 1, .start = 0, .end = 0};
  uint8_t fresh[BNC_SECRET_LEN];
  bool new_session = false;
  struct ext_key *key = key_at(OURS);
  memcpy(request.session_id, session_id, BNC_SESSION_ID_LEN);
  bool ok = key && nonce_cache_fresh_secret(fresh) &&
            bnc_issue(nonce_cache_signer(), &request, fresh, key->priv_key + 1,
                      key->pub_key, ref_out, &new_session, nonce_out,
                      BNC_PUBNONCE_LEN) == BNC_OK &&
            new_session;
  bip32_key_free(key);
  return ok;
}

static bool name_session(struct wally_psbt *psbt, const unsigned char *id,
                         const uint8_t *ref) {
  static const unsigned char key[1] = {BNC_PSBT_GLOBAL_NONCE_CACHE_SESSION};
  unsigned char value[BNC_SESSION_ID_LEN + BNC_SESSION_REF_LEN];
  memcpy(value, id, BNC_SESSION_ID_LEN);
  memcpy(value + BNC_SESSION_ID_LEN, ref, BNC_SESSION_REF_LEN);
  return wally_map_replace(&psbt->unknowns, key, sizeof(key), value,
                           sizeof(value)) == WALLY_OK;
}

/* Our nonce under the BIP-373 key of `aggregate`, on the key path. */
static bool set_own_nonce(fixture_t *f, const unsigned char *aggregate,
                          const unsigned char *nonce) {
  return wally_psbt_input_add_musig2_pubnonce(
             &f->psbt->inputs[0], f->ours, EC_PUBLIC_KEY_LEN, aggregate,
             EC_PUBLIC_KEY_LEN, NULL, 0, nonce, BNC_PUBNONCE_LEN) == WALLY_OK;
}

/* One round from a session issued before the PSBT existed. */
static void test_cached_session(void) {
  static const unsigned char id[BNC_SESSION_ID_LEN] = {9, 8, 7, 6};
  const uint32_t path[] = {0, CHILD};
  unsigned char value[4 + 4 * 2], nonce[BNC_PUBNONCE_LEN];
  unsigned char other_nonce[BNC_PUBNONCE_LEN];
  uint8_t ref[BNC_SESSION_REF_LEN], other_ref[BNC_SESSION_REF_LEN];
  fixture_t f;
  check("aggregate then derive registers",
        register_descriptor(AGGREGATE_THEN_DERIVE));
  check("session issued", issue_session(id, ref, nonce));
  check("PSBT builds",
        fixture(OURS, COSIGNER, value, origin(SYNTHETIC_FP, path, 2, value),
                true, &f) &&
            key_path_output(&f));
  check("cached nonce and cosigner nonce added",
        set_own_nonce(&f, f.output, nonce) &&
            add_cosigner_nonce(&f, f.output, NULL));

  memcpy(other_ref, ref, sizeof(ref));
  other_ref[0] ^= 1;
  check("a session named with another reference is refused",
        name_session(f.psbt, id, other_ref) &&
            step_of(f.psbt) == MUSIG_STEP_CACHED &&
            check_request(f.psbt) == MUSIG_PSBT_ERR_SESSION);

  memcpy(other_nonce, nonce, sizeof(other_nonce));
  other_nonce[1] ^= 1;
  check("a nonce the session does not give is refused",
        name_session(f.psbt, id, ref) &&
            set_own_nonce(&f, f.output, other_nonce) &&
            check_session(f.psbt) == MUSIG_PSBT_ERR_SESSION);

  fixture_t g;
  check("PSBT with only our nonce builds",
        fixture(OURS, COSIGNER, value, origin(SYNTHETIC_FP, path, 2, value),
                true, &g) &&
            key_path_output(&g) && name_session(g.psbt, id, ref) &&
            set_own_nonce(&g, g.output, other_nonce));
  check("a nonce the session does not give is refused before the cosigner's "
        "is looked for",
        check_session(g.psbt) == MUSIG_PSBT_ERR_SESSION &&
            check_request(g.psbt) == MUSIG_PSBT_ERR_SESSION);
  fixture_free(&g);

  check("PSBT with our nonce under the KeyAgg key builds",
        fixture(OURS, COSIGNER, value, origin(SYNTHETIC_FP, path, 2, value),
                true, &g) &&
            key_path_output(&g) && name_session(g.psbt, id, ref) &&
            set_own_nonce(&g, g.aggregate, nonce) &&
            add_cosigner_nonce(&g, g.aggregate, NULL));
  check("the KeyAgg key is not the key path's BIP-373 aggregate: refused",
        check_session(g.psbt) == MUSIG_PSBT_ERR_SESSION &&
            check_request(g.psbt) == MUSIG_PSBT_ERR_SESSION);
  fixture_free(&g);

  /* A nonce keyed by the cosigner's key as the aggregate: no slot of ours */
  check("PSBT with every nonce builds",
        fixture(OURS, COSIGNER, value, origin(SYNTHETIC_FP, path, 2, value),
                true, &g) &&
            key_path_output(&g) && name_session(g.psbt, id, ref) &&
            set_own_nonce(&g, g.output, nonce) &&
            add_cosigner_nonce(&g, g.output, NULL));
  check("the cosigner's nonce on another aggregate is not ours to refuse",
        wally_psbt_input_add_musig2_pubnonce(
            &g.psbt->inputs[0], g.cosigner, EC_PUBLIC_KEY_LEN, g.cosigner,
            EC_PUBLIC_KEY_LEN, NULL, 0, nonce, BNC_PUBNONCE_LEN) == WALLY_OK &&
            check_session(g.psbt) == MUSIG_PSBT_OK);
  check("our nonce on an aggregate no slot signs is refused",
        wally_psbt_input_add_musig2_pubnonce(
            &g.psbt->inputs[0], g.ours, EC_PUBLIC_KEY_LEN, g.cosigner,
            EC_PUBLIC_KEY_LEN, NULL, 0, nonce, BNC_PUBNONCE_LEN) == WALLY_OK &&
            check_session(g.psbt) == MUSIG_PSBT_ERR_SESSION &&
            check_request(g.psbt) == MUSIG_PSBT_ERR_SESSION);
  fixture_free(&g);

  size_t added = 0;
  check(
      "the named session signs in one round, under the output key",
      set_own_nonce(&f, f.output, nonce) &&
          check_request(f.psbt) == MUSIG_PSBT_OK &&
          sign(f.psbt, &added) == MUSIG_PSBT_OK && added == 1 &&
          has_entry(&f.psbt->inputs[0].musig2_partial_sigs, f.ours, f.output));
  check("the named session is consumed",
        check_request(f.psbt) == MUSIG_PSBT_ERR_SESSION);
  fixture_free(&f);
  registry_clear();
}

/* ---------- tapscript leaf ---------- */

/* musig() of the account keys in a leaf, beside another internal key */
#define LEAF                                                                   \
  "tr([deadbeef/86'/1'/2']%s/<0;1>/*,pk(musig([" FP                            \
  "/86'/1'/0']%s,[deadbeef/86'/1'/1']%s)/<0;1>/*))"
#define INTERNAL "m/86'/1'/2'"
#define LEAF_SCRIPT_LEN (1 + EC_XONLY_PUBLIC_KEY_LEN + 1)
#define TAPSCRIPT_LEAF_VERSION 0xc0
#define PSBT_IN_TAP_MERKLE_ROOT 0x18

static bool register_leaf_descriptor(void) {
  char ours[128], cosigner[128], internal[128];
  snprintf(descriptor_buf, sizeof(descriptor_buf), LEAF,
           xpub_at(INTERNAL, internal, sizeof(internal)),
           xpub_at(OURS, ours, sizeof(ours)),
           xpub_at(COSIGNER, cosigner, sizeof(cosigner)));
  registry_clear();
  return registry_add_from_string("l", descriptor_buf, STORAGE_FLASH, false);
}

typedef struct {
  unsigned char key[EC_PUBLIC_KEY_LEN];
  unsigned char script[LEAF_SCRIPT_LEN];
  unsigned char hash[SHA256_LEN];
} leaf_t;

/* pk(leaf key) of the descriptor's key 1 at 0/`child_num`, its BIP-341
 * control block in a one-leaf tree under key 0, and the tree's merkle root,
 * added to the PSBT's input; checks the output key. */
static bool add_leaf(struct wally_psbt *psbt, uint32_t child_num,
                     leaf_t *leaf) {
  unsigned char internal[EC_PUBLIC_KEY_LEN], output[EC_PUBLIC_KEY_LEN];
  unsigned char data[2 + LEAF_SCRIPT_LEN], control[1 + 32];
  unsigned char spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  if (!descriptor_key_at(0, child_num, internal) ||
      !descriptor_key_at(1, child_num, leaf->key) ||
      !script_at(0, child_num, spk))
    return false;
  leaf->script[0] = EC_XONLY_PUBLIC_KEY_LEN;
  memcpy(leaf->script + 1, leaf->key + 1, EC_XONLY_PUBLIC_KEY_LEN);
  leaf->script[LEAF_SCRIPT_LEN - 1] = 0xac; /* OP_CHECKSIG */
  data[0] = TAPSCRIPT_LEAF_VERSION;
  data[1] = LEAF_SCRIPT_LEN;
  memcpy(data + 2, leaf->script, LEAF_SCRIPT_LEN);
  internal[0] = 0x02;
  if (wally_bip340_tagged_hash(data, sizeof(data), "TapLeaf", leaf->hash,
                               sizeof(leaf->hash)) != WALLY_OK ||
      wally_ec_public_key_bip341_tweak(internal, sizeof(internal), leaf->hash,
                                       sizeof(leaf->hash), 0, output,
                                       sizeof(output)) != WALLY_OK ||
      memcmp(output + 1, spk + 2, 32) != 0)
    return false;
  control[0] = TAPSCRIPT_LEAF_VERSION | (output[0] == 0x03);
  memcpy(control + 1, internal + 1, 32);
  return wally_psbt_input_add_taproot_leaf_script(
             &psbt->inputs[0], control, sizeof(control), leaf->script,
             sizeof(leaf->script)) == WALLY_OK &&
         wally_map_add_integer(&psbt->inputs[0].psbt_fields,
                               PSBT_IN_TAP_MERKLE_ROOT, leaf->hash,
                               sizeof(leaf->hash)) == WALLY_OK;
}

/* The leaf's BIP-342 sighash, SIGHASH_DEFAULT. */
static bool leaf_sighash(struct wally_psbt *psbt, const leaf_t *leaf,
                         unsigned char *sighash) {
  unsigned char spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  size_t spk_len = 0;
  const uint64_t values[] = {psbt_get_input_value(psbt, 0)};
  struct wally_map scripts = {0};
  struct wally_tx *tx = psbt_tx_alloc(psbt);
  bool ok = tx && psbt_input_utxo_script(psbt, 0, spk, sizeof(spk), &spk_len) &&
            wally_map_init(1, NULL, &scripts) == WALLY_OK &&
            wally_map_add_integer(&scripts, 0, spk, spk_len) == WALLY_OK &&
            wally_tx_get_btc_taproot_signature_hash(
                tx, 0, &scripts, values, 1, leaf->script, sizeof(leaf->script),
                0, WALLY_NO_CODESEPARATOR, NULL, 0, WALLY_SIGHASH_DEFAULT, 0,
                sighash, SHA256_LEN) == WALLY_OK;
  wally_map_clear(&scripts);
  wally_tx_free(tx);
  return ok;
}

/* Two rounds on a leaf: every BIP-373 entry keyed by the key the leaf
 * pushes, as Bitcoin Core and Ledger key it, and the aggregate must be a
 * BIP-340 signature of that key, which libwally derives from the
 * descriptor. */
static void test_leaf(void) {
  check("musig() in a leaf registers", register_leaf_descriptor());
  const uint32_t path[] = {0, CHILD};
  unsigned char value[4 + 4 * 2];
  fixture_t f;
  leaf_t leaf;
  check("PSBT with the leaf builds",
        fixture(OURS, COSIGNER, value, origin(SYNTHETIC_FP, path, 2, value),
                true, &f) &&
            add_leaf(f.psbt, CHILD, &leaf));

  musig_plan_t plan;
  check("plan has our leaf signature, keyed by the leaf key, in round 1",
        musig_psbt_plan(f.psbt, NULL, &plan) == MUSIG_PSBT_OK &&
            plan.num_slots == 1 && plan.step == MUSIG_STEP_PUB_NONCES &&
            plan.slots[0].has_leaf_hash &&
            memcmp(plan.slots[0].leaf_hash, leaf.hash, SHA256_LEN) == 0 &&
            memcmp(plan.slots[0].aggregate, leaf.key, EC_PUBLIC_KEY_LEN) == 0 &&
            plan.slots[0].key_expression_index == 0);
  musig_plan_free(&plan);

  size_t added = 0;
  check("round 1 adds our leaf public nonce under the leaf key",
        sign(f.psbt, &added) == MUSIG_PSBT_OK && added == 1 &&
            entry(&f.psbt->inputs[0].musig2_pubnonces, f.ours, leaf.key,
                  leaf.hash, WALLY_MUSIG_PUBNONCE_LEN) &&
            !entry(&f.psbt->inputs[0].musig2_pubnonces, f.ours, f.aggregate,
                   leaf.hash, WALLY_MUSIG_PUBNONCE_LEN));
  check("a cosigner nonce under the KeyAgg key is not the leaf's",
        add_cosigner_nonce(&f, f.aggregate, leaf.hash) &&
            step_of(f.psbt) == MUSIG_STEP_NOTHING);

  cosigner_t cosigner = {.pub = f.cosigner, .sk = f.cosigner_sk};
  check("cosigner adds its leaf nonce under the leaf key",
        cosigner_nonce(f.psbt, &cosigner, leaf.key, leaf.hash));
  check("round 2 adds our leaf partial signature under the leaf key",
        step_of(f.psbt) == MUSIG_STEP_PARTIAL_SIGS &&
            sign(f.psbt, &added) == MUSIG_PSBT_OK && added == 1 &&
            entry(&f.psbt->inputs[0].musig2_partial_sigs, f.ours, leaf.key,
                  leaf.hash, WALLY_MUSIG_PARTIAL_SIG_LEN));

  unsigned char key[EC_PUBLIC_KEY_LEN], sighash[SHA256_LEN];
  struct wally_musig_keyagg_cache *cache = fixture_key_agg(&f, path, 2);
  check("the BIP-328 tweaks give libwally's leaf key",
        cache && wally_musig_pubkey_get(cache, key, sizeof(key)) == WALLY_OK &&
            memcmp(key, leaf.key, EC_PUBLIC_KEY_LEN) == 0);
  check("the partial signatures make a BIP-340 signature of the leaf key",
        cache && leaf_sighash(f.psbt, &leaf, sighash) &&
            signature_verifies(f.psbt, f.ours, &cosigner, 1, cache, leaf.key,
                               leaf.hash, sighash));
  wally_musig_keyagg_cache_free(cache);
  wally_musig_secnonce_free(cosigner.secnonce);
  fixture_free(&f);
  registry_clear();
}

/* ---------- nonce preparation ---------- */

static const uint32_t ACCOUNT_PATH[] = {0x80000056, 0x80000001, 0x80000000};

static nonce_cache_result_t prepare(bnc_issuance *request, bool draw,
                                    const uint32_t *path, size_t path_len,
                                    uint8_t *nonces, size_t count,
                                    nonce_cache_issued_t *issued) {
  return nonce_cache_issue(request, draw, path, path_len, nonces,
                           count * BNC_PUBNONCE_LEN, issued);
}

static void test_nonce_preparation(void) {
  bnc_issuance request = {.inputs = 2, .start = 0, .end = 2};
  uint8_t nonces[6 * BNC_PUBNONCE_LEN], chunk[2 * BNC_PUBNONCE_LEN];
  nonce_cache_issued_t issued, again;
  check("a request without session ID draws one for a new session",
        prepare(&request, true, ACCOUNT_PATH, 3, nonces, 6, &issued) ==
                NONCE_CACHE_OK &&
            issued.new_session &&
            memcmp(issued.session_id, request.session_id, BNC_SESSION_ID_LEN) ==
                0);

  bnc_issuance extend = {
      .has_session_ref = 1, .inputs = 2, .start = 2, .end = 2};
  memcpy(extend.session_id, issued.session_id, BNC_SESSION_ID_LEN);
  memcpy(extend.session_ref, issued.session_ref, BNC_SESSION_REF_LEN);
  check("a chunk of the session comes from it, positioned by index then input",
        prepare(&extend, false, ACCOUNT_PATH, 3, chunk, 2, &again) ==
                NONCE_CACHE_OK &&
            !again.new_session &&
            memcmp(again.session_ref, issued.session_ref,
                   BNC_SESSION_REF_LEN) == 0 &&
            memcmp(chunk, nonces + 4 * BNC_PUBNONCE_LEN, sizeof(chunk)) == 0);

  extend.session_ref[0] ^= 1;
  check("a reference of another session is refused",
        prepare(&extend, false, ACCOUNT_PATH, 3, chunk, 2, &again) ==
            NONCE_CACHE_ERR_SESSION);
  bnc_issuance unknown = extend;
  unknown.session_id[0] ^= 1;
  bnc_secret *secret = NULL;
  check("a reference without a held session is refused and creates none",
        prepare(&unknown, false, ACCOUNT_PATH, 3, chunk, 2, &again) ==
                NONCE_CACHE_ERR_SESSION &&
            bnc_held_session(nonce_cache_signer(), unknown.session_id, NULL,
                             &secret) == BNC_ERR_UNKNOWN_SESSION);
  check("a request without a key path is refused",
        prepare(&request, false, ACCOUNT_PATH, 0, nonces, 6, &issued) ==
            NONCE_CACHE_ERR_INVALID);
  check("a nonce buffer of another size is refused",
        prepare(&request, false, ACCOUNT_PATH, 3, nonces, 5, &issued) ==
            NONCE_CACHE_ERR_INVALID);
}

/* ---------- key path and leaf of three seeds ---------- */

/* musig() of the accounts 87'/1'/0' of three seeds on the key path, of the
 * first two in a leaf; the expected keys are the ones a Bitcoin Core or
 * Ledger coordinator keys its BIP-373 entries by at 0/7 */
#define THREE_SEEDS                                                            \
  "tr(musig([73c5da0a/87'/1'/0']tpubDCChhoz5Qdrkn7Z7KXawq6Ad6r3A4MUkCoVTqeWx"  \
  "fTkA6bHNJ3CHUEtALQdkNeixNz4446PcAmw4WKcj3mV2vb29H7sg9EPzbyCU1y2merw,[b868"  \
  "8df1/87'/1'/0']tpubDC44ZFebbFm5ZXnG5Xt8k9PpdSZXUQ4HyuU8e8u5zfutYuu8EW4MLK"  \
  "S54EFTfGYgeqt7P2jEEd1iCF5kSPi7Xrj6EZcsStCcAjPy97DSiLb,[28645006/87'/1'/0'"  \
  "]tpubDCs6kWyAq2CsViTz5YR3tKpCQ4kq2xwDmERmF5cGet45CsHAqR8wbQGRin6fzLJgCdrK"  \
  "fYts4ddyTJ7Zo4ocmG1zHK3vw71mh32wj25WmsT)/<0;1>/*,pk(musig([73c5da0a/87'/1"  \
  "'/0']tpubDCChhoz5Qdrkn7Z7KXawq6Ad6r3A4MUkCoVTqeWxfTkA6bHNJ3CHUEtALQdkNeix"  \
  "Nz4446PcAmw4WKcj3mV2vb29H7sg9EPzbyCU1y2merw,[b8688df1/87'/1'/0']tpubDC44Z"  \
  "FebbFm5ZXnG5Xt8k9PpdSZXUQ4HyuU8e8u5zfutYuu8EW4MLKS54EFTfGYgeqt7P2jEEd1iCF"  \
  "5kSPi7Xrj6EZcsStCcAjPy97DSiLb)/<0;1>/*))#dqt5r5m9"
#define SEED_B                                                                 \
  "legal winner thank year wave sausage worth useful legal winner thank "      \
  "yellow"
#define SEED_C                                                                 \
  "letter advice cage absurd amount doctor acoustic avoid letter advice cage " \
  "above"
#define THREE_SEEDS_CHILD 7

static const uint32_t ACCOUNT_87[] = {0x80000057, 0x80000001, 0x80000000};

static bool from_hex(const char *hex, unsigned char *out, size_t len) {
  size_t written = 0;
  return wally_hex_to_bytes(hex, out, len, &written) == WALLY_OK &&
         written == len;
}

/* The account 87'/1'/0' of a BIP-39 seed without passphrase. */
static struct ext_key *seed_account(const char *mnemonic) {
  unsigned char seed[BIP39_SEED_LEN_512];
  struct ext_key *root = NULL, *account = NULL;
  bool ok =
      bip39_mnemonic_to_seed512(mnemonic, NULL, seed, sizeof(seed)) ==
          WALLY_OK &&
      bip32_key_from_seed_alloc(seed, sizeof(seed), BIP32_VER_TEST_PRIVATE, 0,
                                &root) == WALLY_OK &&
      bip32_key_from_parent_path_alloc(
          root, ACCOUNT_87, 3, BIP32_FLAG_KEY_PRIVATE, &account) == WALLY_OK;
  wally_bzero(seed, sizeof(seed));
  bip32_key_free(root);
  return ok ? account : NULL;
}

/* PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS of `n` keys, in BIP-390 order, under
 * their KeyAgg key, written to `aggregate_out`. */
static bool add_participants(struct wally_psbt *psbt, const unsigned char *keys,
                             size_t n, unsigned char *aggregate_out) {
  unsigned char sorted[MAX_PARTICIPANTS * EC_PUBLIC_KEY_LEN];
  struct wally_musig_keyagg_cache *cache = key_agg(keys, n, NULL, 0);
  memcpy(sorted, keys, n * EC_PUBLIC_KEY_LEN);
  qsort(sorted, n, EC_PUBLIC_KEY_LEN, compare_keys);
  bool ok = cache &&
            wally_musig_pubkey_get(cache, aggregate_out, EC_PUBLIC_KEY_LEN) ==
                WALLY_OK &&
            wally_psbt_input_add_musig2_participant_pubkeys(
                &psbt->inputs[0], aggregate_out, EC_PUBLIC_KEY_LEN, sorted,
                n * EC_PUBLIC_KEY_LEN) == WALLY_OK;
  wally_musig_keyagg_cache_free(cache);
  return ok;
}

/* Our nonce from the prepared session under the BIP-373 key of `aggregate`
 * and `leaf_hash`, as the coordinator places it. */
static bool add_own_nonce(struct wally_psbt *psbt, const unsigned char *ours,
                          const unsigned char *aggregate,
                          const unsigned char *leaf_hash,
                          const unsigned char *nonce) {
  return wally_psbt_input_add_musig2_pubnonce(
             &psbt->inputs[0], ours, EC_PUBLIC_KEY_LEN, aggregate,
             EC_PUBLIC_KEY_LEN, leaf_hash, leaf_hash ? SHA256_LEN : 0, nonce,
             BNC_PUBNONCE_LEN) == WALLY_OK;
}

/* One round from a prepared nonce cache session on the key path and the leaf,
 * every BIP-373 entry keyed as Bitcoin Core and Ledger key it; the partial
 * signatures of the three seeds must make BIP-340 signatures of the output
 * key and of the leaf key. */
static void test_three_seeds(void) {
  unsigned char a_key[EC_PUBLIC_KEY_LEN], b_key[EC_PUBLIC_KEY_LEN];
  unsigned char c_key[EC_PUBLIC_KEY_LEN], keyagg_abc[EC_PUBLIC_KEY_LEN];
  unsigned char keyagg_ab[EC_PUBLIC_KEY_LEN], output[EC_PUBLIC_KEY_LEN];
  unsigned char spk[WALLY_SCRIPTPUBKEY_P2TR_LEN];
  unsigned char internal[EC_XONLY_PUBLIC_KEY_LEN];
  unsigned char leaf_key[EC_PUBLIC_KEY_LEN], leaf_hash[SHA256_LEN];
  check("expected keys parse",
        from_hex("024fa60842fe43fd476291703aa69974a2322e835f37c6acd4f22d4b152f1"
                 "5039b",
                 a_key, sizeof(a_key)) &&
            from_hex("0208c426b56c36540026267f37e3ca01126ac96da1e2c704836a76a7"
                     "b78dc93590",
                     b_key, sizeof(b_key)) &&
            from_hex("031fea37b0a22086455bc208edf029696ca8cdbee9a1243085f53239"
                     "b52fd2c375",
                     c_key, sizeof(c_key)) &&
            from_hex("028cbbd5f38ab6a0ec50c0888428caccc00cb660a152efd9b54fa3eb"
                     "e330eaa7bd",
                     keyagg_abc, sizeof(keyagg_abc)) &&
            from_hex("021e4240bacca55cb106a7546000c79549350df61064a51d2d6154f5"
                     "7bec0d75fb",
                     keyagg_ab, sizeof(keyagg_ab)) &&
            from_hex("02b213d1062e1202e6e390daea9ba20a0d79adcced3130979966469f"
                     "a5166c8ff1",
                     output, sizeof(output)) &&
            from_hex("5120b213d1062e1202e6e390daea9ba20a0d79adcced313097996646"
                     "9fa5166c8ff1",
                     spk, sizeof(spk)) &&
            from_hex("e7e775f5f6020d5d286b223d1f2e6d0934d635caf43f440f8276f727"
                     "7d00d567",
                     internal, sizeof(internal)) &&
            from_hex("020c5727de797ed735ac403e1a5cc96defda99935bfb8c023ea9b9c7"
                     "e5b378b365",
                     leaf_key, sizeof(leaf_key)) &&
            from_hex("e75d416537d0f55af33cf851edb7ea99749fc681c655c57f0572e53b"
                     "6cef5754",
                     leaf_hash, sizeof(leaf_hash)));

  registry_clear();
  check("the three seeds' wallet registers",
        registry_add_from_string("w", THREE_SEEDS, STORAGE_FLASH, false));
  struct ext_key *a = key_at("m/87'/1'/0'");
  struct ext_key *b = seed_account(SEED_B);
  struct ext_key *c = seed_account(SEED_C);
  check("each seed gives its participant key",
        a && b && c && memcmp(a->pub_key, a_key, EC_PUBLIC_KEY_LEN) == 0 &&
            memcmp(b->pub_key, b_key, EC_PUBLIC_KEY_LEN) == 0 &&
            memcmp(c->pub_key, c_key, EC_PUBLIC_KEY_LEN) == 0);

  unsigned char script[WALLY_SCRIPTPUBKEY_P2TR_LEN], key[EC_PUBLIC_KEY_LEN];
  check("the script at 0/7 pays the output key",
        script_at(0, THREE_SEEDS_CHILD, script) &&
            memcmp(script, spk, sizeof(spk)) == 0);
  check("the internal key is the musig() of the three, derived at 0/7",
        descriptor_key_at(0, THREE_SEEDS_CHILD, key) &&
            memcmp(key + 1, internal, sizeof(internal)) == 0);

  const uint32_t path[] = {0, THREE_SEEDS_CHILD};
  static const unsigned char aggregate_fp[4] = {0xe9, 0x56, 0xe2, 0xc2};
  unsigned char value[4 + 4 * 2], abc[3 * EC_PUBLIC_KEY_LEN];
  unsigned char computed_abc[EC_PUBLIC_KEY_LEN], computed_ab[EC_PUBLIC_KEY_LEN];
  struct wally_psbt *psbt = NULL;
  leaf_t leaf;
  memcpy(abc, a_key, EC_PUBLIC_KEY_LEN);
  memcpy(abc + EC_PUBLIC_KEY_LEN, b_key, EC_PUBLIC_KEY_LEN);
  memcpy(abc + 2 * EC_PUBLIC_KEY_LEN, c_key, EC_PUBLIC_KEY_LEN);
  check("PSBT with the key path and the leaf builds",
        spend_alloc(THREE_SEEDS_CHILD, internal, value,
                    origin(aggregate_fp, path, 2, value), &psbt) &&
            add_participants(psbt, abc, 3, computed_abc) &&
            add_participants(psbt, abc, 2, computed_ab) &&
            add_leaf(psbt, THREE_SEEDS_CHILD, &leaf));
  check("0x1a is keyed by each musig()'s KeyAgg key",
        memcmp(computed_abc, keyagg_abc, EC_PUBLIC_KEY_LEN) == 0 &&
            memcmp(computed_ab, keyagg_ab, EC_PUBLIC_KEY_LEN) == 0);
  check("the leaf pushes the musig() of the first two, derived at 0/7",
        memcmp(leaf.key, leaf_key, EC_PUBLIC_KEY_LEN) == 0 &&
            memcmp(leaf.hash, leaf_hash, SHA256_LEN) == 0);

  bnc_issuance request = {.inputs = 1, .start = 0, .end = 1};
  uint8_t nonces[2 * BNC_PUBNONCE_LEN];
  nonce_cache_issued_t issued;
  check("Nonce Preparation prepares a session of the two musig()",
        prepare(&request, true, ACCOUNT_87, 3, nonces, 2, &issued) ==
                NONCE_CACHE_OK &&
            issued.new_session);
  cosigner_t key_path[] = {{.pub = b_key, .sk = b->priv_key + 1},
                           {.pub = c_key, .sk = c->priv_key + 1}};
  cosigner_t in_leaf = {.pub = b_key, .sk = b->priv_key + 1};
  check("every nonce in, keyed by the output key and the leaf key",
        name_session(psbt, issued.session_id, issued.session_ref) &&
            add_own_nonce(psbt, a_key, output, NULL, nonces) &&
            add_own_nonce(psbt, a_key, leaf_key, leaf_hash,
                          nonces + BNC_PUBNONCE_LEN) &&
            cosigner_nonce(psbt, &key_path[0], output, NULL) &&
            cosigner_nonce(psbt, &key_path[1], output, NULL) &&
            cosigner_nonce(psbt, &in_leaf, leaf_key, leaf_hash));

  musig_plan_t plan;
  check("plan signs the key path under the output key, the leaf under its key",
        musig_psbt_plan(psbt, NULL, &plan) == MUSIG_PSBT_OK &&
            plan.step == MUSIG_STEP_CACHED && plan.num_slots == 2 &&
            !plan.slots[0].has_leaf_hash &&
            memcmp(plan.slots[0].aggregate, output, EC_PUBLIC_KEY_LEN) == 0 &&
            plan.slots[1].has_leaf_hash &&
            memcmp(plan.slots[1].aggregate, leaf_key, EC_PUBLIC_KEY_LEN) == 0 &&
            memcmp(plan.slots[1].leaf_hash, leaf_hash, SHA256_LEN) == 0);
  musig_plan_free(&plan);
  check("the session is held and gives the nonces the PSBT carries",
        check_request(psbt) == MUSIG_PSBT_OK);

  struct wally_psbt *keyagg_keyed = NULL;
  unsigned char nonce_key[2 * EC_PUBLIC_KEY_LEN];
  memcpy(nonce_key, a_key, EC_PUBLIC_KEY_LEN);
  memcpy(nonce_key + EC_PUBLIC_KEY_LEN, output, EC_PUBLIC_KEY_LEN);
  check("our key path nonce under the KeyAgg key is refused",
        wally_psbt_clone_alloc(psbt, 0, &keyagg_keyed) == WALLY_OK &&
            wally_map_remove(&keyagg_keyed->inputs[0].musig2_pubnonces,
                             nonce_key, sizeof(nonce_key)) == WALLY_OK &&
            add_own_nonce(keyagg_keyed, a_key, keyagg_abc, NULL, nonces) &&
            check_request(keyagg_keyed) == MUSIG_PSBT_ERR_SESSION);
  wally_psbt_free(keyagg_keyed);

  size_t added = 0;
  check("one round adds our two partial signatures",
        sign(psbt, &added) == MUSIG_PSBT_OK && added == 2 &&
            entry(&psbt->inputs[0].musig2_partial_sigs, a_key, output, NULL,
                  WALLY_MUSIG_PARTIAL_SIG_LEN) &&
            entry(&psbt->inputs[0].musig2_partial_sigs, a_key, leaf_key,
                  leaf_hash, WALLY_MUSIG_PARTIAL_SIG_LEN));
  check("the session is consumed",
        check_request(psbt) == MUSIG_PSBT_ERR_SESSION);

  unsigned char sighash[SHA256_LEN];
  struct wally_musig_keyagg_cache *cache = key_agg(abc, 3, path, 2);
  check("the three partial signatures make a signature of the output key",
        cache && tap_tweak(cache, leaf_hash) &&
            key_path_sighash(psbt, sighash) &&
            signature_verifies(psbt, a_key, key_path, 2, cache, output, NULL,
                               sighash));
  wally_musig_keyagg_cache_free(cache);
  cache = key_agg(abc, 2, path, 2);
  check("the two partial signatures make a signature of the leaf key",
        cache && leaf_sighash(psbt, &leaf, sighash) &&
            signature_verifies(psbt, a_key, &in_leaf, 1, cache, leaf_key,
                               leaf_hash, sighash));
  wally_musig_keyagg_cache_free(cache);

  wally_musig_secnonce_free(key_path[0].secnonce);
  wally_musig_secnonce_free(key_path[1].secnonce);
  wally_musig_secnonce_free(in_leaf.secnonce);
  wally_psbt_free(psbt);
  bip32_key_free(a);
  bip32_key_free(b);
  bip32_key_free(c);
  registry_clear();
}

static void test_participant_path(void) {
  const uint32_t cosigner[] = {0x80000056, 0x80000001, 0x80000001};
  const uint32_t child[] = {0x80000056, 0x80000001, 0x80000000, 0, CHILD};
  check("aggregate then derive registers",
        register_descriptor(AGGREGATE_THEN_DERIVE));
  const struct wally_descriptor *desc = registry_get(0)->desc;
  check("our account key is a participant",
        musig_psbt_is_participant_path(desc, ACCOUNT_PATH, 3));
  check("the cosigner's account key is not ours",
        !musig_psbt_is_participant_path(desc, cosigner, 3));
  check("a key derived under our participant is not one",
        !musig_psbt_is_participant_path(desc, child, 5));

  check("derive then aggregate registers",
        register_descriptor(DERIVE_THEN_AGGREGATE));
  desc = registry_get(0)->desc;
  check("our key at 0/3 is a participant",
        musig_psbt_is_participant_path(desc, child, 5));
  check("our account key alone is not",
        !musig_psbt_is_participant_path(desc, ACCOUNT_PATH, 3));

  const uint32_t recovery[] = {0x80000056, 0x80000001, 0x80000000, 3, CHILD};
  check("derive then aggregate on <2;3> registers",
        register_descriptor(DERIVE_THEN_AGGREGATE_RECOVERY));
  desc = registry_get(0)->desc;
  check("our key at 3/3 of <2;3> is a participant",
        musig_psbt_is_participant_path(desc, recovery, 5));
  check("our key at 0/3 is not one of <2;3>",
        !musig_psbt_is_participant_path(desc, child, 5));
  registry_clear();
}

int main(void) {
  char dir[] = "/tmp/kern_musig_psbt_XXXXXX";
  if (!mkdtemp(dir)) {
    perror("mkdtemp");
    return 1;
  }
  sim_nvs_set_data_dir(dir);
  printf("=== musig_psbt tests ===\n\n");
  check("test mnemonic loads on testnet",
        key_load_from_mnemonic(TEST_MNEMONIC, "", true) &&
            wallet_init(WALLET_NETWORK_TESTNET));
  test_claim();
  test_two_rounds();
  test_sighash_all();
  test_sighash_all_beside_silent_payments();
  test_aggregate_then_derive();
  test_leaf();
  test_cached_session();
  test_nonce_preparation();
  test_three_seeds();
  test_participant_path();
  registry_clear();
  key_unload();
  wallet_cleanup();
  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
