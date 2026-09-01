/*
 * Descriptor validator tests (core/descriptor_validator.c).
 *
 * Runs against the real key, wallet and registry modules with the BIP39 test
 * mnemonic loaded, so fingerprint and xpub checks exercise real derivation.
 * Descriptors are assembled from the wallet's own xpubs rather than pasted in,
 * which keeps the fixtures independent of the derivation path under test.
 * The confirmation callbacks are captured and fired by hand to cover the
 * asynchronous flow, including the stale-callback generation guard.
 */

#include "../descriptor_validator.h"
#include "../key.h"
#include "../registry.h"
#include "../storage.h"
#include "../wallet.h"
#include "esp_err.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wally_bip32.h>
#include <wally_core.h>

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

static int storage_saves;

esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  bool encrypted) {
  (void)loc;
  (void)id;
  (void)data;
  (void)len;
  (void)encrypted;
  storage_saves++;
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
                                  bool *encrypted_out) {
  (void)loc;
  (void)filename;
  *data_out = NULL;
  *len_out = 0;
  *encrypted_out = false;
  return -1;
}

void storage_free_file_list(char **files, int count) {
  (void)files;
  (void)count;
}

/* ---------- callback capture ---------- */

static const char *TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";
#define FP "73c5da0a"
#define FP_UPPER "73C5DA0A"
/* x coordinate of G: a valid x-only key that is not a NUMS point */
#define XONLY_G                                                                \
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
#define NUMS_H                                                                 \
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

static int done_calls;
static descriptor_validation_result_t done_result;
static void *done_user_data;

static int info_calls;
static descriptor_info_t info_seen;
static void (*info_proceed)(bool, void *);
static bool info_auto;
static bool info_answer;

static int warn_calls;
static char warn_msg[256];
static void (*warn_proceed)(bool, void *);
static bool warn_auto;
static bool warn_answer;

static void capture_reset(void) {
  done_calls = 0;
  done_result = (descriptor_validation_result_t)-1;
  done_user_data = NULL;
  info_calls = 0;
  memset(&info_seen, 0, sizeof(info_seen));
  info_proceed = NULL;
  info_auto = true;
  info_answer = true;
  warn_calls = 0;
  warn_msg[0] = '\0';
  warn_proceed = NULL;
  warn_auto = true;
  warn_answer = true;
}

static void done_cb(descriptor_validation_result_t result, void *user_data) {
  done_calls++;
  done_result = result;
  done_user_data = user_data;
}

static void info_cb(const descriptor_info_t *info,
                    void (*proceed)(bool, void *)) {
  info_calls++;
  info_seen = *info;
  if (info_auto)
    proceed(info_answer, NULL);
  else
    info_proceed = proceed;
}

static void warn_cb(const char *message, void (*proceed)(bool, void *)) {
  warn_calls++;
  snprintf(warn_msg, sizeof(warn_msg), "%s", message);
  if (warn_auto)
    proceed(warn_answer, NULL);
  else
    warn_proceed = proceed;
}

static int marker;

static descriptor_validation_result_t run(const char *desc) {
  capture_reset();
  descriptor_validate_and_load(desc, done_cb, warn_cb, info_cb, NULL, &marker);
  return done_result;
}

static descriptor_validation_result_t run_watch(const char *desc,
                                                wallet_network_t net) {
  capture_reset();
  descriptor_validate_and_load_watch_only(desc, net, done_cb, info_cb, &marker);
  return done_result;
}

/* ---------- fixtures ---------- */

static char xpub_buf[16][120];
static int xpub_next;

static const char *xpub_at(const char *path) {
  char *xpub = NULL;
  if (!key_get_xpub(path, &xpub))
    return "";
  char *slot = xpub_buf[xpub_next++ % 16];
  snprintf(slot, sizeof(xpub_buf[0]), "%s", xpub);
  wally_free_string(xpub);
  return slot;
}

/* Captured while a key is loaded, for the keyless watch-only stage. */
static char X84_0[120], X84_1[120], X86_0[120], X86_1[120];

static char desc_buf[4][4096];
static int desc_next;

static const char *descf(const char *fmt, ...) {
  char *slot = desc_buf[desc_next++ % 4];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(slot, sizeof(desc_buf[0]), fmt, ap);
  va_end(ap);
  return slot;
}

static const char *wpkh84(void) {
  return descf("wpkh([" FP "/84'/0'/0']%s/0/*)", xpub_at("m/84'/0'/0'"));
}

static bool registry_has_label(const char *label) {
  for (size_t i = 0; i < registry_count(); i++)
    if (strcmp(registry_get(i)->label, label) == 0)
      return true;
  return false;
}

/* ---------- tests ---------- */

static void test_preconditions(void) {
  key_unload();
  wallet_cleanup();
  check("no wallet key: internal error",
        run(wpkh84()) == VALIDATION_INTERNAL_ERROR);
  check("no wallet key: no dialogs", info_calls == 0 && warn_calls == 0);

  bool loaded = key_load_from_mnemonic(TEST_MNEMONIC, "", false);
  check("test mnemonic loads", loaded);
  check("wallet initialises", wallet_init(WALLET_NETWORK_MAINNET));
  registry_clear();

  char fp_hex[9];
  check("test key fingerprint is " FP,
        key_get_fingerprint_hex(fp_hex) && strcasecmp(fp_hex, FP) == 0);
  snprintf(X84_0, sizeof(X84_0), "%s", xpub_at("m/84'/0'/0'"));
  snprintf(X84_1, sizeof(X84_1), "%s", xpub_at("m/84'/0'/1'"));
  snprintf(X86_0, sizeof(X86_0), "%s", xpub_at("m/86'/0'/0'"));
  snprintf(X86_1, sizeof(X86_1), "%s", xpub_at("m/86'/0'/1'"));
  check("BIP84 account xpub matches the reference vector",
        strcmp(xpub_at("m/84'/0'/0'"),
               "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEb"
               "vqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V") == 0);

  check("NULL descriptor: internal error",
        run(NULL) == VALIDATION_INTERNAL_ERROR && done_user_data == &marker);
  capture_reset();
  descriptor_validate_and_load(wpkh84(), NULL, warn_cb, info_cb, NULL, NULL);
  check("NULL completion callback tolerated", info_calls == 0);
  registry_clear();
}

static void test_static_gates(void) {
  registry_clear();
  const char *upper =
      descf("wpkh([" FP "/84H/0H/0H]%s/0/*)", xpub_at("m/84'/0'/0'"));
  check("uppercase H hardened marker rejected",
        run(upper) == VALIDATION_INVALID_HARDENED_NOTATION);
  check("hardened notation rejection is synchronous and silent",
        done_calls == 1 && info_calls == 0);

  check("garbage rejected as parse error",
        run("wpkh(not a key)") == VALIDATION_PARSE_ERROR);
  check("empty string rejected as parse error",
        run("") == VALIDATION_PARSE_ERROR);

  const char *lower_h =
      descf("wpkh([" FP "/84h/0h/0h]%s/0/*)", xpub_at("m/84'/0'/0'"));
  check("lowercase h hardened marker accepted",
        run(lower_h) == VALIDATION_SUCCESS);
  registry_clear();

  const char *bare_ms = descf("and_v(v:pk([" FP "/84'/0'/0']%s/0/*),older(10))",
                              xpub_at("m/84'/0'/0'"));
  check("bare miniscript rejected",
        run(bare_ms) == VALIDATION_UNSUPPORTED_MINISCRIPT);

  const char *sh_wsh_ms =
      descf("sh(wsh(and_v(v:pk([" FP "/49'/0'/0']%s/0/*),older(10))))",
            xpub_at("m/49'/0'/0'"));
  check("sh(wsh(miniscript)) rejected",
        run(sh_wsh_ms) == VALIDATION_UNSUPPORTED_MINISCRIPT);

  char big[4096];
  size_t n = snprintf(big, sizeof(big), "wsh(sortedmulti(1");
  for (int i = 0; i < 16; i++) {
    char path[32];
    snprintf(path, sizeof(path), "m/48'/0'/%d'/2'", i);
    n += snprintf(big + n, sizeof(big) - n, ",[%s/48'/0'/%d'/2']%s/0/*",
                  i == 0 ? FP : "deadbeef", i, xpub_at(path));
  }
  snprintf(big + n, sizeof(big) - n, "))");
  descriptor_validation_result_t r = run(big);
  check("sixteen-key multisig rejected as unsupported script",
        r == VALIDATION_UNSUPPORTED_SCRIPT);
  check("static rejections never reach the dialogs",
        info_calls == 0 && warn_calls == 0 && registry_count() == 0);
}

static void test_key_matching(void) {
  registry_clear();
  const char *foreign =
      descf("wpkh([00000000/84'/0'/0']%s/0/*)", xpub_at("m/84'/0'/0'"));
  check("fingerprint absent from descriptor",
        run(foreign) == VALIDATION_FINGERPRINT_NOT_FOUND);

  const char *wrong_xpub =
      descf("wpkh([" FP "/84'/0'/0']%s/0/*)", xpub_at("m/84'/0'/1'"));
  check("fingerprint matches but xpub differs",
        run(wrong_xpub) == VALIDATION_XPUB_MISMATCH);
  check("xpub mismatch reached no dialog", info_calls == 0);

  const char *wrong_path =
      descf("wpkh([" FP "/84'/0'/1']%s/0/*)", xpub_at("m/84'/0'/0'"));
  check("origin path not matching xpub rejected",
        run(wrong_path) == VALIDATION_XPUB_MISMATCH);
  check("nothing registered after rejections", registry_count() == 0);
}

static void test_single_sig_success(void) {
  registry_clear();
  check("single-sig wpkh accepted", run(wpkh84()) == VALIDATION_SUCCESS);
  check("completion carries user data", done_user_data == &marker);
  check("info dialog shown once, no warning",
        info_calls == 1 && warn_calls == 0);
  check("info: single key, not multisig, not miniscript",
        info_seen.num_keys == 1 && !info_seen.is_multisig &&
            !info_seen.is_miniscript && info_seen.threshold == 0);
  check("info: fingerprint upper-case hex",
        strcmp(info_seen.keys[0].fingerprint_hex, FP_UPPER) == 0);
  check("info: derivation path",
        strcmp(info_seen.keys[0].derivation, "m/84'/0'/0'") == 0);
  check("info: xpub",
        strcmp(info_seen.keys[0].xpub, xpub_at("m/84'/0'/0'")) == 0);
  check("info: not taproot", info_seen.tr_keypath == TR_KEYPATH_NONE);
  check("registered once in the session", registry_count() == 1);
  check("session label is Single-sig", registry_has_label("Single-sig"));
  check("session id derives from the checksum",
        strncmp(registry_get(0)->id, "desc_", 5) == 0 &&
            strlen(registry_get(0)->id) == 13);
  check("session entry is not persisted",
        !registry_get(0)->persisted && storage_saves == 0);

  registry_clear();
  capture_reset();
  info_answer = false;
  descriptor_validate_and_load(wpkh84(), done_cb, warn_cb, info_cb, NULL, NULL);
  check("declining the info dialog", done_result == VALIDATION_USER_DECLINED);
  check("declined descriptor not registered", registry_count() == 0);

  capture_reset();
  descriptor_validate_and_load(wpkh84(), done_cb, warn_cb, NULL, NULL, NULL);
  check("NULL info callback auto-confirms",
        done_result == VALIDATION_SUCCESS && registry_count() == 1);

  registry_clear();
  const char *pkh =
      descf("pkh([" FP "/44'/0'/0']%s/0/*)", xpub_at("m/44'/0'/0'"));
  check("legacy pkh accepted", run(pkh) == VALIDATION_SUCCESS);
  const char *sh_wpkh =
      descf("sh(wpkh([" FP "/49'/0'/0']%s/0/*))", xpub_at("m/49'/0'/0'"));
  check("nested sh(wpkh) accepted", run(sh_wpkh) == VALIDATION_SUCCESS);
  const char *tr86 =
      descf("tr([" FP "/86'/0'/0']%s/0/*)", xpub_at("m/86'/0'/0'"));
  check("BIP86 tr accepted", run(tr86) == VALIDATION_SUCCESS);
  check("BIP86 key-path is ours", info_seen.tr_keypath == TR_KEYPATH_OURS);
  check("three descriptors registered", registry_count() == 3);
}

static void test_purpose_binding_warning(void) {
  registry_clear();
  const char *mixed =
      descf("wpkh([" FP "/44'/0'/0']%s/0/*)", xpub_at("m/44'/0'/0'"));

  capture_reset();
  warn_auto = false;
  info_auto = false;
  descriptor_validate_and_load(mixed, done_cb, warn_cb, info_cb, NULL, NULL);
  check("purpose/script mismatch raises the warning first",
        warn_calls == 1 && info_calls == 0 && done_calls == 0);
  check("warning names the purpose and the script",
        strstr(warn_msg, "purpose-44") && strstr(warn_msg, "wpkh"));
  warn_proceed(true, NULL);
  check("accepting the warning shows the info dialog",
        info_calls == 1 && done_calls == 0);
  info_proceed(true, NULL);
  check("accepting both loads the descriptor",
        done_result == VALIDATION_SUCCESS && registry_count() == 1);

  registry_clear();
  capture_reset();
  warn_answer = false;
  descriptor_validate_and_load(mixed, done_cb, warn_cb, info_cb, NULL, NULL);
  check("declining the warning stops the flow",
        done_result == VALIDATION_USER_DECLINED && info_calls == 0 &&
            registry_count() == 0);

  capture_reset();
  descriptor_validate_and_load(mixed, done_cb, NULL, info_cb, NULL, NULL);
  check("NULL warning callback auto-declines",
        done_result == VALIDATION_USER_DECLINED && info_calls == 0);

  const char *sh_wsh_84 =
      descf("sh(wpkh([" FP "/84'/0'/0']%s/0/*))", xpub_at("m/84'/0'/0'"));
  capture_reset();
  warn_auto = false;
  descriptor_validate_and_load(sh_wsh_84, done_cb, warn_cb, info_cb, NULL,
                               NULL);
  check("purpose 84 inside sh(wpkh) warns with the wrapper name",
        warn_calls == 1 && strstr(warn_msg, "purpose-84") &&
            strstr(warn_msg, "sh(wpkh)"));
  warn_proceed(false, NULL);
  check("conventional descriptor never warns",
        run(wpkh84()) == VALIDATION_SUCCESS && warn_calls == 0);
  registry_clear();
}

static void test_multisig_and_miniscript(void) {
  registry_clear();
  const char *a = xpub_at("m/48'/0'/0'/2'");
  const char *b = xpub_at("m/48'/0'/1'/2'");
  const char *c = xpub_at("m/48'/0'/2'/2'");

  const char *ms2of3 = descf("wsh(sortedmulti(2,[" FP "/48'/0'/0'/2']%s/0/*,"
                             "[deadbeef/48'/0'/1'/2']%s/0/*,%s/0/*))",
                             a, b, c);
  check("2-of-3 sortedmulti accepted", run(ms2of3) == VALIDATION_SUCCESS);
  check("info: multisig 2 of 3",
        info_seen.is_multisig && !info_seen.is_miniscript &&
            info_seen.threshold == 2 && info_seen.num_keys == 3);
  check("info: cosigner fingerprint reported",
        strcmp(info_seen.keys[1].fingerprint_hex, "DEADBEEF") == 0 &&
            strcmp(info_seen.keys[1].derivation, "m/48'/0'/1'/2'") == 0);
  check("info: originless key reported as N/A",
        strcmp(info_seen.keys[2].fingerprint_hex, "N/A") == 0 &&
            strcmp(info_seen.keys[2].derivation, "N/A") == 0 &&
            strcmp(info_seen.keys[2].xpub, c) == 0);
  check("session label Multisig (2 of 3)",
        registry_has_label("Multisig (2 of 3)"));

  const char *ms_ours_last = descf("wsh(multi(1,[deadbeef/48'/0'/1'/2']%s/0/*,"
                                   "[" FP "/48'/0'/0'/2']%s/0/*))",
                                   b, a);
  check("our key found at a later index",
        run(ms_ours_last) == VALIDATION_SUCCESS);

  const char *msc1 = descf("wsh(and_v(v:pk([" FP "/48'/0'/0'/2']%s/0/*),"
                           "older(144)))",
                           a);
  check("wsh miniscript accepted", run(msc1) == VALIDATION_SUCCESS);
  check("info: miniscript with one key", info_seen.is_miniscript &&
                                             !info_seen.is_multisig &&
                                             info_seen.num_keys == 1);
  check("info: policy string rendered",
        strstr(info_seen.policy, "older(144)") &&
            strstr(info_seen.policy, "pk(A)"));
  check("session label Miniscript (1 key)",
        registry_has_label("Miniscript (1 key)"));

  const char *msc2 = descf("wsh(or_d(pk([" FP "/48'/0'/0'/2']%s/0/*),"
                           "and_v(v:pk([deadbeef/48'/0'/1'/2']%s/0/*),"
                           "older(144))))",
                           a, b);
  check("two-key miniscript accepted", run(msc2) == VALIDATION_SUCCESS);
  check("session label Miniscript (2 keys)",
        registry_has_label("Miniscript (2 keys)"));
  check("four session entries", registry_count() == 4);
  registry_clear();
}

static void test_taproot_keypath(void) {
  registry_clear();
  const char *ours = xpub_at("m/86'/0'/0'");
  const char *other = xpub_at("m/86'/0'/1'");

  const char *bare_internal =
      descf("tr(" XONLY_G ",pk([" FP "/86'/0'/0']%s/0/*))", ours);
  check("script tree with bare non-NUMS internal key rejected",
        run(bare_internal) == VALIDATION_TR_INTERNAL_NOT_UNSPENDABLE);
  check("taproot rejection is silent", info_calls == 0);

  const char *nums_internal =
      descf("tr(" NUMS_H ",pk([" FP "/86'/0'/0']%s/0/*))", ours);
  check("script tree with NUMS internal key accepted",
        run(nums_internal) == VALIDATION_SUCCESS);
  check("info: key-path classified NUMS",
        info_seen.tr_keypath == TR_KEYPATH_NUMS);

  const char *nums_compressed =
      descf("tr(02" NUMS_H ",pk([" FP "/86'/0'/0']%s/0/*))", ours);
  check("compressed NUMS form accepted",
        run(nums_compressed) == VALIDATION_SUCCESS &&
            info_seen.tr_keypath == TR_KEYPATH_NUMS);

  const char *external_internal =
      descf("tr([deadbeef/86'/0'/1']%s/0/*,pk([" FP "/86'/0'/0']%s/0/*))",
            other, ours);
  check("origin-bearing external internal key accepted",
        run(external_internal) == VALIDATION_SUCCESS);
  check("info: key-path classified external",
        info_seen.tr_keypath == TR_KEYPATH_EXTERNAL);

  const char *ours_internal =
      descf("tr([" FP "/86'/0'/0']%s/0/*,pk([deadbeef/86'/0'/1']%s/0/*))", ours,
            other);
  check("our key as internal with a tree accepted",
        run(ours_internal) == VALIDATION_SUCCESS &&
            info_seen.tr_keypath == TR_KEYPATH_OURS);

  const char *multi_a =
      descf("tr(" NUMS_H ",multi_a(2,[" FP "/86'/0'/0']%s/0/*,"
            "[deadbeef/86'/0'/1']%s/0/*))",
            ours, other);
  check("tr multi_a leaf accepted", run(multi_a) == VALIDATION_SUCCESS);
  registry_clear();
}

static void test_network(void) {
  registry_clear();
  key_unload();
  wallet_cleanup();
  check("reload key as testnet",
        key_load_from_mnemonic(TEST_MNEMONIC, "", true));
  char tpub[120];
  snprintf(tpub, sizeof(tpub), "%s", xpub_at("m/84'/1'/0'"));
  check("testnet key yields a tpub", strncmp(tpub, "tpub", 4) == 0);
  key_unload();
  check("reload key as mainnet",
        key_load_from_mnemonic(TEST_MNEMONIC, "", false));
  check("wallet re-initialises", wallet_init(WALLET_NETWORK_MAINNET));

  const char *testnet_desc = descf("wpkh([" FP "/84'/1'/0']%s/0/*)", tpub);
  check("tpub descriptor on a mainnet wallet is a network mismatch",
        run(testnet_desc) == VALIDATION_NETWORK_MISMATCH);

  wallet_network_t net = WALLET_NETWORK_MAINNET;
  check("infer network: xpub is mainnet",
        descriptor_infer_network(wpkh84(), &net) &&
            net == WALLET_NETWORK_MAINNET);
  check("infer network: tpub is testnet",
        descriptor_infer_network(testnet_desc, &net) &&
            net == WALLET_NETWORK_TESTNET);
  check("infer network: garbage fails",
        !descriptor_infer_network("wpkh(nope)", &net));
  check("infer network: NULL args fail",
        !descriptor_infer_network(NULL, &net) &&
            !descriptor_infer_network(wpkh84(), NULL));
}

static void test_dedup(void) {
  registry_clear();
  check("first load succeeds", run(wpkh84()) == VALIDATION_SUCCESS);
  char first_id[REGISTRY_ID_MAX_LEN];
  snprintf(first_id, sizeof(first_id), "%s", registry_get(0)->id);
  char dup_id[REGISTRY_ID_MAX_LEN];
  check("no duplicate id pending after a success",
        !descriptor_validator_get_duplicate_id(dup_id, sizeof(dup_id)));

  check("second load of the same descriptor is a duplicate",
        run(wpkh84()) == VALIDATION_DUPLICATE);
  check("duplicate is silent", info_calls == 0);
  check("duplicate id names the existing entry",
        descriptor_validator_get_duplicate_id(dup_id, sizeof(dup_id)) &&
            strcmp(dup_id, first_id) == 0);
  check("duplicate id refuses a short buffer",
        !descriptor_validator_get_duplicate_id(dup_id, 4));
  check("duplicate id refuses NULL",
        !descriptor_validator_get_duplicate_id(NULL, sizeof(dup_id)));

  const char *h_variant =
      descf("wpkh([" FP "/84h/0h/0h]%s/0/*)", xpub_at("m/84'/0'/0'"));
  check("h-notation variant is the same descriptor",
        run(h_variant) == VALIDATION_DUPLICATE);
  check("still exactly one entry", registry_count() == 1);

  const char *other =
      descf("wpkh([" FP "/84'/0'/1']%s/0/*)", xpub_at("m/84'/0'/1'"));
  check("different account is not a duplicate",
        run(other) == VALIDATION_SUCCESS && registry_count() == 2);
  check("distinct ids", strcmp(registry_get(0)->id, registry_get(1)->id) != 0);
  check("duplicate id cleared by the next validation",
        !descriptor_validator_get_duplicate_id(dup_id, sizeof(dup_id)));

  registry_clear();
  check("cleared session accepts the descriptor again",
        run(wpkh84()) == VALIDATION_SUCCESS);
  registry_clear();
}

static void test_generation_guard(void) {
  registry_clear();
  capture_reset();
  info_auto = false;
  descriptor_validate_and_load(wpkh84(), done_cb, warn_cb, info_cb, NULL, NULL);
  void (*stale_proceed)(bool, void *) = info_proceed;
  check("first flow waits on the info dialog",
        info_calls == 1 && done_calls == 0 && stale_proceed != NULL);

  const char *other =
      descf("wpkh([" FP "/84'/0'/1']%s/0/*)", xpub_at("m/84'/0'/1'"));
  capture_reset();
  descriptor_validate_and_load(other, done_cb, warn_cb, info_cb, NULL, NULL);
  check("second flow completes while the first is abandoned",
        done_calls == 1 && done_result == VALIDATION_SUCCESS &&
            registry_count() == 1);

  stale_proceed(true, NULL);
  check("stale confirmation from the abandoned flow is ignored",
        done_calls == 1 && registry_count() == 1);
  char dup[REGISTRY_ID_MAX_LEN];
  check("abandoned descriptor was never registered",
        !registry_session_has_duplicate(wpkh84(), dup, sizeof(dup)));

  capture_reset();
  info_auto = false;
  descriptor_validate_and_load(wpkh84(), done_cb, warn_cb, info_cb, NULL, NULL);
  void (*live_proceed)(bool, void *) = info_proceed;
  live_proceed(true, NULL);
  check("live confirmation completes its flow",
        done_calls == 1 && done_result == VALIDATION_SUCCESS &&
            registry_count() == 2);
  live_proceed(true, NULL);
  check("repeated confirmation is a no-op",
        done_calls == 1 && registry_count() == 2);
  registry_clear();

  capture_reset();
  warn_auto = false;
  const char *mixed =
      descf("wpkh([" FP "/44'/0'/0']%s/0/*)", xpub_at("m/44'/0'/0'"));
  descriptor_validate_and_load(mixed, done_cb, warn_cb, info_cb, NULL, NULL);
  void (*stale_warn)(bool, void *) = warn_proceed;
  check("warning flow waits", warn_calls == 1 && done_calls == 0);
  capture_reset();
  descriptor_validate_and_load(wpkh84(), done_cb, warn_cb, info_cb, NULL, NULL);
  check("new flow completes while a warning was pending",
        done_result == VALIDATION_SUCCESS);
  stale_warn(true, NULL);
  check("stale warning confirmation is ignored",
        done_calls == 1 && registry_count() == 1);
  registry_clear();
}

static void test_watch_only(void) {
  registry_clear();
  key_unload();
  wallet_cleanup();
  wallet_set_watch_only(WALLET_NETWORK_MAINNET);

  const char *foreign = descf("wpkh([deadbeef/84'/0'/0']%s/0/*)", X84_0);
  check("keyed validation without a key is an internal error",
        run(foreign) == VALIDATION_INTERNAL_ERROR);

  check("watch-only loads a foreign descriptor",
        run_watch(foreign, WALLET_NETWORK_MAINNET) == VALIDATION_SUCCESS);
  check("watch-only info dialog shown", info_calls == 1);
  check("watch-only info: foreign fingerprint reported",
        strcmp(info_seen.keys[0].fingerprint_hex, "DEADBEEF") == 0);
  check("watch-only entry registered", registry_count() == 1);
  check("watch-only entry labelled Single-sig",
        registry_has_label("Single-sig"));

  check("watch-only dedup",
        run_watch(foreign, WALLET_NETWORK_MAINNET) == VALIDATION_DUPLICATE);

  capture_reset();
  info_answer = false;
  descriptor_validate_and_load_watch_only(
      descf("wpkh([deadbeef/84'/0'/1']%s/0/*)", X84_1), WALLET_NETWORK_MAINNET,
      done_cb, info_cb, NULL);
  check("watch-only decline",
        done_result == VALIDATION_USER_DECLINED && registry_count() == 1);

  const char *tr_ext =
      descf("tr([deadbeef/86'/0'/1']%s/0/*,pk([cafebabe/86'/0'/0']%s/0/*))",
            X86_1, X86_0);
  check("watch-only cannot classify an external key-path",
        run_watch(tr_ext, WALLET_NETWORK_MAINNET) == VALIDATION_SUCCESS &&
            info_seen.tr_keypath == TR_KEYPATH_NONE);

  const char *tr_nums =
      descf("tr(" NUMS_H ",pk([cafebabe/86'/0'/0']%s/0/*))", X86_0);
  check("watch-only still recognises a NUMS key-path",
        run_watch(tr_nums, WALLET_NETWORK_MAINNET) == VALIDATION_SUCCESS &&
            info_seen.tr_keypath == TR_KEYPATH_NUMS);

  const char *tr_bare =
      descf("tr(" XONLY_G ",pk([cafebabe/86'/0'/0']%s/0/*))", X86_0);
  check("watch-only keeps the structural taproot gate",
        run_watch(tr_bare, WALLET_NETWORK_MAINNET) ==
            VALIDATION_TR_INTERNAL_NOT_UNSPENDABLE);

  check("watch-only hardened notation gate",
        run_watch(descf("wpkh([deadbeef/84H/0H/0H]%s/0/*)", X84_0),
                  WALLET_NETWORK_MAINNET) ==
            VALIDATION_INVALID_HARDENED_NOTATION);

  wallet_clear_watch_only();
  check("clearing watch-only empties the session", registry_count() == 0);
}

int main(void) {
  printf("=== descriptor_validator tests ===\n\n");

  test_preconditions();
  test_static_gates();
  test_key_matching();
  test_single_sig_success();
  test_purpose_binding_warning();
  test_multisig_and_miniscript();
  test_taproot_keypath();
  test_network();
  test_dedup();
  test_generation_guard();
  test_watch_only();

  key_unload();
  wallet_cleanup();
  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
