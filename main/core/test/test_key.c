/*
 * Master key tests (core/key.c).
 *
 * Uses the BIP39 test mnemonic and cross-checks derivations against libwally
 * called directly, so the module's path handling, network selection and
 * passphrase plumbing are verified independently of its own code paths.
 */

#include "../../utils/secure_mem.h"
#include "../key.h"
#include "kern_wally.h"
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>

static int tests_run = 0;
static int tests_failed = 0;

/* Observe the tokenized duplicate while it is still allocated. This tests
 * key.c's explicit wipe independently of firmware's global release policy. */
static int fail_after = -1;
static bool probe_other_thread, other_thread_allocated;
static void *public_allocation_thread(void *unused) {
  (void)unused;
  void *p = wally_malloc(4096);
  other_thread_allocated = p != NULL;
  wally_free(p);
  return NULL;
}
static bool deny_secret_allocation(void) {
  if (fail_after < 0)
    return false;
  if (fail_after == 0)
    return true;
  --fail_after;
  return false;
}
void *__real_kern_secret_alloc(size_t size);
void *__wrap_kern_secret_alloc(size_t size) {
  if (probe_other_thread) {
    probe_other_thread = false;
    pthread_t thread;
    if (pthread_create(&thread, NULL, public_allocation_thread, NULL) != 0)
      abort();
    pthread_join(thread, NULL);
  }
  return deny_secret_allocation() ? NULL : __real_kern_secret_alloc(size);
}
static bool track_duplicate, duplicate_wiped;
static char *tracked_duplicate;
static size_t tracked_size;
char *__real_kern_secret_strdup(const char *s);
void __real_free(void *p);
char *__wrap_kern_secret_strdup(const char *s) {
  if (deny_secret_allocation())
    return NULL;
  char *p = __real_kern_secret_strdup(s);
  if (track_duplicate && !tracked_duplicate) {
    tracked_duplicate = p;
    tracked_size = strlen(s) + 1;
  }
  return p;
}
void __wrap_free(void *p) {
  if (p && p == tracked_duplicate) {
    duplicate_wiped = true;
    for (size_t i = 0; i < tracked_size; ++i)
      if (((unsigned char *)p)[i])
        duplicate_wiped = false;
    tracked_duplicate = NULL;
    track_duplicate = false;
  }
  __real_free(p);
}

static void check(const char *name, bool ok) {
  tests_run++;
  if (!ok)
    tests_failed++;
  printf("Testing: %s... %s\n", name, ok ? "PASS" : "FAIL");
}

static const char *TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";
static const char *TEST_MNEMONIC_24 =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art";
static const char *MASTER_XPUB =
    "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3ux"
    "BxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8";
static const char *BIP84_XPUB =
    "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshW"
    "cMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";

/* Independent derivation through libwally for cross-checks. */
static bool reference_master(const char *mnemonic, const char *passphrase,
                             uint32_t version, struct ext_key *out) {
  unsigned char seed[BIP39_SEED_LEN_512];
  if (bip39_mnemonic_to_seed512(mnemonic, passphrase, seed, sizeof(seed)) !=
      WALLY_OK)
    return false;
  int r = bip32_key_from_seed(seed, sizeof(seed), version, 0, out);
  wally_bzero(seed, sizeof(seed));
  return r == WALLY_OK;
}

static void fp_hex(const unsigned char fp[4], char out[9]) {
  snprintf(out, 9, "%02x%02x%02x%02x", fp[0], fp[1], fp[2], fp[3]);
}

static void test_unloaded(void) {
  check("init succeeds", key_init());
  check("not loaded after init", !key_is_loaded());

  unsigned char fp[4];
  char hex[9];
  char *s = NULL;
  char **words = NULL;
  size_t n = 0;
  struct ext_key *k = NULL;
  check("getters refuse when unloaded",
        !key_get_fingerprint(fp) && !key_get_fingerprint_hex(hex) &&
            !key_get_xpub("m/84'/0'/0'", &s) && !key_get_master_xpub(&s) &&
            !key_get_mnemonic(&s) && !key_get_mnemonic_words(&words, &n) &&
            !key_get_derived_key("m/0", &k) &&
            !key_get_derived_key_components(NULL, 0, &k));
  key_unload();
  check("unload when unloaded is harmless", !key_is_loaded());
}

static void test_load_and_reject(void) {
  check("NULL mnemonic rejected", !key_load_from_mnemonic(NULL, "", false));
  check("invalid checksum rejected",
        !key_load_from_mnemonic("abandon abandon abandon abandon abandon "
                                "abandon abandon abandon abandon abandon "
                                "abandon abandon",
                                "", false));
  check("non-wordlist word rejected",
        !key_load_from_mnemonic("abandon abandon abandon abandon abandon "
                                "abandon abandon abandon abandon abandon "
                                "abandon zzzz",
                                "", false));
  check("wrong word count rejected",
        !key_load_from_mnemonic("abandon abandon about", "", false));
  check("rejections leave the module unloaded", !key_is_loaded());

  check("test mnemonic loads",
        key_load_from_mnemonic(TEST_MNEMONIC, "", false));
  check("loaded", key_is_loaded());
  check("NULL passphrase equals empty passphrase", true);
}

static void test_fingerprint_and_xpubs(void) {
  unsigned char fp[4];
  char hex[9];
  check("fingerprint bytes", key_get_fingerprint(fp) && fp[0] == 0x73 &&
                                 fp[1] == 0xc5 && fp[2] == 0xda &&
                                 fp[3] == 0x0a);
  check("fingerprint hex",
        key_get_fingerprint_hex(hex) && strcmp(hex, "73c5da0a") == 0);
  check("fingerprint NULL out rejected",
        !key_get_fingerprint(NULL) && !key_get_fingerprint_hex(NULL));

  char *xpub = NULL;
  check("master xpub",
        key_get_master_xpub(&xpub) && strcmp(xpub, MASTER_XPUB) == 0);
  wally_free_string(xpub);
  check("BIP84 account xpub",
        key_get_xpub("m/84'/0'/0'", &xpub) && strcmp(xpub, BIP84_XPUB) == 0);
  wally_free_string(xpub);
  check("h notation derives the same key",
        key_get_xpub("m/84h/0h/0h", &xpub) && strcmp(xpub, BIP84_XPUB) == 0);
  wally_free_string(xpub);
  char *a = NULL, *b = NULL;
  check("path without m prefix accepted", key_get_xpub("84'/0'/0'", &a) &&
                                              key_get_xpub("m/84'/0'/0'", &b) &&
                                              strcmp(a, b) == 0);
  wally_free_string(a);
  wally_free_string(b);
  xpub = NULL;
  check("root path yields the master xpub",
        key_get_xpub("m", &xpub) && xpub && strcmp(xpub, MASTER_XPUB) == 0);
  wally_free_string(xpub);

  check("malformed path rejected",
        !key_get_xpub("m/84'/x/0'", &xpub) && !key_get_xpub("m//0", &xpub));
  check("path deeper than ten levels rejected",
        !key_get_xpub("m/1/2/3/4/5/6/7/8/9/10/11", &xpub));
  check("ten levels accepted", key_get_xpub("m/1/2/3/4/5/6/7/8/9/10", &xpub));
  wally_free_string(xpub);
  check("hardened index at the limit accepted",
        key_get_xpub("m/2147483647'", &xpub));
  wally_free_string(xpub);
  check("xpub NULL args rejected", !key_get_xpub(NULL, &xpub) &&
                                       !key_get_xpub("m/0", NULL) &&
                                       !key_get_master_xpub(NULL));
}

static void test_derived_keys(void) {
  struct ext_key *k = NULL;
  check("derived key at path", key_get_derived_key("m/84'/0'/0'", &k) && k);
  char *xpub = NULL;
  check("derived key carries private material",
        k->priv_key[0] == BIP32_FLAG_KEY_PRIVATE);
  check("derived key public part matches xpub",
        bip32_key_to_base58(k, BIP32_FLAG_KEY_PUBLIC, &xpub) == WALLY_OK &&
            strcmp(xpub, BIP84_XPUB) == 0);
  wally_free_string(xpub);
  bip32_key_free(k);

  uint32_t comps[3] = {84 | BIP32_INITIAL_HARDENED_CHILD,
                       0 | BIP32_INITIAL_HARDENED_CHILD,
                       0 | BIP32_INITIAL_HARDENED_CHILD};
  check("components derivation agrees with string path",
        key_get_derived_key_components(comps, 3, &k) &&
            bip32_key_to_base58(k, BIP32_FLAG_KEY_PUBLIC, &xpub) == WALLY_OK &&
            strcmp(xpub, BIP84_XPUB) == 0);
  wally_free_string(xpub);
  bip32_key_free(k);

  struct ext_key ref;
  check("depth zero returns a copy of the master key",
        key_get_derived_key_components(NULL, 0, &k) &&
            reference_master(TEST_MNEMONIC, "", BIP32_VER_MAIN_PRIVATE, &ref) &&
            memcmp(k->priv_key, ref.priv_key, sizeof(ref.priv_key)) == 0 &&
            memcmp(k->chain_code, ref.chain_code, sizeof(ref.chain_code)) == 0);
  bip32_key_free(k);
  wally_bzero(&ref, sizeof(ref));

  uint32_t deep[11] = {0};
  check("components deeper than ten rejected",
        !key_get_derived_key_components(deep, 11, &k));
  check("components NULL path with depth rejected",
        !key_get_derived_key_components(NULL, 1, &k));
  check("derived key malformed path rejected",
        !key_get_derived_key("m/abc", &k) && k == NULL);
  check("derived key NULL args rejected",
        !key_get_derived_key(NULL, &k) && !key_get_derived_key("m/0", NULL) &&
            !key_get_derived_key_components(comps, 3, NULL));
}

static void test_mnemonic_access(void) {
  char *m = NULL;
  check("mnemonic copy", key_get_mnemonic(&m) && strcmp(m, TEST_MNEMONIC) == 0);
  check("mnemonic copy is a distinct allocation", m != TEST_MNEMONIC);
  SECURE_FREE_STRING(m);
  check("mnemonic NULL out rejected", !key_get_mnemonic(NULL));

  char **words = NULL;
  size_t n = 0;
  track_duplicate = true;
  duplicate_wiped = false;
  check("mnemonic words split", key_get_mnemonic_words(&words, &n) && n == 12);
  check("tokenized copy wiped through original terminator", duplicate_wiped);
  check("first and last words", n == 12 && strcmp(words[0], "abandon") == 0 &&
                                    strcmp(words[11], "about") == 0);
  for (size_t i = 0; i < n; i++)
    SECURE_FREE_STRING(words[i]);
  free(words);
  check("mnemonic words NULL args rejected",
        !key_get_mnemonic_words(NULL, &n) &&
            !key_get_mnemonic_words(&words, NULL));

  check("24-word mnemonic loads",
        key_load_from_mnemonic(TEST_MNEMONIC_24, "", false));
  check("24 words split", key_get_mnemonic_words(&words, &n) && n == 24 &&
                              strcmp(words[23], "art") == 0);
  for (size_t i = 0; i < n; i++)
    SECURE_FREE_STRING(words[i]);
  free(words);
  char hex[9];
  check("reload replaced the key",
        key_get_fingerprint_hex(hex) && strcmp(hex, "73c5da0a") != 0);
}

static void test_passphrase_and_network(void) {
  struct ext_key ref;
  unsigned char fp[4];
  char expect[9], got[9];

  check(
      "reference key with passphrase",
      reference_master(TEST_MNEMONIC, "TREZOR", BIP32_VER_MAIN_PRIVATE, &ref) &&
          bip32_key_get_fingerprint(&ref, fp, 4) == WALLY_OK);
  fp_hex(fp, expect);
  check("passphrase changes the fingerprint", strcmp(expect, "73c5da0a") != 0);
  check("load with passphrase",
        key_load_from_mnemonic(TEST_MNEMONIC, "TREZOR", false) &&
            key_get_fingerprint_hex(got) && strcmp(got, expect) == 0);
  check("stored mnemonic excludes the passphrase", ({
          char *m = NULL;
          bool ok = key_get_mnemonic(&m) && strcmp(m, TEST_MNEMONIC) == 0;
          SECURE_FREE_STRING(m);
          ok;
        }));

  check("preview fingerprint with passphrase",
        key_mnemonic_passphrase_fingerprint_hex(TEST_MNEMONIC, "TREZOR", got) &&
            strcmp(got, expect) == 0);
  check("preview fingerprint without passphrase",
        key_mnemonic_fingerprint_hex(TEST_MNEMONIC, got) &&
            strcmp(got, "73c5da0a") == 0);
  check("preview with NULL passphrase equals empty",
        key_mnemonic_passphrase_fingerprint_hex(TEST_MNEMONIC, NULL, got) &&
            strcmp(got, "73c5da0a") == 0);
  check("preview does not disturb the loaded key",
        key_get_fingerprint_hex(got) && strcmp(got, expect) == 0);
  check("preview rejects invalid mnemonic and NULL args",
        !key_mnemonic_fingerprint_hex("abandon about", got) &&
            !key_mnemonic_fingerprint_hex(NULL, got) &&
            !key_mnemonic_fingerprint_hex(TEST_MNEMONIC, NULL));

  check("testnet load", key_load_from_mnemonic(TEST_MNEMONIC, "", true));
  check("testnet fingerprint is network independent",
        key_get_fingerprint_hex(got) && strcmp(got, "73c5da0a") == 0);
  char *xpub = NULL;
  check("testnet master key serialises as tprv-derived tpub",
        key_get_master_xpub(&xpub) && strncmp(xpub, "tpub", 4) == 0);
  wally_free_string(xpub);
  char *ref_b58 = NULL;
  check("testnet account matches reference derivation",
        reference_master(TEST_MNEMONIC, "", BIP32_VER_TEST_PRIVATE, &ref) &&
            key_get_xpub("m/84'/1'/0'", &xpub) && ({
              uint32_t p[3] = {84 | BIP32_INITIAL_HARDENED_CHILD,
                               1 | BIP32_INITIAL_HARDENED_CHILD,
                               0 | BIP32_INITIAL_HARDENED_CHILD};
              struct ext_key d;
              bip32_key_from_parent_path(&ref, p, 3, BIP32_FLAG_KEY_PRIVATE,
                                         &d) ==
                  WALLY_OK &&bip32_key_to_base58(&d, BIP32_FLAG_KEY_PUBLIC,
                                                 &ref_b58) ==
                  WALLY_OK &&strcmp(xpub, ref_b58) == 0;
            }));
  wally_free_string(xpub);
  wally_free_string(ref_b58);
  wally_bzero(&ref, sizeof(ref));
}

static void test_unload(void) {
  check("loaded before unload", key_is_loaded());
  key_unload();
  check("unloaded", !key_is_loaded());
  char hex[9];
  char *m = NULL;
  check("getters refuse after unload",
        !key_get_fingerprint_hex(hex) && !key_get_mnemonic(&m));
  check("reload after unload",
        key_load_from_mnemonic(TEST_MNEMONIC, "", false) &&
            key_get_fingerprint_hex(hex) && strcmp(hex, "73c5da0a") == 0);
  key_cleanup();
  check("cleanup unloads", !key_is_loaded());
}

static void test_internal_memory_exhaustion(void) {
  for (int n = 0; n < 3; ++n) {
    fail_after = n;
    check("load fails closed at each secret allocation",
          !key_load_from_mnemonic(TEST_MNEMONIC, "", false) &&
              !key_is_loaded());
  }
  fail_after = -1;
  check("load recovers after memory becomes available",
        key_load_from_mnemonic(TEST_MNEMONIC, "", false));
  fail_after = 0;
  struct ext_key *derived = NULL;
  check("master copy has no fallback",
        !key_get_derived_key("m", &derived) && !derived);
  check("derived private key has no fallback",
        !key_get_derived_key("m/84h/0h/0h", &derived) && !derived);
  char *phrase = NULL;
  check("mnemonic copy has no fallback", !key_get_mnemonic(&phrase) && !phrase);
  unsigned char entropy[16] = {0};
  probe_other_thread = true;
  other_thread_allocated = false;
  check("libwally mnemonic generation has no fallback",
        kern_bip39_mnemonic_from_bytes(NULL, entropy, sizeof(entropy),
                                       &phrase) == WALLY_ENOMEM &&
            !phrase);
  check("secret scope does not constrain a concurrent public-data thread",
        other_thread_allocated);
  void *public_data = wally_malloc(4096);
  check("public libwally allocation is unaffected and secret scope restored",
        public_data != NULL);
  wally_free(public_data);
  fail_after = 3;
  char **words = NULL;
  size_t count = 0;
  check("partial word allocation failure cleans up without output",
        !key_get_mnemonic_words(&words, &count) && !words && !count);
  fail_after = -1;
  key_unload();
}

int main(void) {
  printf("=== key tests ===\n\n");
  test_unloaded();
  test_load_and_reject();
  test_fingerprint_and_xpubs();
  test_derived_keys();
  test_mnemonic_access();
  test_passphrase_and_network();
  test_unload();
  test_internal_memory_exhaustion();
  printf("\nResults: %d passed, %d failed\n", tests_run - tests_failed,
         tests_failed);
  return tests_failed == 0 ? 0 : 1;
}
