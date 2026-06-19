#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Wally types needed by stubs */
#include <wally_bip32.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>

/* Project headers for stub type declarations */
#include "core/key.h"
#include "core/psbt.h"
#include "core/psbt_internal.h"
#include "core/registry.h"
#include "core/storage.h"
#include "core/wallet.h"

/* --- Storage stubs (registry.c persist=false path never calls these) --- */
esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  bool encrypted) {
  (void)loc;
  (void)id;
  (void)data;
  (void)len;
  (void)encrypted;
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
                                  bool *encrypted_out) {
  (void)loc;
  (void)filename;
  if (data_out)
    *data_out = NULL;
  if (len_out)
    *len_out = 0;
  if (encrypted_out)
    *encrypted_out = false;
  return -1;
}
void storage_free_file_list(char **files, int count) {
  (void)files;
  (void)count;
}

/* --- Wallet stubs --- */
wallet_network_t wallet_get_network(void) { return WALLET_NETWORK_MAINNET; }

/* --- Settings stub: permissive signing disabled in tests --- */
#include "core/settings.h"
bool settings_get_permissive_signing(void) { return false; }

bool key_get_fingerprint(unsigned char *fp) {
  if (fp)
    memset(fp, 0, BIP32_KEY_FINGERPRINT_LEN);
  return true;
}

/* ------------------------------------------------------------------ */

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) printf("Testing: %s... ", name)
#define PASS()                                                                 \
  do {                                                                         \
    printf("PASS\n");                                                          \
    tests_passed++;                                                            \
  } while (0)
#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
    tests_failed++;                                                            \
  } while (0)

/* ================================================================
 * Whitelist tests
 * ================================================================ */

static const char *TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

static const uint8_t REF_SPK_P2PKH[] = {
    0x76, 0xa9, 0x14, 0xd9, 0x86, 0xed, 0x01, 0xb7, 0xa2,
    0x22, 0x25, 0xa7, 0x0e, 0xdb, 0xf2, 0xba, 0x7c, 0xfb,
    0x63, 0xa1, 0x5c, 0xb3, 0xaa, 0x88, 0xac};

static const uint8_t REF_SPK_P2SH_P2WPKH[] = {
    0xa9, 0x14, 0x3f, 0xb6, 0xe9, 0x58, 0x12, 0xe5, 0x7b, 0xb4, 0x69, 0x1f,
    0x9a, 0x4a, 0x62, 0x88, 0x62, 0xa6, 0x1a, 0x4f, 0x76, 0x9b, 0x87};

static const uint8_t REF_SPK_P2WPKH[] = {
    0x00, 0x14, 0xc0, 0xce, 0xbc, 0xd6, 0xc3, 0xd3, 0xca, 0x8c, 0x75,
    0xdc, 0x5e, 0xc6, 0x2e, 0xbe, 0x55, 0x33, 0x0e, 0xf9, 0x10, 0xe2};

static const uint8_t REF_SPK_P2TR[] = {
    0x51, 0x20, 0xa6, 0x08, 0x69, 0xf0, 0xdb, 0xcf, 0x1d, 0xc6, 0x59, 0xc9,
    0xce, 0xcb, 0xaf, 0x80, 0x50, 0x13, 0x5e, 0xa9, 0xe8, 0xcd, 0xc4, 0x87,
    0x05, 0x3f, 0x1d, 0xc6, 0x88, 0x09, 0x49, 0xdc, 0x68, 0x4c};

static void test_whitelist_claim(const char *name, ss_script_type_t script,
                                 uint32_t purpose, const uint8_t *ref_spk,
                                 size_t ref_spk_len, bool expect_redeem) {
  TEST(name);
  claim_t claim = {0};
  claim.kind = CLAIM_WHITELIST;
  claim.whitelist.script = script;
  claim.whitelist.purpose = purpose;
  claim.whitelist.coin = 0;
  claim.whitelist.account = 0;
  claim.whitelist.chain = 0;
  claim.whitelist.index = 0;

  expected_scripts_t out = {0};
  if (!claim_regenerate(&claim, false, &out)) {
    FAIL("claim_regenerate returned false");
    return;
  }
  if (out.spk_len != ref_spk_len) {
    FAIL("wrong spk_len");
    return;
  }
  if (memcmp(out.spk, ref_spk, ref_spk_len) != 0) {
    FAIL("spk bytes mismatch");
    return;
  }
  if (expect_redeem && out.redeem_len != SS_P2SH_P2WPKH_REDEEM_LEN) {
    FAIL("wrong redeem_len for P2SH-P2WPKH");
    return;
  }
  if (!expect_redeem && out.redeem_len != 0) {
    FAIL("non-zero redeem_len for non-P2SH type");
    return;
  }
  if (expect_redeem && (out.redeem[0] != 0x00 || out.redeem[1] != 0x14)) {
    FAIL("redeem script does not start OP_0 <20>");
    return;
  }
  if (out.witness_len != 0) {
    FAIL("witness_len should be 0");
    return;
  }
  PASS();
}

/* ================================================================
 * Registry tests
 * ================================================================ */

#define XPUB_84                                                                \
  "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvP"               \
  "EbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"
#define XPUB_86                                                                \
  "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWc"                \
  "LteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"

/* --- Reference bytes (captured from print-mode run) --- */

/* wsh(sortedmulti(2-of-2)): P2WSH SPK, no redeem, sortedmulti witness */
static const uint8_t REF_WSH_SPK[] = {
    0x00, 0x20, 0xdc, 0x66, 0x81, 0xe3, 0x4b, 0x91, 0xcd, 0xf6, 0x3f, 0x40,
    0x08, 0xdb, 0x1f, 0x8b, 0xb0, 0x2d, 0x62, 0xf0, 0x06, 0xa1, 0xd7, 0x46,
    0x39, 0xc6, 0x56, 0xdf, 0x52, 0x61, 0x96, 0x7f, 0xc2, 0xb1};
static const uint8_t REF_WSH_WITNESS[] = {
    0x52, 0x21, 0x03, 0x30, 0xd5, 0x4f, 0xd0, 0xdd, 0x42, 0x0a, 0x6e, 0x5f,
    0x8d, 0x36, 0x24, 0xf5, 0xf3, 0x48, 0x2c, 0xae, 0x35, 0x0f, 0x79, 0xd5,
    0xf0, 0x75, 0x3b, 0xf5, 0xbe, 0xef, 0x9c, 0x2d, 0x91, 0xaf, 0x3c, 0x21,
    0x03, 0xcc, 0x8a, 0x4b, 0xc6, 0x4d, 0x89, 0x7b, 0xdd, 0xc5, 0xfb, 0xc2,
    0xf6, 0x70, 0xf7, 0xa8, 0xba, 0x0b, 0x38, 0x67, 0x79, 0x10, 0x6c, 0xf1,
    0x22, 0x3c, 0x6f, 0xc5, 0xd7, 0xcd, 0x6f, 0xc1, 0x15, 0x52, 0xae};

/* sh(wsh(sortedmulti(2-of-2))): P2SH SPK, P2WSH redeem, same witness */
static const uint8_t REF_SHWSH_SPK[] = {
    0xa9, 0x14, 0x87, 0xbb, 0xc7, 0x92, 0xae, 0x98, 0xf0, 0x87, 0x4a, 0x1c,
    0x2e, 0xc9, 0x99, 0xc4, 0x55, 0x73, 0x6d, 0x9d, 0x2b, 0xba, 0x87};
/* REF_SHWSH_REDEEM is the P2WSH program — identical to REF_WSH_SPK */
static const uint8_t REF_SHWSH_WITNESS[] = {
    0x52, 0x21, 0x03, 0x30, 0xd5, 0x4f, 0xd0, 0xdd, 0x42, 0x0a, 0x6e, 0x5f,
    0x8d, 0x36, 0x24, 0xf5, 0xf3, 0x48, 0x2c, 0xae, 0x35, 0x0f, 0x79, 0xd5,
    0xf0, 0x75, 0x3b, 0xf5, 0xbe, 0xef, 0x9c, 0x2d, 0x91, 0xaf, 0x3c, 0x21,
    0x03, 0xcc, 0x8a, 0x4b, 0xc6, 0x4d, 0x89, 0x7b, 0xdd, 0xc5, 0xfb, 0xc2,
    0xf6, 0x70, 0xf7, 0xa8, 0xba, 0x0b, 0x38, 0x67, 0x79, 0x10, 0x6c, 0xf1,
    0x22, 0x3c, 0x6f, 0xc5, 0xd7, 0xcd, 0x6f, 0xc1, 0x15, 0x52, 0xae};

/* sh(multi(2-of-2)): P2SH SPK, raw multi redeem, no witness */
static const uint8_t REF_SHMU_SPK[] = {
    0xa9, 0x14, 0x7d, 0xbf, 0x87, 0xe7, 0x0c, 0x23, 0x27, 0x49, 0x95, 0x78,
    0xd6, 0xfb, 0xa1, 0xe4, 0x8a, 0x1f, 0xe8, 0xd1, 0xe3, 0x44, 0x87};
static const uint8_t REF_SHMU_REDEEM[] = {
    0x52, 0x21, 0x03, 0x30, 0xd5, 0x4f, 0xd0, 0xdd, 0x42, 0x0a, 0x6e, 0x5f,
    0x8d, 0x36, 0x24, 0xf5, 0xf3, 0x48, 0x2c, 0xae, 0x35, 0x0f, 0x79, 0xd5,
    0xf0, 0x75, 0x3b, 0xf5, 0xbe, 0xef, 0x9c, 0x2d, 0x91, 0xaf, 0x3c, 0x21,
    0x03, 0xcc, 0x8a, 0x4b, 0xc6, 0x4d, 0x89, 0x7b, 0xdd, 0xc5, 0xfb, 0xc2,
    0xf6, 0x70, 0xf7, 0xa8, 0xba, 0x0b, 0x38, 0x67, 0x79, 0x10, 0x6c, 0xf1,
    0x22, 0x3c, 0x6f, 0xc5, 0xd7, 0xcd, 0x6f, 0xc1, 0x15, 0x52, 0xae};

/* wsh(or_d(pk(key0),and_v(v:pkh(key1),older(65535)))) miniscript:
 * P2WSH SPK, no redeem, miniscript witness */
static const uint8_t REF_MS_SPK[] = {
    0x00, 0x20, 0xdc, 0x3f, 0x0c, 0xa5, 0x22, 0xe9, 0x88, 0x49, 0xdb, 0xcf,
    0xa3, 0xc8, 0x40, 0x88, 0xe1, 0x57, 0x2d, 0xa4, 0x5d, 0xbe, 0xaa, 0x9f,
    0x69, 0x1a, 0x2e, 0x37, 0xac, 0xb1, 0xae, 0x73, 0xbf, 0xc9};
static const uint8_t REF_MS_WITNESS[] = {
    0x21, 0x03, 0x30, 0xd5, 0x4f, 0xd0, 0xdd, 0x42, 0x0a, 0x6e, 0x5f, 0x8d,
    0x36, 0x24, 0xf5, 0xf3, 0x48, 0x2c, 0xae, 0x35, 0x0f, 0x79, 0xd5, 0xf0,
    0x75, 0x3b, 0xf5, 0xbe, 0xef, 0x9c, 0x2d, 0x91, 0xaf, 0x3c, 0xac, 0x73,
    0x64, 0x76, 0xa9, 0x14, 0xef, 0xdd, 0xfd, 0xb4, 0xcd, 0x52, 0x11, 0xcc,
    0xd5, 0x45, 0x7e, 0x6c, 0x23, 0x7c, 0xab, 0xca, 0xd1, 0x4d, 0x4f, 0x39,
    0x88, 0xad, 0x03, 0xff, 0xff, 0x00, 0xb2, 0x68};

/* tr([00000000/86'/0'/0']XPUB_86/0/ *) child_num=0: P2TR SPK, no redeem, no
 * witness */
static const uint8_t REF_TR_SPK[] = {
    0x51, 0x20, 0xa6, 0x08, 0x69, 0xf0, 0xdb, 0xcf, 0x1d, 0xc6, 0x59, 0xc9,
    0xce, 0xcb, 0xaf, 0x80, 0x50, 0x13, 0x5e, 0xa9, 0xe8, 0xcd, 0xc4, 0x87,
    0x05, 0x3f, 0x1d, 0xc6, 0x88, 0x09, 0x49, 0xdc, 0x68, 0x4c};

/* sh(wsh(pkh([00000000/49'/0'/0']XPUB_84/0/ *))) child_num=0:
 * P2SH SPK, P2WSH redeem, P2PKH witness script.
 * wsh(wpkh()) is rejected by this libwally build (BUILD_MINIMAL);
 * sh(wsh(pkh())) exercises the identical claim_regenerate code path. */
static const uint8_t REF_SHWSH_PKH_SPK[] = {
    0xa9, 0x14, 0xfe, 0x3b, 0x8d, 0xe9, 0xe4, 0xda, 0xda, 0x6f, 0x6e, 0x11,
    0x27, 0xb0, 0xae, 0xf0, 0x44, 0x40, 0x41, 0x9d, 0x36, 0xeb, 0x87};
static const uint8_t REF_SHWSH_PKH_REDEEM[] = {
    0x00, 0x20, 0xd5, 0x23, 0x5c, 0x05, 0xc4, 0xfa, 0xe0, 0x21, 0x87, 0xdf,
    0xe8, 0x5b, 0xfc, 0x3f, 0x4c, 0x8e, 0x4d, 0x1f, 0x34, 0x7e, 0xce, 0x42,
    0x34, 0xe3, 0x6d, 0x13, 0x96, 0x57, 0x8e, 0x21, 0xe8, 0xbb};
static const uint8_t REF_SHWSH_PKH_WITNESS[] = {
    0x76, 0xa9, 0x14, 0xc0, 0xce, 0xbc, 0xd6, 0xc3, 0xd3,
    0xca, 0x8c, 0x75, 0xdc, 0x5e, 0xc6, 0x2e, 0xbe, 0x55,
    0x33, 0x0e, 0xf9, 0x10, 0xe2, 0x88, 0xac};

/* ------------------------------------------------------------------ */

static struct wally_psbt *
make_test_psbt(const uint8_t *utxo_script, size_t utxo_script_len,
               const uint8_t *pubkey, size_t pubkey_len,
               const uint8_t *kp_value, size_t kp_value_len) {
  struct wally_tx *tx = NULL;
  if (wally_tx_init_alloc(2, 0, 1, 1, &tx) != WALLY_OK)
    return NULL;

  uint8_t txid[32] = {0};
  wally_tx_add_raw_input(tx, txid, sizeof(txid), 0, 0xffffffff, NULL, 0, NULL,
                         0);
  uint8_t op_return[] = {0x6a};
  wally_tx_add_raw_output(tx, 0, op_return, sizeof(op_return), 0);

  struct wally_psbt *psbt = NULL;
  if (wally_psbt_from_tx(tx, 0, 0, &psbt) != WALLY_OK) {
    wally_tx_free(tx);
    return NULL;
  }
  wally_tx_free(tx);

  struct wally_tx_output *utxo = NULL;
  wally_tx_output_init_alloc(100000, utxo_script, utxo_script_len, &utxo);
  wally_psbt_set_input_witness_utxo(psbt, 0, utxo);
  wally_tx_output_free(utxo);

  wally_map_add(&psbt->inputs[0].keypaths, pubkey, pubkey_len, kp_value,
                kp_value_len);

  return psbt;
}

static void test_psbt_classify_fixture_a(void) {
  TEST("psbt_classify_input: fixture A (BIP84 verified-owned)");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fingerprint */
      0x54, 0x00, 0x00, 0x80, /* 84' */
      0x00, 0x00, 0x00, 0x80, /* 0'  */
      0x00, 0x00, 0x00, 0x80, /* 0'  */
      0x00, 0x00, 0x00, 0x00, /* 0   */
      0x00, 0x00, 0x00, 0x00, /* 0   */
  };

  struct wally_psbt *psbt =
      make_test_psbt(REF_SPK_P2WPKH, sizeof(REF_SPK_P2WPKH), derived->pub_key,
                     sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  if (r.ownership != PSBT_OWNERSHIP_OWNED_SAFE) {
    FAIL("expected OWNED_SAFE");
    return;
  }
  if (r.claim.kind != CLAIM_WHITELIST) {
    FAIL("expected CLAIM_WHITELIST");
    return;
  }
  if (r.claim.whitelist.script != SS_SCRIPT_P2WPKH) {
    FAIL("wrong script type");
    return;
  }
  if (r.claim.whitelist.account != 0) {
    FAIL("expected account 0");
    return;
  }
  if (r.claim.whitelist.chain != 0) {
    FAIL("expected chain 0");
    return;
  }
  if (r.claim.whitelist.index != 0) {
    FAIL("expected index 0");
    return;
  }
  PASS();
}

static void test_psbt_classify_fixture_a_p2sh_p2wpkh(void) {
  TEST("psbt_classify_input: P2SH-P2WPKH BIP49 verified-owned");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/49'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  /* The redeem script for P2SH-P2WPKH is the P2WPKH witness program of the
   * same key: OP_0 <hash160(pubkey)>, 22 bytes. The classifier byte-compares
   * this against the PSBT input's redeem_script. */
  uint8_t redeem[22];
  size_t redeem_len = 0;
  if (wally_witness_program_from_bytes(
          derived->pub_key, EC_PUBLIC_KEY_LEN, WALLY_SCRIPT_HASH160, redeem,
          sizeof(redeem), &redeem_len) != WALLY_OK) {
    bip32_key_free(derived);
    FAIL("redeem build");
    return;
  }

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fingerprint */
      0x31, 0x00, 0x00, 0x80, /* 49' */
      0x00, 0x00, 0x00, 0x80, /* 0'  */
      0x00, 0x00, 0x00, 0x80, /* 0'  */
      0x00, 0x00, 0x00, 0x00, /* 0   */
      0x00, 0x00, 0x00, 0x00, /* 0   */
  };

  struct wally_psbt *psbt = make_test_psbt(
      REF_SPK_P2SH_P2WPKH, sizeof(REF_SPK_P2SH_P2WPKH), derived->pub_key,
      sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }
  if (wally_psbt_set_input_redeem_script(psbt, 0, redeem, redeem_len) !=
      WALLY_OK) {
    wally_psbt_free(psbt);
    FAIL("set redeem_script");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  if (r.ownership != PSBT_OWNERSHIP_OWNED_SAFE) {
    FAIL("expected OWNED_SAFE");
    return;
  }
  if (r.claim.kind != CLAIM_WHITELIST) {
    FAIL("expected CLAIM_WHITELIST");
    return;
  }
  if (r.claim.whitelist.script != SS_SCRIPT_P2SH_P2WPKH) {
    FAIL("wrong script type");
    return;
  }
  if (r.claim.whitelist.purpose != 49) {
    FAIL("wrong purpose");
    return;
  }
  PASS();
}

/* Build a P2WPKH PSBT for the testnet keypath m/84'/1'/0'/0/0 and classify it
 * with is_testnet=true. Catches the d49f923-class regression where a stale
 * is_testnet flag would cause the whitelist (coin pinned to network) to
 * reject a legitimately owned testnet input. */
static void test_psbt_classify_fixture_a_testnet(void) {
  TEST("psbt_classify_input: BIP84 testnet verified-owned (is_testnet=true)");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/1'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  uint8_t spk[22];
  size_t spk_len = 0;
  if (wally_witness_program_from_bytes(derived->pub_key, EC_PUBLIC_KEY_LEN,
                                       WALLY_SCRIPT_HASH160, spk, sizeof(spk),
                                       &spk_len) != WALLY_OK) {
    bip32_key_free(derived);
    FAIL("witness program build");
    return;
  }

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fingerprint     */
      0x54, 0x00, 0x00, 0x80, /* 84'             */
      0x01, 0x00, 0x00, 0x80, /* 1' (testnet)    */
      0x00, 0x00, 0x00, 0x80, /* 0'              */
      0x00, 0x00, 0x00, 0x00, /* 0               */
      0x00, 0x00, 0x00, 0x00, /* 0               */
  };

  struct wally_psbt *psbt =
      make_test_psbt(spk, spk_len, derived->pub_key, sizeof(derived->pub_key),
                     kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, true);
  wally_psbt_free(psbt);

  if (r.ownership != PSBT_OWNERSHIP_OWNED_SAFE) {
    FAIL("expected OWNED_SAFE on testnet keypath");
    return;
  }
  if (r.claim.kind != CLAIM_WHITELIST) {
    FAIL("expected CLAIM_WHITELIST");
    return;
  }
  if (r.claim.whitelist.coin != 1) {
    FAIL("expected whitelist coin == 1");
    return;
  }
  PASS();
}

/* Same testnet PSBT as above but classify with is_testnet=false. The
 * whitelist must reject (coin=1 vs expected coin=0); derive→spk still
 * succeeds against the keypath-supplied path so the result drops from
 * OWNED_SAFE to OWNED_UNSAFE -- the user must now opt into permissive
 * signing instead of getting a silent OWNED_SAFE pass. */
static void test_psbt_classify_adv_testnet_flag_mismatch(void) {
  TEST("psbt_classify_input: testnet keypath classified as mainnet -> "
       "OWNED_UNSAFE");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/1'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  uint8_t spk[22];
  size_t spk_len = 0;
  if (wally_witness_program_from_bytes(derived->pub_key, EC_PUBLIC_KEY_LEN,
                                       WALLY_SCRIPT_HASH160, spk, sizeof(spk),
                                       &spk_len) != WALLY_OK) {
    bip32_key_free(derived);
    FAIL("witness program build");
    return;
  }

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x80,
      0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  struct wally_psbt *psbt =
      make_test_psbt(spk, spk_len, derived->pub_key, sizeof(derived->pub_key),
                     kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  /* Classify as mainnet -- the whitelist coin (0) won't match the testnet
   * keypath's coin (1), so the whitelist rejects. derive→spk still succeeds
   * against the path the PSBT supplied (84'/1'/0'/0/0), so the result is
   * OWNED_UNSAFE rather than the safer OWNED_SAFE. */
  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  if (r.ownership != PSBT_OWNERSHIP_OWNED_UNSAFE) {
    FAIL("expected OWNED_UNSAFE on testnet keypath read as mainnet");
    return;
  }
  PASS();
}

static void test_psbt_classify_fixture_d(void) {
  TEST(
      "psbt_classify_input: fixture D (attack -- correct keypath, wrong UTXO)");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
      0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  /* Attacker swaps the UTXO to a P2PKH output — same keypath, wrong script */
  struct wally_psbt *psbt =
      make_test_psbt(REF_SPK_P2PKH, sizeof(REF_SPK_P2PKH), derived->pub_key,
                     sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  /* Attacker swapped the spk to REF_SPK_P2PKH which is hash of
   * derive(m/44'/0'/0'/0/0).pub_key — a different key than the one at
   * m/84'/0'/0'/0/0 advertised in the keypath. derive→spk fails for
   * every shape → EXPECTED_OWNED (the harness state that prevents
   * silently signing for an attacker's key). */
  if (r.ownership != PSBT_OWNERSHIP_EXPECTED_OWNED) {
    FAIL("must be EXPECTED_OWNED (derive doesn't reach the swapped spk)");
    return;
  }
  PASS();
}

static void test_psbt_classify_fixture_e(void) {
  TEST("psbt_classify_input: fixture E (fp match, unknown path, derive "
       "mismatch)");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  /* Path uses purpose 99' (0x80000063) — not in whitelist, not in registry */
  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fingerprint = 00000000 (matches stub) */
      0x63, 0x00, 0x00, 0x80, /* 99' = 0x80000063 LE                   */
      0x00, 0x00, 0x00, 0x80, /* 0'                                    */
      0x00, 0x00, 0x00, 0x80, /* 0'                                    */
      0x00, 0x00, 0x00, 0x00, /* 0                                     */
      0x00, 0x00, 0x00, 0x00, /* 0                                     */
  };

  struct wally_psbt *psbt =
      make_test_psbt(REF_SPK_P2WPKH, sizeof(REF_SPK_P2WPKH), derived->pub_key,
                     sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  /* fp matches but the path (99') derives to a pubkey other than the
   * one whose p2wpkh produced REF_SPK_P2WPKH, so derive→spk fails →
   * EXPECTED_OWNED (harness state). */
  if (r.ownership != PSBT_OWNERSHIP_EXPECTED_OWNED) {
    FAIL("must be EXPECTED_OWNED (fp matches, derive doesn't reach spk)");
    return;
  }
  PASS();
}

static void test_psbt_classify_fixture_f(void) {
  TEST("psbt_classify_input: fixture F (fp + non-standard path, derive "
       "verifies)");

  /* Path m/9999'/0'/0'/0/0 — purpose 9999 isn't on the whitelist and
   * isn't in the registry, but the spk in the PSBT IS the p2wpkh of
   * derive(that path). Classifier should return OWNED_UNSAFE. */
  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/9999'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  uint8_t spk[22];
  size_t spk_len = 0;
  if (wally_witness_program_from_bytes(derived->pub_key, EC_PUBLIC_KEY_LEN,
                                       WALLY_SCRIPT_HASH160, spk, sizeof(spk),
                                       &spk_len) != WALLY_OK) {
    bip32_key_free(derived);
    FAIL("witness program build");
    return;
  }

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fingerprint = 00000000 (matches stub) */
      0x0F, 0x27, 0x00, 0x80, /* 9999' = 0x8000270F LE                 */
      0x00, 0x00, 0x00, 0x80, /* 0'                                    */
      0x00, 0x00, 0x00, 0x80, /* 0'                                    */
      0x00, 0x00, 0x00, 0x00, /* 0                                     */
      0x00, 0x00, 0x00, 0x00, /* 0                                     */
  };

  struct wally_psbt *psbt =
      make_test_psbt(spk, spk_len, derived->pub_key, sizeof(derived->pub_key),
                     kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  if (r.ownership != PSBT_OWNERSHIP_OWNED_UNSAFE) {
    FAIL("must be OWNED_UNSAFE (fp + derive verifies on non-whitelisted path)");
    return;
  }
  PASS();
}

static void test_psbt_classify_fixture_b(void) {
  TEST("psbt_classify_output: fixture B (BIP86 taproot owned + external)");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/86'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fingerprint = 00000000 (stub) */
      0x56, 0x00, 0x00, 0x80, /* 86' = 0x80000056 */
      0x00, 0x00, 0x00, 0x80, /* 0'  */
      0x00, 0x00, 0x00, 0x80, /* 0'  */
      0x00, 0x00, 0x00, 0x00, /* 0 (chain) */
      0x00, 0x00, 0x00, 0x00, /* 0 (index) */
  };

  struct wally_tx *tx = NULL;
  if (wally_tx_init_alloc(2, 0, 1, 2, &tx) != WALLY_OK) {
    bip32_key_free(derived);
    FAIL("wally_tx_init_alloc");
    return;
  }
  uint8_t txid[32] = {0};
  wally_tx_add_raw_input(tx, txid, sizeof(txid), 0, 0xffffffff, NULL, 0, NULL,
                         0);
  wally_tx_add_raw_output(tx, 50000, REF_SPK_P2TR, sizeof(REF_SPK_P2TR),
                          0); /* output 0: ours */
  wally_tx_add_raw_output(tx, 49000, REF_SPK_P2PKH, sizeof(REF_SPK_P2PKH),
                          0); /* output 1: external */

  struct wally_psbt *psbt = NULL;
  if (wally_psbt_from_tx(tx, 0, 0, &psbt) != WALLY_OK) {
    wally_tx_free(tx);
    bip32_key_free(derived);
    FAIL("wally_psbt_from_tx");
    return;
  }
  wally_tx_free(tx);

  uint8_t op_return[] = {0x6a};
  struct wally_tx_output *utxo = NULL;
  wally_tx_output_init_alloc(100000, op_return, sizeof(op_return), &utxo);
  wally_psbt_set_input_witness_utxo(psbt, 0, utxo);
  wally_tx_output_free(utxo);

  wally_map_add(&psbt->outputs[0].keypaths, derived->pub_key,
                sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  /* output 1: no keypath added — external destination */

  output_ownership_t r0 = psbt_classify_output(psbt, 0, false);
  if (r0.ownership != PSBT_OWNERSHIP_OWNED_SAFE) {
    FAIL("output 0: expected OWNED_SAFE");
    wally_psbt_free(psbt);
    return;
  }
  if (r0.source.kind != CLAIM_WHITELIST) {
    FAIL("output 0: expected CLAIM_WHITELIST");
    wally_psbt_free(psbt);
    return;
  }
  if (r0.source.whitelist.script != SS_SCRIPT_P2TR) {
    FAIL("output 0: wrong script type");
    wally_psbt_free(psbt);
    return;
  }
  if (r0.source.whitelist.account != 0) {
    FAIL("output 0: wrong account");
    wally_psbt_free(psbt);
    return;
  }

  output_ownership_t r1 = psbt_classify_output(psbt, 1, false);
  if (r1.ownership != PSBT_OWNERSHIP_EXTERNAL) {
    FAIL("output 1: must be EXTERNAL");
    wally_psbt_free(psbt);
    return;
  }

  wally_psbt_free(psbt);
  PASS();
}

static void test_psbt_classify_fixture_c(void) {
  TEST("psbt_classify_output: fixture C (WSH sortedmulti registry)");

  registry_clear();
  if (!registry_add_from_string("u",
                                "wsh(sortedmulti(2,"
                                "[00000000/48'/0'/0'/2']" XPUB_84 "/0/*,"
                                "[11111111/48'/0'/0'/2']" XPUB_86 "/0/*"
                                "))#6nfc46dh",
                                STORAGE_FLASH, false)) {
    FAIL("registry_add_from_string");
    return;
  }

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fingerprint = 00000000 (stub) */
      0x30, 0x00, 0x00, 0x80, /* 48' = 0x80000030 */
      0x00, 0x00, 0x00, 0x80, /* 0'  */
      0x00, 0x00, 0x00, 0x80, /* 0'  */
      0x02, 0x00, 0x00, 0x80, /* 2'  */
      0x00, 0x00, 0x00, 0x00, /* 0 (multi_index) */
      0x00, 0x00, 0x00, 0x00, /* 0 (child_num) */
  };

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/48'/0'/0'/2'/0/0", &derived)) {
    FAIL("key derivation failed");
    registry_clear();
    return;
  }

  struct wally_tx *tx = NULL;
  if (wally_tx_init_alloc(2, 0, 1, 1, &tx) != WALLY_OK) {
    bip32_key_free(derived);
    registry_clear();
    FAIL("wally_tx_init_alloc");
    return;
  }
  uint8_t txid[32] = {0};
  wally_tx_add_raw_input(tx, txid, sizeof(txid), 0, 0xffffffff, NULL, 0, NULL,
                         0);
  wally_tx_add_raw_output(tx, 50000, REF_WSH_SPK, sizeof(REF_WSH_SPK), 0);

  struct wally_psbt *psbt = NULL;
  if (wally_psbt_from_tx(tx, 0, 0, &psbt) != WALLY_OK) {
    wally_tx_free(tx);
    bip32_key_free(derived);
    registry_clear();
    FAIL("wally_psbt_from_tx");
    return;
  }
  wally_tx_free(tx);

  uint8_t op_return[] = {0x6a};
  struct wally_tx_output *utxo = NULL;
  wally_tx_output_init_alloc(100000, op_return, sizeof(op_return), &utxo);
  wally_psbt_set_input_witness_utxo(psbt, 0, utxo);
  wally_tx_output_free(utxo);

  wally_map_add(&psbt->outputs[0].keypaths, derived->pub_key,
                sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);

  output_ownership_t r = psbt_classify_output(psbt, 0, false);
  wally_psbt_free(psbt);
  registry_clear();

  if (r.ownership != PSBT_OWNERSHIP_OWNED_SAFE) {
    FAIL("expected OWNED_SAFE");
    return;
  }
  if (r.source.kind != CLAIM_REGISTRY) {
    FAIL("expected CLAIM_REGISTRY");
    return;
  }
  if (r.source.registry.multi_index != 0) {
    FAIL("wrong multi_index");
    return;
  }
  if (r.source.registry.child_num != 0) {
    FAIL("wrong child_num");
    return;
  }
  PASS();
}

/* ================================================================
 * Adversarial classifier tests
 * ================================================================ */

static void test_psbt_classify_adv_fp_mismatch(void) {
  TEST("psbt_classify_input: foreign fingerprint -> EXTERNAL");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  /* Same path/spk as fixture A, but fp = deadbeef does not match the
   * stub fingerprint 00000000. */
  uint8_t kp_val[] = {
      0xde, 0xad, 0xbe, 0xef, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
      0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  struct wally_psbt *psbt =
      make_test_psbt(REF_SPK_P2WPKH, sizeof(REF_SPK_P2WPKH), derived->pub_key,
                     sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  if (r.ownership != PSBT_OWNERSHIP_EXTERNAL) {
    FAIL("expected EXTERNAL for foreign fingerprint");
    return;
  }
  PASS();
}

static void test_psbt_classify_adv_keypath_truncated(void) {
  TEST("psbt_classify_input: keypath shorter than fingerprint -> EXTERNAL");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  /* 3 bytes — below fingerprint length, classifier must skip. */
  uint8_t kp_val[] = {0x00, 0x00, 0x00};
  struct wally_psbt *psbt =
      make_test_psbt(REF_SPK_P2WPKH, sizeof(REF_SPK_P2WPKH), derived->pub_key,
                     sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  if (r.ownership != PSBT_OWNERSHIP_EXTERNAL) {
    FAIL("expected EXTERNAL for sub-fingerprint keypath");
    return;
  }
  PASS();
}

static void test_psbt_classify_adv_keypath_fp_only(void) {
  TEST(
      "psbt_classify_input: fp-only keypath (no derivation) -> EXPECTED_OWNED");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  /* 4 bytes: fingerprint matches but no derivation components. fp-match
   * marks the input as ours, but derive→spk has nothing to derive →
   * EXPECTED_OWNED (harness state). */
  uint8_t kp_val[] = {0x00, 0x00, 0x00, 0x00};
  struct wally_psbt *psbt =
      make_test_psbt(REF_SPK_P2WPKH, sizeof(REF_SPK_P2WPKH), derived->pub_key,
                     sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  if (r.ownership != PSBT_OWNERSHIP_EXPECTED_OWNED) {
    FAIL("expected EXPECTED_OWNED for fp-only keypath");
    return;
  }
  PASS();
}

static void test_psbt_classify_adv_mixed_script(void) {
  TEST("psbt_classify_input: 84' path + P2PKH(same key) -> OWNED_UNSAFE");

  /* Attack: declare a whitelist-shaped path (84') but supply a P2PKH
   * UTXO derived from the same pubkey. The whitelist match fails
   * (script-type mismatch on regenerate), but derive_matches_spk tries
   * all four standard shapes and finds P2PKH(pubkey) matches → falls
   * through to OWNED_UNSAFE. Locks in: this shape is gated by
   * permissive_signing, never auto-OWNED_SAFE. */
  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  uint8_t pkh20[HASH160_LEN];
  if (wally_hash160(derived->pub_key, EC_PUBLIC_KEY_LEN, pkh20, HASH160_LEN) !=
      WALLY_OK) {
    bip32_key_free(derived);
    FAIL("hash160");
    return;
  }
  uint8_t spk[25] = {0x76, 0xa9, 0x14};
  memcpy(spk + 3, pkh20, 20);
  spk[23] = 0x88;
  spk[24] = 0xac;

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
      0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  struct wally_psbt *psbt =
      make_test_psbt(spk, sizeof(spk), derived->pub_key,
                     sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  if (r.ownership != PSBT_OWNERSHIP_OWNED_UNSAFE) {
    FAIL("expected OWNED_UNSAFE (whitelist rejects, derive matches P2PKH)");
    return;
  }
  PASS();
}

static void test_psbt_classify_adv_registry_depth_mismatch(void) {
  TEST("psbt_classify_input: registered desc, keypath missing tail -> "
       "EXPECTED_OWNED");

  /* Register a 4-deep origin (48'/0'/0'/2') multisig descriptor, then
   * supply a keypath whose total depth equals the origin (no tail) —
   * registry_match_keypath requires exactly origin+2 components, so it
   * must reject. fp matches but derive_matches_spk over the WSH spk
   * does not match any of the four singlesig shapes → EXPECTED_OWNED. */
  registry_clear();
  if (!registry_add_from_string("u",
                                "wsh(sortedmulti(2,"
                                "[00000000/48'/0'/0'/2']" XPUB_84 "/0/*,"
                                "[11111111/48'/0'/0'/2']" XPUB_86 "/0/*"
                                "))#6nfc46dh",
                                STORAGE_FLASH, false)) {
    FAIL("registry_add_from_string");
    return;
  }

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/48'/0'/0'/2'", &derived)) {
    registry_clear();
    FAIL("key derivation failed");
    return;
  }

  /* No tail components — only fp + 4 origin components. */
  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fp */
      0x30, 0x00, 0x00, 0x80, /* 48' */
      0x00, 0x00, 0x00, 0x80, /* 0' */
      0x00, 0x00, 0x00, 0x80, /* 0' */
      0x02, 0x00, 0x00, 0x80, /* 2' */
  };

  struct wally_psbt *psbt =
      make_test_psbt(REF_WSH_SPK, sizeof(REF_WSH_SPK), derived->pub_key,
                     sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    registry_clear();
    FAIL("make_test_psbt");
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);
  registry_clear();

  if (r.ownership != PSBT_OWNERSHIP_EXPECTED_OWNED) {
    FAIL("expected EXPECTED_OWNED (registry must reject depth mismatch)");
    return;
  }
  PASS();
}

static void test_psbt_classify_adv_taproot_foreign_fp(void) {
  TEST("psbt_classify_input: taproot leaf path with foreign fp -> EXTERNAL");

  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/86'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }

  struct wally_tx *tx = NULL;
  if (wally_tx_init_alloc(2, 0, 1, 1, &tx) != WALLY_OK) {
    bip32_key_free(derived);
    FAIL("tx alloc");
    return;
  }
  uint8_t txid[32] = {0};
  wally_tx_add_raw_input(tx, txid, sizeof(txid), 0, 0xffffffff, NULL, 0, NULL,
                         0);
  uint8_t op_return[] = {0x6a};
  wally_tx_add_raw_output(tx, 0, op_return, sizeof(op_return), 0);

  struct wally_psbt *psbt = NULL;
  if (wally_psbt_from_tx(tx, 0, 0, &psbt) != WALLY_OK) {
    wally_tx_free(tx);
    bip32_key_free(derived);
    FAIL("psbt from tx");
    return;
  }
  wally_tx_free(tx);

  struct wally_tx_output *utxo = NULL;
  wally_tx_output_init_alloc(50000, REF_SPK_P2TR, sizeof(REF_SPK_P2TR), &utxo);
  wally_psbt_set_input_witness_utxo(psbt, 0, utxo);
  wally_tx_output_free(utxo);

  /* Foreign fp in the taproot_leaf_paths entry. */
  uint8_t kp_val[] = {
      0xde, 0xad, 0xbe, 0xef, 0x56, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
      0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  /* xonly = drop leading 02/03 byte of the compressed pubkey */
  wally_map_add(&psbt->inputs[0].taproot_leaf_paths, derived->pub_key + 1,
                EC_PUBLIC_KEY_LEN - 1, kp_val, sizeof(kp_val));
  bip32_key_free(derived);

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);

  if (r.ownership != PSBT_OWNERSHIP_EXTERNAL) {
    FAIL("expected EXTERNAL for foreign fp in taproot_leaf_paths");
    return;
  }
  PASS();
}

/* ================================================================
 * psbt_sign policy-gate tests
 *
 * Verify that psbt_sign() refuses to produce signatures for
 * OWNED_UNSAFE / EXPECTED_OWNED inputs unless the corresponding policy
 * bit is set, even when libwally signing would succeed.
 * ================================================================ */

/* Build a single-input PSBT whose input is OWNED_UNSAFE (fp matches,
 * derive(path) reproduces the spk, but path is not whitelisted).
 * Mirrors fixture F. */
static struct wally_psbt *make_unsafe_psbt(void) {
  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/9999'/0'/0'/0/0", &derived))
    return NULL;

  uint8_t spk[22];
  size_t spk_len = 0;
  if (wally_witness_program_from_bytes(derived->pub_key, EC_PUBLIC_KEY_LEN,
                                       WALLY_SCRIPT_HASH160, spk, sizeof(spk),
                                       &spk_len) != WALLY_OK) {
    bip32_key_free(derived);
    return NULL;
  }

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fp = 00000000 */
      0x0F, 0x27, 0x00, 0x80, /* 9999' */
      0x00, 0x00, 0x00, 0x80, /* 0' */
      0x00, 0x00, 0x00, 0x80, /* 0' */
      0x00, 0x00, 0x00, 0x00, /* 0 */
      0x00, 0x00, 0x00, 0x00, /* 0 */
  };

  struct wally_psbt *psbt =
      make_test_psbt(spk, spk_len, derived->pub_key, sizeof(derived->pub_key),
                     kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  return psbt;
}

/* EXPECTED_OWNED: fp matches but derive doesn't reproduce the spk
 * (here the path is unknown purpose 99'). Mirrors fixture E. */
static struct wally_psbt *make_expected_owned_psbt(void) {
  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/0'/0'/0/0", &derived))
    return NULL;

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fp = 00000000 */
      0x63, 0x00, 0x00, 0x80, /* 99' */
      0x00, 0x00, 0x00, 0x80, /* 0' */
      0x00, 0x00, 0x00, 0x80, /* 0' */
      0x00, 0x00, 0x00, 0x00, /* 0 */
      0x00, 0x00, 0x00, 0x00, /* 0 */
  };

  struct wally_psbt *psbt =
      make_test_psbt(REF_SPK_P2WPKH, sizeof(REF_SPK_P2WPKH), derived->pub_key,
                     sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  return psbt;
}

static void test_psbt_sign_gate_unsafe_blocked(void) {
  TEST("psbt_sign: OWNED_UNSAFE blocked when allow_unsafe=false");

  struct wally_psbt *psbt = make_unsafe_psbt();
  if (!psbt) {
    FAIL("make_unsafe_psbt");
    return;
  }

  psbt_sign_policy_t policy = {.allow_unsafe = false,
                               .allow_expected_owned = false};
  size_t n = psbt_sign(psbt, false, policy);
  wally_psbt_free(psbt);

  if (n != 0) {
    FAIL("expected 0 signatures (policy gate should block)");
    return;
  }
  PASS();
}

static void test_psbt_sign_gate_unsafe_allowed(void) {
  TEST("psbt_sign: OWNED_UNSAFE signed when allow_unsafe=true");

  struct wally_psbt *psbt = make_unsafe_psbt();
  if (!psbt) {
    FAIL("make_unsafe_psbt");
    return;
  }

  psbt_sign_policy_t policy = {.allow_unsafe = true,
                               .allow_expected_owned = false};
  size_t n = psbt_sign(psbt, false, policy);
  wally_psbt_free(psbt);

  if (n != 1) {
    FAIL("expected 1 signature when policy allows OWNED_UNSAFE");
    return;
  }
  PASS();
}

static void test_psbt_sign_gate_expected_blocked(void) {
  TEST("psbt_sign: EXPECTED_OWNED blocked when allow_expected_owned=false");

  struct wally_psbt *psbt = make_expected_owned_psbt();
  if (!psbt) {
    FAIL("make_expected_owned_psbt");
    return;
  }

  psbt_sign_policy_t policy = {.allow_unsafe = false,
                               .allow_expected_owned = false};
  size_t n = psbt_sign(psbt, false, policy);
  wally_psbt_free(psbt);

  if (n != 0) {
    FAIL("expected 0 signatures (policy gate should block)");
    return;
  }
  PASS();
}

static void test_psbt_sign_gate_external_always_skipped(void) {
  TEST("psbt_sign: EXTERNAL skipped even with all policy bits true");

  /* fp=deadbeef will not match key_get_fingerprint stub (00000000) →
   * EXTERNAL. Even with both policy bits on, no signatures should be
   * produced. */
  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/0'/0'/0/0", &derived)) {
    FAIL("key derivation failed");
    return;
  }
  uint8_t kp_val[] = {
      0xde, 0xad, 0xbe, 0xef, /* foreign fp */
      0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
      0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  struct wally_psbt *psbt =
      make_test_psbt(REF_SPK_P2WPKH, sizeof(REF_SPK_P2WPKH), derived->pub_key,
                     sizeof(derived->pub_key), kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt) {
    FAIL("make_test_psbt");
    return;
  }

  psbt_sign_policy_t policy = {.allow_unsafe = true,
                               .allow_expected_owned = true};
  size_t n = psbt_sign(psbt, false, policy);
  wally_psbt_free(psbt);

  if (n != 0) {
    FAIL("EXTERNAL must never be signed");
    return;
  }
  PASS();
}

/* Two-input PSBT helper. Each input gets a witness_utxo + a single keypath
 * entry. Distinct prev-tx txids prevent the inputs from being treated as
 * duplicates. */
static struct wally_psbt *
make_two_input_psbt(const uint8_t *spk1, size_t spk1_len, const uint8_t *pk1,
                    size_t pk1_len, const uint8_t *kp1, size_t kp1_len,
                    const uint8_t *spk2, size_t spk2_len, const uint8_t *pk2,
                    size_t pk2_len, const uint8_t *kp2, size_t kp2_len) {
  struct wally_tx *tx = NULL;
  if (wally_tx_init_alloc(2, 0, 2, 1, &tx) != WALLY_OK)
    return NULL;

  uint8_t txid_a[32] = {0};
  uint8_t txid_b[32] = {0};
  txid_b[0] = 0x01; /* distinct prevout */
  wally_tx_add_raw_input(tx, txid_a, sizeof(txid_a), 0, 0xffffffff, NULL, 0,
                         NULL, 0);
  wally_tx_add_raw_input(tx, txid_b, sizeof(txid_b), 0, 0xffffffff, NULL, 0,
                         NULL, 0);
  uint8_t op_return[] = {0x6a};
  wally_tx_add_raw_output(tx, 0, op_return, sizeof(op_return), 0);

  struct wally_psbt *psbt = NULL;
  if (wally_psbt_from_tx(tx, 0, 0, &psbt) != WALLY_OK) {
    wally_tx_free(tx);
    return NULL;
  }
  wally_tx_free(tx);

  struct wally_tx_output *u1 = NULL;
  wally_tx_output_init_alloc(100000, spk1, spk1_len, &u1);
  wally_psbt_set_input_witness_utxo(psbt, 0, u1);
  wally_tx_output_free(u1);
  wally_map_add(&psbt->inputs[0].keypaths, pk1, pk1_len, kp1, kp1_len);

  struct wally_tx_output *u2 = NULL;
  wally_tx_output_init_alloc(50000, spk2, spk2_len, &u2);
  wally_psbt_set_input_witness_utxo(psbt, 1, u2);
  wally_tx_output_free(u2);
  wally_map_add(&psbt->inputs[1].keypaths, pk2, pk2_len, kp2, kp2_len);

  return psbt;
}

#define WSH_REGISTRY_DESC                                                      \
  "wsh(sortedmulti(2,"                                                         \
  "[00000000/48'/0'/0'/2']" XPUB_84 "/0/*,"                                    \
  "[11111111/48'/0'/0'/2']" XPUB_86 "/0/*"                                     \
  "))#6nfc46dh"

#define MS_REGISTRY_DESC                                                       \
  "wsh(or_d(pk([00000000/48'/0'/0'/2']" XPUB_84 "/0/*),"                       \
  "and_v(v:pkh([11111111/48'/0'/0'/2']" XPUB_86 "/0/*),"                       \
  "older(65535))))#xqs0xj7k"

/* Build a PSBT input that matches a registered wsh descriptor with origin
 * 48'/0'/0'/2' at multi_index=0, child_num=0. The returned PSBT has the
 * given spk + witness_script wired in; caller is responsible for any
 * tampering before classification. */
static struct wally_psbt *make_wsh_registry_psbt(const uint8_t *spk,
                                                 size_t spk_len,
                                                 const uint8_t *witness_script,
                                                 size_t witness_script_len) {
  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/48'/0'/0'/2'/0/0", &derived))
    return NULL;

  uint8_t kp_val[] = {
      0x00, 0x00, 0x00, 0x00, /* fp = 00000000 (matches stub) */
      0x30, 0x00, 0x00, 0x80, /* 48' */
      0x00, 0x00, 0x00, 0x80, /* 0'  */
      0x00, 0x00, 0x00, 0x80, /* 0'  */
      0x02, 0x00, 0x00, 0x80, /* 2'  */
      0x00, 0x00, 0x00, 0x00, /* chain 0 */
      0x00, 0x00, 0x00, 0x00, /* index 0 */
  };

  struct wally_psbt *psbt =
      make_test_psbt(spk, spk_len, derived->pub_key, sizeof(derived->pub_key),
                     kp_val, sizeof(kp_val));
  bip32_key_free(derived);
  if (!psbt)
    return NULL;
  if (wally_psbt_set_input_witness_script(psbt, 0, witness_script,
                                          witness_script_len) != WALLY_OK) {
    wally_psbt_free(psbt);
    return NULL;
  }
  return psbt;
}

/* Positive case for the wsh(sortedmulti) registry path: SPK matches,
 * witness_script matches -> OWNED_SAFE via CLAIM_REGISTRY. */
static void test_psbt_classify_registry_wsh_owned(void) {
  TEST("psbt_classify_input: wsh(sortedmulti) registry-matched -> OWNED_SAFE");

  registry_clear();
  if (!registry_add_from_string("t", WSH_REGISTRY_DESC, STORAGE_FLASH, false)) {
    FAIL("registry_add_from_string");
    return;
  }

  struct wally_psbt *psbt =
      make_wsh_registry_psbt(REF_WSH_SPK, sizeof(REF_WSH_SPK), REF_WSH_WITNESS,
                             sizeof(REF_WSH_WITNESS));
  if (!psbt) {
    FAIL("make_wsh_registry_psbt");
    registry_clear();
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);
  registry_clear();

  if (r.ownership != PSBT_OWNERSHIP_OWNED_SAFE) {
    FAIL("expected OWNED_SAFE");
    return;
  }
  if (r.claim.kind != CLAIM_REGISTRY) {
    FAIL("expected CLAIM_REGISTRY");
    return;
  }
  PASS();
}

/* Tamper the wsh sortedmulti witness_script: SPK still matches (so the
 * registry entry's regen spk passes), but the byte-compare against the
 * provided witness_script fails. The classifier must reject SAFE and fall
 * through; no other claim shape matches the wsh spk for our key, so we land
 * on EXPECTED_OWNED -- the user can no longer unsafely-sign without first
 * also enabling expected-owned signing. */
static void test_psbt_classify_registry_wsh_tampered_witness(void) {
  TEST("psbt_classify_input: wsh(sortedmulti) tampered witness -> "
       "EXPECTED_OWNED");

  registry_clear();
  if (!registry_add_from_string("t", WSH_REGISTRY_DESC, STORAGE_FLASH, false)) {
    FAIL("registry_add_from_string");
    return;
  }

  uint8_t bad_witness[sizeof(REF_WSH_WITNESS)];
  memcpy(bad_witness, REF_WSH_WITNESS, sizeof(REF_WSH_WITNESS));
  bad_witness[3] ^= 0xff; /* flip a pubkey byte inside the multisig script */

  struct wally_psbt *psbt = make_wsh_registry_psbt(
      REF_WSH_SPK, sizeof(REF_WSH_SPK), bad_witness, sizeof(bad_witness));
  if (!psbt) {
    FAIL("make_wsh_registry_psbt");
    registry_clear();
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);
  registry_clear();

  if (r.ownership != PSBT_OWNERSHIP_EXPECTED_OWNED) {
    FAIL("expected EXPECTED_OWNED on tampered witness");
    return;
  }
  PASS();
}

/* Positive case for the wsh(miniscript) registry path: same shape as the
 * sortedmulti case but the witness script is an or_d/and_v/older miniscript
 * compilation. SPK matches, witness_script matches -> OWNED_SAFE. */
static void test_psbt_classify_registry_miniscript_owned(void) {
  TEST("psbt_classify_input: wsh(miniscript) registry-matched -> OWNED_SAFE");

  registry_clear();
  if (!registry_add_from_string("t", MS_REGISTRY_DESC, STORAGE_FLASH, false)) {
    FAIL("registry_add_from_string");
    return;
  }

  struct wally_psbt *psbt = make_wsh_registry_psbt(
      REF_MS_SPK, sizeof(REF_MS_SPK), REF_MS_WITNESS, sizeof(REF_MS_WITNESS));
  if (!psbt) {
    FAIL("make_wsh_registry_psbt");
    registry_clear();
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);
  registry_clear();

  if (r.ownership != PSBT_OWNERSHIP_OWNED_SAFE) {
    FAIL("expected OWNED_SAFE");
    return;
  }
  if (r.claim.kind != CLAIM_REGISTRY) {
    FAIL("expected CLAIM_REGISTRY");
    return;
  }
  PASS();
}

/* Tampered wsh(miniscript) witness: SPK matches but the witness byte-compare
 * fails -> EXPECTED_OWNED, same as the sortedmulti tamper case. */
static void test_psbt_classify_registry_miniscript_tampered(void) {
  TEST("psbt_classify_input: wsh(miniscript) tampered witness -> "
       "EXPECTED_OWNED");

  registry_clear();
  if (!registry_add_from_string("t", MS_REGISTRY_DESC, STORAGE_FLASH, false)) {
    FAIL("registry_add_from_string");
    return;
  }

  uint8_t bad_witness[sizeof(REF_MS_WITNESS)];
  memcpy(bad_witness, REF_MS_WITNESS, sizeof(REF_MS_WITNESS));
  bad_witness[3] ^= 0xff; /* flip a pubkey byte inside the miniscript */

  struct wally_psbt *psbt = make_wsh_registry_psbt(
      REF_MS_SPK, sizeof(REF_MS_SPK), bad_witness, sizeof(bad_witness));
  if (!psbt) {
    FAIL("make_wsh_registry_psbt");
    registry_clear();
    return;
  }

  input_ownership_t r = psbt_classify_input(psbt, 0, false);
  wally_psbt_free(psbt);
  registry_clear();

  if (r.ownership != PSBT_OWNERSHIP_EXPECTED_OWNED) {
    FAIL("expected EXPECTED_OWNED on tampered witness");
    return;
  }
  PASS();
}

/* Mixed two-input PSBT: input 0 is OWNED_SAFE (BIP84 verified), input 1 is
 * EXTERNAL (foreign fp). Verifies each input is classified independently and
 * that the per-input policy gate in psbt_sign signs exactly one of them. */
static void test_psbt_classify_multi_input_mixed(void) {
  struct ext_key *derived = NULL;
  if (!key_get_derived_key("m/84'/0'/0'/0/0", &derived)) {
    TEST("psbt_classify_multi_input: setup");
    FAIL("key derivation failed");
    return;
  }

  uint8_t kp_owned[] = {
      0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
      0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  uint8_t kp_external[] = {
      0xde, 0xad, 0xbe, 0xef, /* foreign fp -> EXTERNAL */
      0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
      0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  /* Use a distinct external pubkey (just the derived pubkey reversed in the
   * leading byte) so the second input's keypath/pubkey pair doesn't collide
   * with the first. The fp mismatch is the real EXTERNAL signal. */
  uint8_t ext_pubkey[EC_PUBLIC_KEY_LEN];
  memcpy(ext_pubkey, derived->pub_key, sizeof(ext_pubkey));
  ext_pubkey[0] = (derived->pub_key[0] == 0x02) ? 0x03 : 0x02;

  struct wally_psbt *psbt = make_two_input_psbt(
      REF_SPK_P2WPKH, sizeof(REF_SPK_P2WPKH), derived->pub_key,
      sizeof(derived->pub_key), kp_owned, sizeof(kp_owned), REF_SPK_P2PKH,
      sizeof(REF_SPK_P2PKH), ext_pubkey, sizeof(ext_pubkey), kp_external,
      sizeof(kp_external));
  bip32_key_free(derived);
  if (!psbt) {
    TEST("psbt_classify_multi_input: setup");
    FAIL("make_two_input_psbt");
    return;
  }

  TEST("psbt_classify_multi_input: input 0 -> OWNED_SAFE");
  input_ownership_t r0 = psbt_classify_input(psbt, 0, false);
  if (r0.ownership != PSBT_OWNERSHIP_OWNED_SAFE) {
    wally_psbt_free(psbt);
    FAIL("input 0 should classify as OWNED_SAFE");
    return;
  }
  PASS();

  TEST("psbt_classify_multi_input: input 1 -> EXTERNAL");
  input_ownership_t r1 = psbt_classify_input(psbt, 1, false);
  if (r1.ownership != PSBT_OWNERSHIP_EXTERNAL) {
    wally_psbt_free(psbt);
    FAIL("input 1 should classify as EXTERNAL");
    return;
  }
  PASS();

  TEST("psbt_sign multi-input: permissive policy signs exactly the owned "
       "input");
  psbt_sign_policy_t policy = {.allow_unsafe = true,
                               .allow_expected_owned = true};
  size_t n = psbt_sign(psbt, false, policy);
  wally_psbt_free(psbt);
  if (n != 1) {
    FAIL("expected exactly 1 signature on the mixed PSBT");
    return;
  }
  PASS();
}

/* ------------------------------------------------------------------ */

/* Register desc_str and regenerate its scripts into *out.
 * Returns NULL on success, or the name of the failing step. */
static const char *regen_registry_scripts(const char *desc_str,
                                          uint32_t multi_index,
                                          uint32_t child_num,
                                          expected_scripts_t *out) {
  registry_clear();
  if (!registry_add_from_string("t", desc_str, STORAGE_FLASH, false))
    return "registry_add_from_string";
  const registry_entry_t *e = registry_find_by_id("t");
  if (!e)
    return "entry not found";

  claim_t claim = {0};
  claim.kind = CLAIM_REGISTRY;
  claim.registry.entry = e;
  claim.registry.multi_index = multi_index;
  claim.registry.child_num = child_num;

  if (!claim_regenerate(&claim, false, out))
    return "claim_regenerate returned false";
  return NULL;
}

static void test_registry_claim(const char *test_name, const char *desc_str,
                                uint32_t multi_index, uint32_t child_num,
                                const uint8_t *ref_spk, size_t ref_spk_len,
                                const uint8_t *ref_redeem,
                                size_t ref_redeem_len,
                                const uint8_t *ref_witness,
                                size_t ref_witness_len) {
  TEST(test_name);
  expected_scripts_t out = {0};
  const char *err =
      regen_registry_scripts(desc_str, multi_index, child_num, &out);
  if (err) {
    FAIL(err);
    return;
  }

  if (out.spk_len != ref_spk_len) {
    FAIL("spk_len mismatch");
    return;
  }
  if (memcmp(out.spk, ref_spk, ref_spk_len) != 0) {
    FAIL("spk bytes mismatch");
    return;
  }
  if (out.redeem_len != ref_redeem_len) {
    FAIL("redeem_len mismatch");
    return;
  }
  if (ref_redeem_len > 0 &&
      memcmp(out.redeem, ref_redeem, ref_redeem_len) != 0) {
    FAIL("redeem mismatch");
    return;
  }
  if (out.witness_len != ref_witness_len) {
    FAIL("witness_len mismatch");
    return;
  }
  if (ref_witness_len > 0 &&
      memcmp(out.witness, ref_witness, ref_witness_len) != 0) {
    FAIL("witness mismatch");
    return;
  }
  PASS();
}

/* sortedmulti witness script size: 3 + 34 * num_keys. 15 keys (513 bytes) is
 * libwally's generation maximum: CHECKMULTISIG is capped at 15 keys and
 * sh()/wsh() inner scripts at 520 bytes (PSBT_MAX_INNER_SCRIPT_LEN). */
#define MS_15_KEYS                                                             \
  "[00000000/48'/0'/0'/2']" XPUB_84 "/0/*,"                                    \
  "[11111111/48'/0'/0'/2']" XPUB_86 "/0/*,"                                    \
  "[22222222/48'/0'/0'/2']" XPUB_84 "/1/*,"                                    \
  "[33333333/48'/0'/0'/2']" XPUB_86 "/1/*,"                                    \
  "[44444444/48'/0'/0'/2']" XPUB_84 "/2/*,"                                    \
  "[55555555/48'/0'/0'/2']" XPUB_86 "/2/*,"                                    \
  "[66666666/48'/0'/0'/2']" XPUB_84 "/3/*,"                                    \
  "[77777777/48'/0'/0'/2']" XPUB_86 "/3/*,"                                    \
  "[88888888/48'/0'/0'/2']" XPUB_84 "/4/*,"                                    \
  "[99999999/48'/0'/0'/2']" XPUB_86 "/4/*,"                                    \
  "[aaaaaaaa/48'/0'/0'/2']" XPUB_84 "/5/*,"                                    \
  "[bbbbbbbb/48'/0'/0'/2']" XPUB_86 "/5/*,"                                    \
  "[cccccccc/48'/0'/0'/2']" XPUB_84 "/6/*,"                                    \
  "[dddddddd/48'/0'/0'/2']" XPUB_86 "/6/*,"                                    \
  "[eeeeeeee/48'/0'/0'/2']" XPUB_84 "/7/*"

static void test_registry_claim_wsh_witness_size(const char *test_name,
                                                 const char *desc_str,
                                                 size_t expected_witness_len) {
  TEST(test_name);
  expected_scripts_t out = {0};
  const char *err = regen_registry_scripts(desc_str, 0, 0, &out);
  if (err) {
    FAIL(err);
    return;
  }
  if (out.witness_len != expected_witness_len) {
    FAIL("witness_len mismatch");
    return;
  }
  PASS();
}

static void test_registry_claim_oversize_wsh_fails(void) {
  TEST("wsh(sortedmulti 8-of-16): regeneration fails cleanly");
  /* 16 keys parse (libwally allows up to 20) but cannot generate; descriptor
   * validation rejects these at load time (VALIDATION_UNSUPPORTED_SCRIPT). */
  const char *desc = "wsh(sortedmulti(8," MS_15_KEYS
                     ",[ffffffff/48'/0'/0'/2']" XPUB_86 "/7/*))";
  expected_scripts_t out = {0};
  const char *err = regen_registry_scripts(desc, 0, 0, &out);
  if (!err) {
    FAIL("expected claim_regenerate to fail");
    return;
  }
  if (strcmp(err, "claim_regenerate returned false") != 0) {
    FAIL(err);
    return;
  }
  PASS();
}

/* ------------------------------------------------------------------ */

int main(void) {
  printf("=== claim_regenerate whitelist tests ===\n\n");

  TEST("key_load_from_mnemonic");
  if (!key_load_from_mnemonic(TEST_MNEMONIC, "", false)) {
    FAIL("failed to load mnemonic");
    printf("\n=== ABORT ===\n");
    return 1;
  }
  PASS();

  test_whitelist_claim("P2PKH spk+redeem", SS_SCRIPT_P2PKH, 44, REF_SPK_P2PKH,
                       sizeof(REF_SPK_P2PKH), false);
  test_whitelist_claim("P2SH-P2WPKH spk+redeem", SS_SCRIPT_P2SH_P2WPKH, 49,
                       REF_SPK_P2SH_P2WPKH, sizeof(REF_SPK_P2SH_P2WPKH), true);
  test_whitelist_claim("P2WPKH spk+redeem", SS_SCRIPT_P2WPKH, 84,
                       REF_SPK_P2WPKH, sizeof(REF_SPK_P2WPKH), false);
  test_whitelist_claim("P2TR spk+redeem", SS_SCRIPT_P2TR, 86, REF_SPK_P2TR,
                       sizeof(REF_SPK_P2TR), false);

  key_unload();

  printf("\n=== claim_regenerate registry tests ===\n\n");

  test_registry_claim("wsh(sortedmulti 2-of-2)",
                      "wsh(sortedmulti(2,"
                      "[00000000/48'/0'/0'/2']" XPUB_84 "/0/*,"
                      "[11111111/48'/0'/0'/2']" XPUB_86 "/0/*"
                      "))#6nfc46dh",
                      0, 0, REF_WSH_SPK, sizeof(REF_WSH_SPK), NULL, 0,
                      REF_WSH_WITNESS, sizeof(REF_WSH_WITNESS));

  test_registry_claim("sh(wsh(sortedmulti 2-of-2))",
                      "sh(wsh(sortedmulti(2,"
                      "[00000000/48'/0'/0'/2']" XPUB_84 "/0/*,"
                      "[11111111/48'/0'/0'/2']" XPUB_86 "/0/*"
                      ")))",
                      0, 0, REF_SHWSH_SPK, sizeof(REF_SHWSH_SPK), REF_WSH_SPK,
                      sizeof(REF_WSH_SPK), /* P2WSH redeem == WSH SPK */
                      REF_SHWSH_WITNESS, sizeof(REF_SHWSH_WITNESS));

  test_registry_claim("sh(multi(2-of-2))",
                      "sh(multi(2,"
                      "[00000000/48'/0'/0'/1']" XPUB_84 "/0/*,"
                      "[11111111/48'/0'/0'/1']" XPUB_86 "/0/*"
                      "))",
                      0, 0, REF_SHMU_SPK, sizeof(REF_SHMU_SPK), REF_SHMU_REDEEM,
                      sizeof(REF_SHMU_REDEEM), NULL, 0);

  test_registry_claim("tr([00000000/86'/0'/0']xpub/0/*)",
                      "tr([00000000/86'/0'/0']" XPUB_86 "/0/*)", 0, 0,
                      REF_TR_SPK, sizeof(REF_TR_SPK), NULL, 0, NULL, 0);

  test_registry_claim("wsh(or_d(pk(A),and_v(v:pkh(B),older(65535))))",
                      MS_REGISTRY_DESC, 0, 0, REF_MS_SPK, sizeof(REF_MS_SPK),
                      NULL, 0, REF_MS_WITNESS, sizeof(REF_MS_WITNESS));

  test_registry_claim("sh(wsh(pkh([00000000/49'/0'/0']xpub/0/*)))",
                      "sh(wsh(pkh([00000000/49'/0'/0']" XPUB_84 "/0/*)))", 0, 0,
                      REF_SHWSH_PKH_SPK, sizeof(REF_SHWSH_PKH_SPK),
                      REF_SHWSH_PKH_REDEEM, sizeof(REF_SHWSH_PKH_REDEEM),
                      REF_SHWSH_PKH_WITNESS, sizeof(REF_SHWSH_PKH_WITNESS));
  test_registry_claim_wsh_witness_size(
      "wsh(sortedmulti 5-of-8): 275-byte witness regenerates",
      "wsh(sortedmulti(5,"
      "[00000000/48'/0'/0'/2']" XPUB_84 "/0/*,"
      "[11111111/48'/0'/0'/2']" XPUB_86 "/0/*,"
      "[22222222/48'/0'/0'/2']" XPUB_84 "/1/*,"
      "[33333333/48'/0'/0'/2']" XPUB_86 "/1/*,"
      "[44444444/48'/0'/0'/2']" XPUB_84 "/2/*,"
      "[55555555/48'/0'/0'/2']" XPUB_86 "/2/*,"
      "[66666666/48'/0'/0'/2']" XPUB_84 "/3/*,"
      "[77777777/48'/0'/0'/2']" XPUB_86 "/3/*"
      "))",
      275);
  test_registry_claim_wsh_witness_size(
      "wsh(sortedmulti 8-of-15): 513-byte witness regenerates (max)",
      "wsh(sortedmulti(8," MS_15_KEYS "))", 513);
  test_registry_claim_oversize_wsh_fails();

  printf("\n=== psbt_classify_input tests ===\n\n");

  TEST("key_load_from_mnemonic (for psbt_classify)");
  if (!key_load_from_mnemonic(TEST_MNEMONIC, "", false)) {
    FAIL("failed to load mnemonic");
    printf("\n=== ABORT ===\n");
    return 1;
  }
  PASS();

  test_psbt_classify_fixture_a();
  test_psbt_classify_fixture_a_p2sh_p2wpkh();
  test_psbt_classify_fixture_a_testnet();
  test_psbt_classify_fixture_d();
  test_psbt_classify_fixture_e();
  test_psbt_classify_fixture_f();

  printf("\n=== psbt_classify_output tests ===\n\n");

  test_psbt_classify_fixture_b();
  test_psbt_classify_fixture_c();

  printf("\n=== psbt_classify adversarial tests ===\n\n");

  test_psbt_classify_adv_fp_mismatch();
  test_psbt_classify_adv_keypath_truncated();
  test_psbt_classify_adv_keypath_fp_only();
  test_psbt_classify_adv_mixed_script();
  test_psbt_classify_adv_registry_depth_mismatch();
  test_psbt_classify_adv_taproot_foreign_fp();
  test_psbt_classify_adv_testnet_flag_mismatch();

  printf("\n=== psbt_sign policy-gate tests ===\n\n");

  test_psbt_sign_gate_unsafe_blocked();
  test_psbt_sign_gate_unsafe_allowed();
  test_psbt_sign_gate_expected_blocked();
  test_psbt_sign_gate_external_always_skipped();
  test_psbt_classify_multi_input_mixed();
  test_psbt_classify_registry_wsh_owned();
  test_psbt_classify_registry_wsh_tampered_witness();
  test_psbt_classify_registry_miniscript_owned();
  test_psbt_classify_registry_miniscript_tampered();

  key_unload();

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
