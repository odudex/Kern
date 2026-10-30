#include "self_test.h"
#include "../utils/secure_mem.h"
#include "crypto_utils.h"
#include "dice_mnemonic.h"
#include "kern_wally.h"
#include "key.h"
#include "message_sign.h"
#include "pbkdf2.h"
#include "script_templates.h"
#include "secp_hardening.h"
#include "wallet.h"
#include <esp_log.h>
#include <esp_timer.h>
#include <psa/crypto.h>
#include <sdkconfig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_transaction.h>

static const char *TAG = "self_test";

typedef enum { CHECK_PASS, CHECK_FAIL, CHECK_SKIP } check_status_t;

#define H(n) ((n) | BIP32_INITIAL_HARDENED_CHILD)

/* BIP39's test mnemonic, whose BIP84 keys and address are BIP84's vectors. */
static const char *ABANDON = "abandon abandon abandon abandon abandon abandon "
                             "abandon abandon abandon abandon abandon about";
#define ABANDON_FP "73c5da0a"
#define ABANDON_XPUB_86                                                        \
  "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKD"  \
  "P9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
#define NUMS_H                                                                 \
  "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
static const uint32_t BIP84_ACCOUNT[] = {H(84), H(0), H(0)};
static const uint32_t BIP84_FIRST[] = {H(84), H(0), H(0), 0, 0};

static bool hex_matches(const char *what, const uint8_t *got, size_t len,
                        const char *want) {
  char hex[2 * 80 + 1];
  if (!got || len > 80)
    return false;
  for (size_t i = 0; i < len; i++)
    snprintf(hex + 2 * i, 3, "%02x", got[i]);
  if (strcmp(hex, want) == 0)
    return true;
  ESP_LOGE(TAG, "%s: got %s", what, hex);
  return false;
}

static bool str_matches(const char *what, const char *got, const char *want) {
  if (got && strcmp(got, want) == 0)
    return true;
  ESP_LOGE(TAG, "%s: got %s", what, got ? got : "nothing");
  return false;
}

static bool unhex(const char *hex, uint8_t *out, size_t len) {
  size_t written = 0;
  return wally_hex_to_bytes(hex, out, len, &written) == WALLY_OK &&
         written == len;
}

/* ---- Hashing and AES on their engines ---- */

#define SHA256_ABC                                                             \
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

/* FIPS 180-2's one million 'a', streamed through a thousand updates. */
static bool sha256_million_a(uint8_t out[SHA256_LEN]) {
  uint8_t chunk[1000];
  memset(chunk, 'a', sizeof(chunk));
  psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
  size_t len = 0;
  bool ok = psa_hash_setup(&op, PSA_ALG_SHA_256) == PSA_SUCCESS;
  for (int i = 0; ok && i < 1000; i++)
    ok = psa_hash_update(&op, chunk, sizeof(chunk)) == PSA_SUCCESS;
  ok = ok && psa_hash_finish(&op, out, SHA256_LEN, &len) == PSA_SUCCESS &&
       len == SHA256_LEN;
  psa_hash_abort(&op);
  return ok;
}

static check_status_t check_sha256(void) {
  uint8_t h[SHA256_LEN];
  bool ok =
      crypto_sha256((const uint8_t *)"abc", 3, h) == CRYPTO_OK &&
      hex_matches("SHA-256 abc", h, sizeof(h), SHA256_ABC) &&
      crypto_sha256((const uint8_t *)"", 0, h) == CRYPTO_OK &&
      hex_matches(
          "SHA-256 empty", h, sizeof(h),
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") &&
      wally_sha256((const unsigned char *)"abc", 3, h, sizeof(h)) == WALLY_OK &&
      hex_matches("libwally SHA-256 abc", h, sizeof(h), SHA256_ABC) &&
      sha256_million_a(h) &&
      hex_matches(
          "SHA-256 one million a", h, sizeof(h),
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  return ok ? CHECK_PASS : CHECK_FAIL;
}

/* FIPS 180-2 and RFC 4231 test case 2. */
static check_status_t check_sha512_hmac(void) {
  static const char *data = "what do ya want for nothing?";
  uint8_t h[SHA512_LEN];
  bool ok =
      wally_sha512((const unsigned char *)"abc", 3, h, sizeof(h)) == WALLY_OK &&
      hex_matches("SHA-512 abc", h, sizeof(h),
                  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55"
                  "d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94f"
                  "a54ca49f") &&
      wally_hmac_sha512((const unsigned char *)"Jefe", 4,
                        (const unsigned char *)data, strlen(data), h,
                        sizeof(h)) == WALLY_OK &&
      hex_matches("HMAC-SHA512", h, sizeof(h),
                  "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea25"
                  "05549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a"
                  "38bce737");
  return ok ? CHECK_PASS : CHECK_FAIL;
}

/* CTR's keystream block i is ECB(nonce || BE32(i)), the counter from zero. */
static bool aes_ctr_matches_ecb(const uint8_t key[CRYPTO_AES_KEY_SIZE]) {
  uint8_t nonce[CRYPTO_AES_CTR_NONCE_SIZE], pt[53], ct[53], blocks[64],
      stream[64];
  for (size_t i = 0; i < sizeof(nonce); i++)
    nonce[i] = (uint8_t)(0xa0 + i);
  for (size_t i = 0; i < sizeof(pt); i++)
    pt[i] = (uint8_t)(i * 7);
  memset(blocks, 0, sizeof(blocks));
  for (size_t i = 0; i < 4; i++) {
    memcpy(blocks + 16 * i, nonce, sizeof(nonce));
    blocks[16 * i + 15] = (uint8_t)i;
  }
  if (crypto_aes_ctr(key, nonce, pt, sizeof(pt), ct) != CRYPTO_OK ||
      crypto_aes_ecb_encrypt(key, blocks, sizeof(blocks), stream) != CRYPTO_OK)
    return false;
  for (size_t i = 0; i < sizeof(pt); i++) {
    if (ct[i] != (pt[i] ^ stream[i])) {
      ESP_LOGE(TAG, "AES-256-CTR: byte %u is not ECB's keystream", (unsigned)i);
      return false;
    }
  }
  return true;
}

/* FIPS-197 C.3, SP800-38A F.2.5 and NIST GCM test case 14. */
static check_status_t check_aes(void) {
  uint8_t key[CRYPTO_AES_KEY_SIZE], iv[CRYPTO_AES_IV_SIZE], pt[32], ct[32],
      back[32], tag[16];
  bool ok =
      unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            key, sizeof(key)) &&
      unhex("00112233445566778899aabbccddeeff", pt, 16) &&
      crypto_aes_ecb_encrypt(key, pt, 16, ct) == CRYPTO_OK &&
      hex_matches("AES-256-ECB", ct, 16, "8ea2b7ca516745bfeafc49904b496089") &&
      crypto_aes_ecb_decrypt(key, ct, 16, back) == CRYPTO_OK &&
      memcmp(back, pt, 16) == 0;
  ok =
      ok &&
      unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            key, sizeof(key)) &&
      unhex("000102030405060708090a0b0c0d0e0f", iv, sizeof(iv)) &&
      unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
            pt, 32) &&
      crypto_aes_cbc_encrypt(key, iv, pt, 32, ct) == CRYPTO_OK &&
      hex_matches(
          "AES-256-CBC", ct, 32,
          "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d") &&
      crypto_aes_cbc_decrypt(key, iv, ct, 32, back) == CRYPTO_OK &&
      memcmp(back, pt, 32) == 0 && aes_ctr_matches_ecb(key);
  uint8_t nonce[CRYPTO_AES_GCM_NONCE_SIZE] = {0};
  memset(key, 0, sizeof(key));
  memset(pt, 0, 16);
  ok = ok &&
       crypto_aes_gcm_encrypt(key, nonce, sizeof(nonce), pt, 16, ct, tag,
                              sizeof(tag)) == CRYPTO_OK &&
       hex_matches("AES-256-GCM ciphertext", ct, 16,
                   "cea7403d4d606b6e074ec5d3baf39d18") &&
       hex_matches("AES-256-GCM tag", tag, sizeof(tag),
                   "d0d1c8a799996bf0265b98b5d48ab919") &&
       crypto_aes_gcm_decrypt(key, nonce, sizeof(nonce), ct, 16, back, tag,
                              sizeof(tag)) == CRYPTO_OK &&
       memcmp(back, pt, 16) == 0;
  return ok ? CHECK_PASS : CHECK_FAIL;
}

/* ---- PBKDF2 and BIP39 ---- */

/* The vectors below exercise the accelerated loop's chunks, which this c=2
 * check never reaches; it only shows whether derivations run on the engine. */
static check_status_t check_pbkdf2_accelerator(void) {
#ifdef CONFIG_KERN_PBKDF2_HW_SHA
  if (pbkdf2_hw_active())
    return CHECK_PASS;
  ESP_LOGE(TAG, "PBKDF2 accelerator failed its check: PIN, KEF and BIP39 "
                "derivations fall back to software");
  return CHECK_FAIL;
#else
  return CHECK_SKIP;
#endif
}

static bool pbkdf2_matches(const char *what, bool sha512, const char *password,
                           const char *salt, uint32_t iterations, size_t len,
                           const char *want) {
  uint8_t out[64];
  const uint8_t *pw = (const uint8_t *)password, *s = (const uint8_t *)salt;
  if (len > sizeof(out))
    return false;
  int ret = sha512 ? crypto_pbkdf2_sha512(pw, strlen(password), s, strlen(salt),
                                          iterations, out, len)
                   : crypto_pbkdf2_sha256(pw, strlen(password), s, strlen(salt),
                                          iterations, out, len);
  return ret == CRYPTO_OK && hex_matches(what, out, len, want);
}

/* RFC 6070's inputs, and KEF's iteration count at its own test key and ID. */
static check_status_t check_pbkdf2_sha256(void) {
  bool ok =
      pbkdf2_matches(
          "PBKDF2-SHA256 c=4096", false, "password", "salt", 4096, 32,
          "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a") &&
      pbkdf2_matches("PBKDF2-SHA256 dkLen 40", false,
                     "passwordPASSWORDpassword",
                     "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
                     "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb"
                     "8dd53e1c635518c7dac47e9") &&
      pbkdf2_matches(
          "PBKDF2-SHA256 KEF 100k", false, "test key", "test ID", 100000, 32,
          "e375234c207fc71d82cc430718cd0dbbf6785a05b6806399e4432d7dd1850abc");
  return ok ? CHECK_PASS : CHECK_FAIL;
}

static check_status_t check_pbkdf2_sha512(void) {
  return pbkdf2_matches("PBKDF2-SHA512 c=4096", true, "password", "salt", 4096,
                        64,
                        "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902"
                        "e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532"
                        "e039b742a239434af2d5")
             ? CHECK_PASS
             : CHECK_FAIL;
}

static bool seed_matches(const char *what, const char *mnemonic,
                         const char *want) {
  uint8_t seed[BIP39_SEED_LEN_512];
  bool ok = kern_bip39_mnemonic_validate(NULL, mnemonic) == WALLY_OK &&
            kern_bip39_mnemonic_to_seed512(mnemonic, "TREZOR", seed,
                                           sizeof(seed)) == WALLY_OK &&
            hex_matches(what, seed, sizeof(seed), want);
  secure_memzero(seed, sizeof(seed));
  return ok;
}

/* BIP39's TREZOR vectors; the 24-word mnemonic is longer than a SHA-512
 * block, so its HMAC key is hashed first. */
static check_status_t check_bip39_seed(void) {
  bool ok =
      seed_matches("BIP39 seed, 12 words", ABANDON,
                   "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5"
                   "3495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f00"
                   "1698e7463b04") &&
      seed_matches("BIP39 seed, 24 words",
                   "letter advice cage absurd amount doctor acoustic avoid "
                   "letter advice cage absurd amount doctor acoustic avoid "
                   "letter advice cage absurd amount doctor acoustic bless",
                   "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed"
                   "8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a958909706972"
                   "0d015e4e982f");
  return ok ? CHECK_PASS : CHECK_FAIL;
}

/* ---- Keys and signatures, from ABANDON with no passphrase ---- */

static struct ext_key *abandon_master(void) {
  uint8_t seed[BIP39_SEED_LEN_512];
  struct ext_key *master = NULL;
  if (kern_bip39_mnemonic_to_seed512(ABANDON, NULL, seed, sizeof(seed)) ==
      WALLY_OK)
    (void)kern_bip32_key_from_seed_alloc(seed, sizeof(seed),
                                         BIP32_VER_MAIN_PRIVATE, 0, &master);
  secure_memzero(seed, sizeof(seed));
  return master;
}

static struct ext_key *derive(const struct ext_key *master,
                              const uint32_t *path, size_t len) {
  struct ext_key *child = NULL;
  if (!master)
    return NULL;
  (void)kern_bip32_key_from_parent_path_alloc(master, path, len,
                                              BIP32_FLAG_KEY_PRIVATE, &child);
  return child;
}

static bool xpub_matches(const char *what, const struct ext_key *key,
                         const char *want) {
  char *xpub = NULL;
  bool ok =
      bip32_key_to_base58(key, BIP32_FLAG_KEY_PUBLIC, &xpub) == WALLY_OK &&
      str_matches(what, xpub, want);
  wally_free_string(xpub);
  return ok;
}

/* BIP32's derivation and BIP84's account xpub and first address. */
static check_status_t check_bip32(void) {
  struct ext_key *master = abandon_master();
  struct ext_key *account = derive(master, BIP84_ACCOUNT, 3);
  struct ext_key *first = derive(master, BIP84_FIRST, 5);
  uint8_t fp[BIP32_KEY_FINGERPRINT_LEN], spk[SCRIPT_TEMPLATE_MAX_SPK_LEN];
  size_t spk_len = 0;
  char *address = NULL;
  bool ok =
      account && first &&
      bip32_key_get_fingerprint(master, fp, sizeof(fp)) == WALLY_OK &&
      hex_matches("master fingerprint", fp, sizeof(fp), ABANDON_FP) &&
      xpub_matches("master xpub", master,
                   "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qa"
                   "fCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8") &&
      xpub_matches("BIP84 account xpub", account,
                   "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3Xyu"
                   "vPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V") &&
      script_template_from_pubkey(SCRIPT_TEMPLATE_P2WPKH, first->pub_key,
                                  EC_PUBLIC_KEY_LEN, spk, &spk_len, NULL,
                                  NULL) &&
      (address = script_template_address_from_spk(spk, spk_len, false)) &&
      str_matches("BIP84 first address", address,
                  "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
  wally_free_string(address);
  bip32_key_free(first);
  bip32_key_free(account);
  bip32_key_free(master);
  return ok ? CHECK_PASS : CHECK_FAIL;
}

/* BIP85's own master key and 12-word vector. */
static check_status_t check_bip85(void) {
  struct ext_key master;
  char *mnemonic = NULL;
  bool ok = bip32_key_from_base58("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq"
                                  "2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1"
                                  "LqdGhUtyoFnCNkfmXRyPXLjbKb",
                                  &master) == WALLY_OK &&
            key_bip85_mnemonic(&master, 12, 0, &mnemonic) &&
            str_matches("BIP85 12 words", mnemonic,
                        "girl mad pet galaxy egg matter matrix prison refuse "
                        "sense ordinary nose");
  SECURE_FREE_STRING(mnemonic);
  secure_memzero(&master, sizeof(master));
  return ok ? CHECK_PASS : CHECK_FAIL;
}

/* "Hello Kern" at m/84'/0'/0'/0/0, signed by an independent RFC6979
 * implementation. */
static check_status_t check_message_signature(void) {
  struct ext_key *master = abandon_master();
  struct ext_key *first = derive(master, BIP84_FIRST, 5);
  char *signature = NULL;
  (void)secp_blind_refresh();
  bool ok =
      first && message_sign_with_key(first, "Hello Kern", &signature) &&
      str_matches("message signature", signature,
                  "H6/HLXbHJ4WR/1apaOHCnsBah1Zecvpahhr1VvIIjeROOrvlI0Ky150k"
                  "TVQeiGhSKWabus6Hu7NzUXbrWKvVWLs=");
  wally_free_string(signature);
  bip32_key_free(first);
  bip32_key_free(master);
  return ok ? CHECK_PASS : CHECK_FAIL;
}

/* A one-input transaction paying to OP_RETURN, as the host tests build it. */
static struct wally_psbt *fixture_psbt(uint8_t txid0, uint32_t sequence,
                                       uint64_t amount) {
  static const uint8_t op_return[] = {0x6a};
  uint8_t txid[WALLY_TXHASH_LEN] = {txid0};
  struct wally_tx *tx = NULL;
  struct wally_psbt *psbt = NULL;
  if (wally_tx_init_alloc(2, 0, 1, 1, &tx) != WALLY_OK)
    return NULL;
  if (wally_tx_add_raw_input(tx, txid, sizeof(txid), 0, sequence, NULL, 0, NULL,
                             0) != WALLY_OK ||
      wally_tx_add_raw_output(tx, amount, op_return, sizeof(op_return), 0) !=
          WALLY_OK ||
      wally_psbt_from_tx(tx, 0, 0, &psbt) != WALLY_OK)
    psbt = NULL;
  wally_tx_free(tx);
  return psbt;
}

static bool set_utxo(struct wally_psbt *psbt, const uint8_t *spk,
                     size_t spk_len) {
  struct wally_tx_output *utxo = NULL;
  bool ok =
      wally_tx_output_init_alloc(100000, spk, spk_len, &utxo) == WALLY_OK &&
      wally_psbt_set_input_witness_utxo(psbt, 0, utxo) == WALLY_OK;
  wally_tx_output_free(utxo);
  return ok;
}

/* Signs as psbt_sign() does, after refreshing the blinding as signing does. */
static bool sign_psbt(struct wally_psbt *psbt, const struct ext_key *master) {
  (void)secp_blind_refresh();
  return wally_psbt_sign_bip32(psbt, master, EC_FLAG_GRIND_R) == WALLY_OK;
}

/* Bitcoin Core's CKey::Sign gives this signature too; the first RFC6979 nonce
 * has a high R, so it takes one low-R grinding step. */
static check_status_t check_psbt_segwit(void) {
  static const uint8_t spk[] = {0x00, 0x14, 0xc0, 0xce, 0xbc, 0xd6, 0xc3, 0xd3,
                                0xca, 0x8c, 0x75, 0xdc, 0x5e, 0xc6, 0x2e, 0xbe,
                                0x55, 0x33, 0x0e, 0xf9, 0x10, 0xe2};
  struct ext_key *master = abandon_master();
  struct ext_key *first = derive(master, BIP84_FIRST, 5);
  struct wally_psbt *psbt = fixture_psbt(0, 0xffffffff, 0);
  uint8_t fp[BIP32_KEY_FINGERPRINT_LEN];
  bool ok =
      first && psbt && set_utxo(psbt, spk, sizeof(spk)) &&
      bip32_key_get_fingerprint(master, fp, sizeof(fp)) == WALLY_OK &&
      wally_psbt_add_input_keypath(psbt, 0, first->pub_key, EC_PUBLIC_KEY_LEN,
                                   fp, sizeof(fp), BIP84_FIRST,
                                   5) == WALLY_OK &&
      sign_psbt(psbt, master) && psbt->inputs[0].signatures.num_items == 1 &&
      hex_matches("P2WPKH signature", psbt->inputs[0].signatures.items[0].value,
                  psbt->inputs[0].signatures.items[0].value_len,
                  "3044022072639180bbbaec17bee9427d14c7d8a6ae218700b04a2f"
                  "b248503d44bf07f6c902207da0d3365fe76f44bb0a2b6b4f639f07"
                  "fb34194cb691225633c873b7bb95902c01");
  wally_psbt_free(psbt);
  bip32_key_free(first);
  bip32_key_free(master);
  return ok ? CHECK_PASS : CHECK_FAIL;
}

/* Serialized and parsed again, as a scanned PSBT would be. */
static struct wally_psbt *reparse(struct wally_psbt *psbt) {
  struct wally_psbt *out = NULL;
  size_t len = 0, written = 0;
  unsigned char *bytes = NULL;
  if (psbt && wally_psbt_get_length(psbt, 0, &len) == WALLY_OK &&
      (bytes = malloc(len)) != NULL &&
      wally_psbt_to_bytes(psbt, 0, bytes, len, &written) == WALLY_OK &&
      written == len)
    (void)wally_psbt_from_bytes(bytes, len, 0, &out);
  free(bytes);
  wally_psbt_free(psbt);
  return out;
}

static struct wally_psbt *taproot_fixture(const char *descriptor) {
  struct wally_descriptor *d = NULL;
  struct wally_psbt *psbt = fixture_psbt(1, 0xfffffffd, 1000);
  uint8_t spk[34];
  size_t spk_len = 0;
  bool ok =
      psbt &&
      wallet_descriptor_parse(descriptor, NULL, WALLY_NETWORK_BITCOIN_MAINNET,
                              &d) == WALLY_OK &&
      wally_descriptor_to_script(d, 0, 0, 0, 0, 0, 0, spk, sizeof(spk),
                                 &spk_len) == WALLY_OK &&
      spk_len == sizeof(spk) && set_utxo(psbt, spk, spk_len) &&
      wally_psbt_input_populate_taproot_from_descriptor(psbt, 0, d, 0, 0, 0) ==
          WALLY_OK;
  /* As in the host tests: drop the origin-less NUMS key's bare fingerprint. */
  struct wally_map *paths = ok ? &psbt->inputs[0].taproot_leaf_paths : NULL;
  for (size_t j = paths ? paths->num_items : 0; ok && j-- > 0;)
    if (paths->items[j].value_len == BIP32_KEY_FINGERPRINT_LEN)
      ok = wally_map_remove(paths, paths->items[j].key,
                            paths->items[j].key_len) == WALLY_OK;
  wally_descriptor_free(d);
  if (!ok) {
    wally_psbt_free(psbt);
    return NULL;
  }
  return reparse(psbt);
}

/* Both checked once against an independent BIP340/341/342 implementation. */
static check_status_t check_psbt_taproot(void) {
  struct ext_key *master = abandon_master();
  struct wally_psbt *key_path = taproot_fixture(
      "tr([" ABANDON_FP "/86'/0'/0']" ABANDON_XPUB_86 "/<0;1>/*)");
  struct wally_psbt *script_path = taproot_fixture(
      "tr(" NUMS_H ",pk([" ABANDON_FP "/86'/0'/0']" ABANDON_XPUB_86 "/0/*))");
  uint8_t sig[EC_SIGNATURE_LEN + 1];
  size_t sig_len = 0;
  bool ok =
      master && key_path && script_path && sign_psbt(key_path, master) &&
      wally_psbt_get_input_taproot_signature(key_path, 0, sig, sizeof(sig),
                                             &sig_len) == WALLY_OK &&
      sig_len <= sizeof(sig) &&
      hex_matches("taproot key-path signature", sig, sig_len,
                  "abfdae8f79070b7ffafe4a8c2b25734df93b0ab465ae73b533d904ef93ed"
                  "3fe76ddf98f68d637e9e95cae8d71337b502ea3913b23bf54e6cce5c499d"
                  "64f8cbe7") &&
      sign_psbt(script_path, master) &&
      script_path->inputs[0].taproot_leaf_signatures.num_items == 1 &&
      hex_matches(
          "taproot script-path signature",
          script_path->inputs[0].taproot_leaf_signatures.items[0].value,
          script_path->inputs[0].taproot_leaf_signatures.items[0].value_len,
          "b374394027acae385967663d3c47e6d2b5fc34ba0820b7a2cd4bfebb9dd11fb12e6"
          "afb0fb45ae35556e4b0e8e73ad11aabd513f416099beee95e1de860208f27");
  wally_psbt_free(script_path);
  wally_psbt_free(key_path);
  bip32_key_free(master);
  return ok ? CHECK_PASS : CHECK_FAIL;
}

/* ---- Dice ---- */

static bool dice_matches(const char *rolls, size_t len, int words,
                         const char *want) {
  char *mnemonic = NULL;
  bool ok = dice_mnemonic_from_rolls(rolls, len, words, &mnemonic) &&
            str_matches("dice mnemonic", mnemonic, want);
  SECURE_FREE_STRING(mnemonic);
  return ok;
}

/* Expected mnemonics from Python's hashlib and an independent BIP39 encoder. */
static check_status_t check_dice(void) {
  static const char *mixed =
      "12345612345612345612345612345612345612345612345612345612";
  char ones[99];
  memset(ones, '1', sizeof(ones));
  bool ok =
      dice_matches(ones, 50, 12,
                   "diet glad hat rural panther lawsuit act drop gallery urge "
                   "where fit") &&
      dice_matches(ones, 99, 24,
                   "wheel erase puppy pistol chapter accuse carpet drop quote "
                   "final attend near scrap satisfy limit style crunch person "
                   "south inspire lunch meadow enact tattoo") &&
      dice_matches(mixed, strlen(mixed), 12,
                   "chest spatial into brick once toast dog gallery battle "
                   "flee stem miracle");
  return ok ? CHECK_PASS : CHECK_FAIL;
}

static const struct {
  const char *name;
  check_status_t (*run)(void);
} CHECKS[] = {
    {"SHA-256", check_sha256},
    {"SHA-512 and HMAC", check_sha512_hmac},
    {"AES-256", check_aes},
    {"PBKDF2 accelerator", check_pbkdf2_accelerator},
    {"PBKDF2-SHA256", check_pbkdf2_sha256},
    {"PBKDF2-SHA512", check_pbkdf2_sha512},
    {"BIP39 seed", check_bip39_seed},
    {"BIP32 keys and address", check_bip32},
    {"BIP85 child mnemonic", check_bip85},
    {"Message signature", check_message_signature},
    {"PSBT signature, SegWit", check_psbt_segwit},
    {"PSBT signature, Taproot", check_psbt_taproot},
    {"Dice rolls", check_dice},
};

size_t self_test_count(void) { return sizeof(CHECKS) / sizeof(CHECKS[0]); }

void self_test_run_all(self_test_result_t *results, volatile size_t *progress) {
  for (size_t i = 0; i < self_test_count(); i++) {
    int64_t start = esp_timer_get_time();
    check_status_t status = CHECKS[i].run();
    results[i] = (self_test_result_t){
        .name = CHECKS[i].name,
        .passed = status == CHECK_PASS,
        .skipped = status == CHECK_SKIP,
        .ms = (uint32_t)((esp_timer_get_time() - start + 500) / 1000),
    };
    if (status == CHECK_FAIL)
      ESP_LOGE(TAG, "%s failed", CHECKS[i].name);
    if (progress)
      *progress = i + 1;
  }
}
