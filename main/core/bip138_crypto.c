#include "bip138_crypto.h"
#include "crypto_utils.h"
#include <psa/crypto.h>

static int sha256_cb(void *ctx, const uint8_t *data, size_t len,
                     uint8_t out[32]) {
  (void)ctx;
  return crypto_sha256(data, len, out) == CRYPTO_OK ? 0 : -1;
}

static int random_cb(void *ctx, uint8_t *buf, size_t len) {
  (void)ctx;
  return crypto_random_bytes(buf, len) == CRYPTO_OK ? 0 : -1;
}

static int import_chacha_key(const uint8_t key[32], psa_key_usage_t usage,
                             mbedtls_svc_key_id_t *key_id) {
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attrs, PSA_KEY_TYPE_CHACHA20);
  psa_set_key_bits(&attrs, 256);
  psa_set_key_usage_flags(&attrs, usage);
  psa_set_key_algorithm(&attrs, PSA_ALG_CHACHA20_POLY1305);
  psa_status_t status = psa_import_key(&attrs, key, 32, key_id);
  psa_reset_key_attributes(&attrs);
  return status == PSA_SUCCESS ? 0 : -1;
}

static int aead_encrypt_cb(void *ctx, const uint8_t key[32],
                           const uint8_t nonce[12], const uint8_t *pt,
                           size_t pt_len, uint8_t *ct) {
  (void)ctx;
  mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
  size_t out_len = 0;
  if (psa_crypto_init() != PSA_SUCCESS ||
      import_chacha_key(key, PSA_KEY_USAGE_ENCRYPT, &key_id) != 0)
    return -1;
  psa_status_t status = psa_aead_encrypt(
      key_id, PSA_ALG_CHACHA20_POLY1305, nonce, BIP138_NONCE_LEN, NULL, 0, pt,
      pt_len, ct, pt_len + BIP138_TAG_LEN, &out_len);
  psa_destroy_key(key_id);
  return status == PSA_SUCCESS && out_len == pt_len + BIP138_TAG_LEN ? 0 : -1;
}

static int aead_decrypt_cb(void *ctx, const uint8_t key[32],
                           const uint8_t nonce[12], const uint8_t *ct,
                           size_t ct_len, uint8_t *pt) {
  (void)ctx;
  mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
  size_t out_len = 0;
  if (ct_len < BIP138_TAG_LEN || psa_crypto_init() != PSA_SUCCESS ||
      import_chacha_key(key, PSA_KEY_USAGE_DECRYPT, &key_id) != 0)
    return -1;
  psa_status_t status = psa_aead_decrypt(
      key_id, PSA_ALG_CHACHA20_POLY1305, nonce, BIP138_NONCE_LEN, NULL, 0, ct,
      ct_len, pt, ct_len - BIP138_TAG_LEN, &out_len);
  psa_destroy_key(key_id);
  return status == PSA_SUCCESS && out_len == ct_len - BIP138_TAG_LEN ? 0 : -1;
}

const bip138_crypto *kern_bip138_crypto(void) {
  static const bip138_crypto crypto = {
      .ctx = NULL,
      .sha256 = sha256_cb,
      .aead_encrypt = aead_encrypt_cb,
      .aead_decrypt = aead_decrypt_cb,
      .random = random_cb,
  };
  return &crypto;
}
