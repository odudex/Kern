#include "bip138_crypto.h"

#include <esp_random.h>
#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>

static void bip138_sha256(void *ctx, const uint8_t *data, size_t len,
                          uint8_t *out) {
  (void)ctx;
  size_t out_len = 0;
  if (psa_crypto_init() != PSA_SUCCESS ||
      psa_hash_compute(PSA_ALG_SHA_256, data, len, out, 32, &out_len) !=
          PSA_SUCCESS ||
      out_len != 32) {
    for (size_t i = 0; i < 32; i++)
      out[i] = 0;
  }
}

static int32_t import_chacha_key(const uint8_t *key, psa_key_usage_t usage,
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

static int32_t bip138_aead_encrypt(void *ctx, const uint8_t *key,
                                   const uint8_t *nonce,
                                   const uint8_t *plaintext,
                                   size_t plaintext_len, uint8_t *out,
                                   size_t out_cap, size_t *out_len) {
  (void)ctx;
  if (psa_crypto_init() != PSA_SUCCESS)
    return -1;

  mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
  if (import_chacha_key(key, PSA_KEY_USAGE_ENCRYPT, &key_id) != 0)
    return -1;

  psa_status_t status = psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305,
                                         nonce, BIP138_NONCE_LEN, NULL, 0,
                                         plaintext, plaintext_len, out, out_cap,
                                         out_len);
  psa_destroy_key(key_id);
  return status == PSA_SUCCESS ? 0 : -1;
}

static int32_t bip138_aead_decrypt(void *ctx, const uint8_t *key,
                                   const uint8_t *nonce,
                                   const uint8_t *ciphertext,
                                   size_t ciphertext_len, uint8_t *out,
                                   size_t out_cap, size_t *out_len) {
  (void)ctx;
  if (psa_crypto_init() != PSA_SUCCESS)
    return -1;

  mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
  if (import_chacha_key(key, PSA_KEY_USAGE_DECRYPT, &key_id) != 0)
    return -1;

  psa_status_t status = psa_aead_decrypt(key_id, PSA_ALG_CHACHA20_POLY1305,
                                         nonce, BIP138_NONCE_LEN, NULL, 0,
                                         ciphertext, ciphertext_len, out,
                                         out_cap, out_len);
  psa_destroy_key(key_id);
  return status == PSA_SUCCESS ? 0 : -1;
}

static void bip138_fill_random(void *ctx, uint8_t *buf, size_t len) {
  (void)ctx;
  esp_fill_random(buf, len);
}

const bip138_crypto_vtable *kern_bip138_crypto_vtable(void) {
  static const bip138_crypto_vtable vtable = {
      .ctx = NULL,
      .sha256 = bip138_sha256,
      .aead_encrypt = bip138_aead_encrypt,
      .aead_decrypt = bip138_aead_decrypt,
      .fill_random = bip138_fill_random,
  };
  return &vtable;
}
