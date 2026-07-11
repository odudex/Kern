#include "crypto_utils.h"
#include <esp_random.h>
#include <psa/crypto.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef SIMULATOR
/* Host mbedTLS predates PSA PBKDF2 (added in 3.5); use the legacy pkcs5 API
 * there. The simulator's force-included mbedtls_compat.h wraps it for 2.x. */
#include <mbedtls/pkcs5.h>
#endif

static bool ensure_psa_init(void) { return psa_crypto_init() == PSA_SUCCESS; }

static psa_status_t aes_key_import(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                                   psa_algorithm_t alg, psa_key_usage_t usage,
                                   mbedtls_svc_key_id_t *key_id) {
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attr, usage);
  psa_set_key_algorithm(&attr, alg);
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  return psa_import_key(&attr, key, CRYPTO_AES_KEY_SIZE, key_id);
}

static int aes_cipher_run(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                          psa_algorithm_t alg, bool encrypt, const uint8_t *iv,
                          size_t iv_len, const uint8_t *input, size_t input_len,
                          uint8_t *output) {
  if (!ensure_psa_init()) {
    return CRYPTO_ERR_INTERNAL;
  }

  mbedtls_svc_key_id_t key_id;
  psa_status_t st = aes_key_import(
      key, alg, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT,
      &key_id);
  if (st != PSA_SUCCESS) {
    return CRYPTO_ERR_INTERNAL;
  }

  psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
  st = encrypt ? psa_cipher_encrypt_setup(&op, key_id, alg)
               : psa_cipher_decrypt_setup(&op, key_id, alg);
  size_t out_len = 0;
  size_t fin_len = 0;
  if (st == PSA_SUCCESS && iv_len > 0) {
    st = psa_cipher_set_iv(&op, iv, iv_len);
  }
  if (st == PSA_SUCCESS) {
    st = psa_cipher_update(&op, input, input_len, output, input_len, &out_len);
  }
  if (st == PSA_SUCCESS) {
    st =
        psa_cipher_finish(&op, output + out_len, input_len - out_len, &fin_len);
  }
  psa_cipher_abort(&op);
  psa_destroy_key(key_id);
  return (st == PSA_SUCCESS && out_len + fin_len == input_len)
             ? CRYPTO_OK
             : CRYPTO_ERR_INTERNAL;
}

/* --- Key Derivation --- */

int crypto_pbkdf2_sha256(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t iterations, uint8_t *key_out,
                         size_t key_len) {
  if (!password || !salt || !key_out || iterations == 0 || key_len == 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

#ifdef SIMULATOR
  int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, password,
                                          password_len, salt, salt_len,
                                          iterations, key_len, key_out);
  return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
#else
  if (!ensure_psa_init()) {
    return CRYPTO_ERR_INTERNAL;
  }

  psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
  psa_status_t st =
      psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST,
                                          iterations);
  }
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                        salt, salt_len);
  }
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                        password, password_len);
  }
  if (st == PSA_SUCCESS) {
    st = psa_key_derivation_output_bytes(&op, key_out, key_len);
  }
  psa_key_derivation_abort(&op);
  return (st == PSA_SUCCESS) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
#endif
}

/* --- Hashing --- */

int crypto_sha256(const uint8_t *data, size_t data_len, uint8_t *hash_out) {
  if (!data || !hash_out) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  if (!ensure_psa_init()) {
    return CRYPTO_ERR_INTERNAL;
  }

  size_t hash_len = 0;
  psa_status_t st = psa_hash_compute(PSA_ALG_SHA_256, data, data_len, hash_out,
                                     CRYPTO_SHA256_SIZE, &hash_len);
  return (st == PSA_SUCCESS && hash_len == CRYPTO_SHA256_SIZE)
             ? CRYPTO_OK
             : CRYPTO_ERR_INTERNAL;
}

/* --- AES-256-ECB --- */

int crypto_aes_ecb_encrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output) {
  if (!key || !input || !output || input_len == 0 ||
      input_len % CRYPTO_AES_BLOCK_SIZE != 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  return aes_cipher_run(key, PSA_ALG_ECB_NO_PADDING, true, NULL, 0, input,
                        input_len, output);
}

int crypto_aes_ecb_decrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output) {
  if (!key || !input || !output || input_len == 0 ||
      input_len % CRYPTO_AES_BLOCK_SIZE != 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  return aes_cipher_run(key, PSA_ALG_ECB_NO_PADDING, false, NULL, 0, input,
                        input_len, output);
}

/* --- AES-256-CBC --- */

int crypto_aes_cbc_encrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t iv[CRYPTO_AES_IV_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output) {
  if (!key || !iv || !input || !output || input_len == 0 ||
      input_len % CRYPTO_AES_BLOCK_SIZE != 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  return aes_cipher_run(key, PSA_ALG_CBC_NO_PADDING, true, iv,
                        CRYPTO_AES_IV_SIZE, input, input_len, output);
}

int crypto_aes_cbc_decrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t iv[CRYPTO_AES_IV_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output) {
  if (!key || !iv || !input || !output || input_len == 0 ||
      input_len % CRYPTO_AES_BLOCK_SIZE != 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  return aes_cipher_run(key, PSA_ALG_CBC_NO_PADDING, false, iv,
                        CRYPTO_AES_IV_SIZE, input, input_len, output);
}

/* --- AES-256-CTR --- */

int crypto_aes_ctr(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                   const uint8_t nonce[CRYPTO_AES_CTR_NONCE_SIZE],
                   const uint8_t *input, size_t input_len, uint8_t *output) {
  if (!key || !nonce || !input || !output || input_len == 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  /* 16-byte counter block: 12-byte nonce + 4-byte counter starting at 0 */
  uint8_t counter[CRYPTO_AES_BLOCK_SIZE] = {0};
  memcpy(counter, nonce, CRYPTO_AES_CTR_NONCE_SIZE);

  return aes_cipher_run(key, PSA_ALG_CTR, true, counter, sizeof(counter), input,
                        input_len, output);
}

/* --- AES-256-GCM --- */

int crypto_aes_gcm_encrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *input, size_t input_len,
                           uint8_t *output, uint8_t *tag, size_t tag_len) {
  if (!key || !nonce || !input || !output || !tag || nonce_len == 0 ||
      tag_len == 0 || tag_len > 16) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  if (!ensure_psa_init()) {
    return CRYPTO_ERR_INTERNAL;
  }

  psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tag_len);
  mbedtls_svc_key_id_t key_id;
  if (aes_key_import(key, alg, PSA_KEY_USAGE_ENCRYPT, &key_id) != PSA_SUCCESS) {
    return CRYPTO_ERR_INTERNAL;
  }

  /* PSA one-shot AEAD emits ciphertext||tag contiguously; split afterwards */
  size_t scratch_len = input_len + tag_len;
  uint8_t *scratch = malloc(scratch_len);
  if (!scratch) {
    psa_destroy_key(key_id);
    return CRYPTO_ERR_INTERNAL;
  }

  size_t out_len = 0;
  psa_status_t st =
      psa_aead_encrypt(key_id, alg, nonce, nonce_len, NULL, 0, input, input_len,
                       scratch, scratch_len, &out_len);
  psa_destroy_key(key_id);
  if (st != PSA_SUCCESS || out_len != scratch_len) {
    free(scratch);
    return CRYPTO_ERR_INTERNAL;
  }

  memcpy(output, scratch, input_len);
  memcpy(tag, scratch + input_len, tag_len);
  free(scratch);
  return CRYPTO_OK;
}

int crypto_aes_gcm_decrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *input, size_t input_len,
                           uint8_t *output, const uint8_t *tag,
                           size_t tag_len) {
  if (!key || !nonce || !input || !output || !tag || nonce_len == 0 ||
      tag_len == 0 || tag_len > 16) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  if (!ensure_psa_init()) {
    return CRYPTO_ERR_INTERNAL;
  }

  psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, tag_len);
  mbedtls_svc_key_id_t key_id;
  if (aes_key_import(key, alg, PSA_KEY_USAGE_DECRYPT, &key_id) != PSA_SUCCESS) {
    return CRYPTO_ERR_INTERNAL;
  }

  size_t scratch_len = input_len + tag_len;
  uint8_t *scratch = malloc(scratch_len);
  if (!scratch) {
    psa_destroy_key(key_id);
    return CRYPTO_ERR_INTERNAL;
  }
  memcpy(scratch, input, input_len);
  memcpy(scratch + input_len, tag, tag_len);

  size_t out_len = 0;
  psa_status_t st =
      psa_aead_decrypt(key_id, alg, nonce, nonce_len, NULL, 0, scratch,
                       scratch_len, output, input_len, &out_len);
  psa_destroy_key(key_id);
  free(scratch);
  if (st == PSA_ERROR_INVALID_SIGNATURE) {
    return CRYPTO_ERR_AUTH_FAILED;
  }
  return (st == PSA_SUCCESS && out_len == input_len) ? CRYPTO_OK
                                                     : CRYPTO_ERR_INTERNAL;
}

/* --- Random --- */

void crypto_random_bytes(uint8_t *buf, size_t len) {
  if (buf && len > 0) {
    esp_fill_random(buf, len);
  }
}

/* --- Padding --- */

size_t crypto_pkcs7_pad(const uint8_t *input, size_t input_len, uint8_t *output,
                        size_t output_size) {
  if (!input || !output) {
    return 0;
  }

  uint8_t pad_len = CRYPTO_AES_BLOCK_SIZE - (input_len % CRYPTO_AES_BLOCK_SIZE);
  size_t padded_len = input_len + pad_len;

  if (padded_len > output_size) {
    return 0;
  }

  memcpy(output, input, input_len);
  memset(output + input_len, pad_len, pad_len);
  return padded_len;
}

size_t crypto_pkcs7_unpad(const uint8_t *input, size_t input_len) {
  if (!input || input_len == 0 || input_len % CRYPTO_AES_BLOCK_SIZE != 0) {
    return 0;
  }

  uint8_t pad_len = input[input_len - 1];
  if (pad_len == 0 || pad_len > CRYPTO_AES_BLOCK_SIZE || pad_len > input_len) {
    return 0;
  }

  /* Verify all padding bytes are correct */
  for (size_t i = input_len - pad_len; i < input_len; i++) {
    if (input[i] != pad_len) {
      return 0;
    }
  }

  return input_len - pad_len;
}
