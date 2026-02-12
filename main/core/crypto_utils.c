#include "crypto_utils.h"
#include "../utils/secure_mem.h"
#include <esp_random.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <string.h>

/* --- Key Derivation --- */

int crypto_pbkdf2_sha256(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t iterations, uint8_t *key_out,
                         size_t key_len) {
  if (!password || !salt || !key_out || iterations == 0 || key_len == 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, password,
                                           password_len, salt, salt_len,
                                           iterations, key_len, key_out);
  return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

/* --- Hashing --- */

int crypto_sha256(const uint8_t *data, size_t data_len, uint8_t *hash_out) {
  if (!data || !hash_out) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  int ret = mbedtls_sha256(data, data_len, hash_out, 0);
  return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

/* --- AES-256-ECB --- */

int crypto_aes_ecb_encrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output) {
  if (!key || !input || !output || input_len == 0 ||
      input_len % CRYPTO_AES_BLOCK_SIZE != 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);

  int ret = mbedtls_aes_setkey_enc(&ctx, key, 256);
  if (ret != 0) {
    mbedtls_aes_free(&ctx);
    return CRYPTO_ERR_INTERNAL;
  }

  for (size_t i = 0; i < input_len; i += CRYPTO_AES_BLOCK_SIZE) {
    ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, input + i,
                                output + i);
    if (ret != 0) {
      mbedtls_aes_free(&ctx);
      return CRYPTO_ERR_INTERNAL;
    }
  }

  mbedtls_aes_free(&ctx);
  return CRYPTO_OK;
}

int crypto_aes_ecb_decrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output) {
  if (!key || !input || !output || input_len == 0 ||
      input_len % CRYPTO_AES_BLOCK_SIZE != 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);

  int ret = mbedtls_aes_setkey_dec(&ctx, key, 256);
  if (ret != 0) {
    mbedtls_aes_free(&ctx);
    return CRYPTO_ERR_INTERNAL;
  }

  for (size_t i = 0; i < input_len; i += CRYPTO_AES_BLOCK_SIZE) {
    ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, input + i,
                                output + i);
    if (ret != 0) {
      mbedtls_aes_free(&ctx);
      return CRYPTO_ERR_INTERNAL;
    }
  }

  mbedtls_aes_free(&ctx);
  return CRYPTO_OK;
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

  /* mbedTLS modifies IV in-place, so use a copy */
  uint8_t iv_copy[CRYPTO_AES_IV_SIZE];
  memcpy(iv_copy, iv, CRYPTO_AES_IV_SIZE);

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);

  int ret = mbedtls_aes_setkey_enc(&ctx, key, 256);
  if (ret != 0) {
    mbedtls_aes_free(&ctx);
    return CRYPTO_ERR_INTERNAL;
  }

  ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, input_len, iv_copy,
                               input, output);

  mbedtls_aes_free(&ctx);
  secure_memzero(iv_copy, sizeof(iv_copy));
  return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

int crypto_aes_cbc_decrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t iv[CRYPTO_AES_IV_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output) {
  if (!key || !iv || !input || !output || input_len == 0 ||
      input_len % CRYPTO_AES_BLOCK_SIZE != 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  uint8_t iv_copy[CRYPTO_AES_IV_SIZE];
  memcpy(iv_copy, iv, CRYPTO_AES_IV_SIZE);

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);

  int ret = mbedtls_aes_setkey_dec(&ctx, key, 256);
  if (ret != 0) {
    mbedtls_aes_free(&ctx);
    return CRYPTO_ERR_INTERNAL;
  }

  ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, input_len, iv_copy,
                               input, output);

  mbedtls_aes_free(&ctx);
  secure_memzero(iv_copy, sizeof(iv_copy));
  return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

/* --- AES-256-CTR --- */

int crypto_aes_ctr(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                   const uint8_t nonce[CRYPTO_AES_CTR_NONCE_SIZE],
                   const uint8_t *input, size_t input_len, uint8_t *output) {
  if (!key || !nonce || !input || !output || input_len == 0) {
    return CRYPTO_ERR_INVALID_ARG;
  }

  /* 16-byte counter block: 12-byte nonce + 4-byte counter starting at 0 */
  uint8_t nonce_counter[CRYPTO_AES_BLOCK_SIZE];
  memcpy(nonce_counter, nonce, CRYPTO_AES_CTR_NONCE_SIZE);
  memset(nonce_counter + CRYPTO_AES_CTR_NONCE_SIZE, 0,
         CRYPTO_AES_BLOCK_SIZE - CRYPTO_AES_CTR_NONCE_SIZE);

  uint8_t stream_block[CRYPTO_AES_BLOCK_SIZE];
  size_t nc_off = 0;

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);

  int ret = mbedtls_aes_setkey_enc(&ctx, key, 256);
  if (ret != 0) {
    mbedtls_aes_free(&ctx);
    return CRYPTO_ERR_INTERNAL;
  }

  ret = mbedtls_aes_crypt_ctr(&ctx, input_len, &nc_off, nonce_counter,
                               stream_block, input, output);

  mbedtls_aes_free(&ctx);
  secure_memzero(nonce_counter, sizeof(nonce_counter));
  secure_memzero(stream_block, sizeof(stream_block));
  return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
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

  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (ret != 0) {
    mbedtls_gcm_free(&ctx);
    return CRYPTO_ERR_INTERNAL;
  }

  ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, input_len, nonce,
                                  nonce_len, NULL, 0, input, output, tag_len,
                                  tag);

  mbedtls_gcm_free(&ctx);
  return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
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

  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (ret != 0) {
    mbedtls_gcm_free(&ctx);
    return CRYPTO_ERR_INTERNAL;
  }

  ret = mbedtls_gcm_auth_decrypt(&ctx, input_len, nonce, nonce_len, NULL, 0,
                                 tag, tag_len, input, output);

  mbedtls_gcm_free(&ctx);
  if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED) {
    return CRYPTO_ERR_AUTH_FAILED;
  }
  return (ret == 0) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

/* --- Random --- */

void crypto_random_bytes(uint8_t *buf, size_t len) {
  if (buf && len > 0) {
    esp_fill_random(buf, len);
  }
}

/* --- Padding --- */

size_t crypto_pkcs7_pad(const uint8_t *input, size_t input_len,
                        uint8_t *output, size_t output_size) {
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
