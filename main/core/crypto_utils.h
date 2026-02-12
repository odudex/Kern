/*
 * Crypto Utilities
 * AES-256, PBKDF2-HMAC-SHA256, SHA-256 primitives wrapping ESP-IDF mbedTLS
 * (hardware-accelerated transparently).
 *
 * All functions return 0 on success, negative on error.
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <stdint.h>

#define CRYPTO_AES_KEY_SIZE 32
#define CRYPTO_AES_BLOCK_SIZE 16
#define CRYPTO_AES_IV_SIZE 16
#define CRYPTO_AES_CTR_NONCE_SIZE 12
#define CRYPTO_AES_GCM_NONCE_SIZE 12
#define CRYPTO_SHA256_SIZE 32

#define CRYPTO_OK 0
#define CRYPTO_ERR_INVALID_ARG -1
#define CRYPTO_ERR_INTERNAL -2
#define CRYPTO_ERR_AUTH_FAILED -3

/* --- Key Derivation --- */

/* PBKDF2-HMAC-SHA256.
 * Derives key_len bytes from password + salt with given iteration count. */
int crypto_pbkdf2_sha256(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint32_t iterations, uint8_t *key_out,
                         size_t key_len);

/* --- Hashing --- */

/* SHA-256 hash. hash_out must be at least CRYPTO_SHA256_SIZE bytes. */
int crypto_sha256(const uint8_t *data, size_t data_len, uint8_t *hash_out);

/* --- AES-256-ECB --- */

/* Encrypt/decrypt in ECB mode. input_len must be a multiple of 16. */
int crypto_aes_ecb_encrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output);

int crypto_aes_ecb_decrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output);

/* --- AES-256-CBC --- */

/* Encrypt/decrypt in CBC mode. input_len must be a multiple of 16.
 * iv is not modified (copied internally). */
int crypto_aes_cbc_encrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t iv[CRYPTO_AES_IV_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output);

int crypto_aes_cbc_decrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t iv[CRYPTO_AES_IV_SIZE],
                           const uint8_t *input, size_t input_len,
                           uint8_t *output);

/* --- AES-256-CTR --- */

/* Encrypt or decrypt in CTR mode (symmetric operation).
 * nonce is 12 bytes; the 4-byte counter starts at 0. Any input_len is valid.
 */
int crypto_aes_ctr(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                   const uint8_t nonce[CRYPTO_AES_CTR_NONCE_SIZE],
                   const uint8_t *input, size_t input_len, uint8_t *output);

/* --- AES-256-GCM --- */

/* Encrypt with GCM authentication. tag_len can be 4-16 bytes. */
int crypto_aes_gcm_encrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *input, size_t input_len,
                           uint8_t *output, uint8_t *tag, size_t tag_len);

/* Decrypt with GCM authentication verification.
 * Returns CRYPTO_ERR_AUTH_FAILED if tag doesn't match. */
int crypto_aes_gcm_decrypt(const uint8_t key[CRYPTO_AES_KEY_SIZE],
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *input, size_t input_len,
                           uint8_t *output, const uint8_t *tag,
                           size_t tag_len);

/* --- Random --- */

/* Fill buf with cryptographically secure random bytes (hardware TRNG). */
void crypto_random_bytes(uint8_t *buf, size_t len);

/* --- Padding --- */

/* Apply PKCS#7 padding. output must have room for input_len + padding (up to
 * input_len + 16). Returns padded length, or 0 on error. */
size_t crypto_pkcs7_pad(const uint8_t *input, size_t input_len,
                        uint8_t *output, size_t output_size);

/* Remove PKCS#7 padding in-place. Returns unpadded length, or 0 on error. */
size_t crypto_pkcs7_unpad(const uint8_t *input, size_t input_len);

#endif // CRYPTO_UTILS_H
