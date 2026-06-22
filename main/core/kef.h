/*
 * KEF — Key Encryption Format
 *
 * Versioned encryption envelope wrapping data with AES-256 and PBKDF2
 * key derivation. Supports ECB/CBC/CTR/GCM modes with optional PKCS#7
 * padding, compression, and hidden/exposed authentication.
 *
 * Envelope layout:
 *   [len_id:1] [id:len_id] [version:1] [iterations:3 BE]
 *   [iv:0|12|16] [ciphertext] [exposed_auth?]
 *
 * Both kef_encrypt and kef_decrypt heap-allocate output.
 * Caller frees with free() or SECURE_FREE_BUFFER().
 */

#ifndef KEF_H
#define KEF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Version constants */
#define KEF_V0_ECB_NUL_H16 0
#define KEF_V1_CBC_NUL_H16 1
#define KEF_V5_ECB_NUL_E3 5
#define KEF_V6_ECB_PKCS7_H4 6
#define KEF_V7_ECB_PKCS7Z_H4 7
#define KEF_V10_CBC_NUL_E4 10
#define KEF_V11_CBC_PKCS7_H4 11
#define KEF_V12_CBC_PKCS7Z_H4 12
#define KEF_V15_CTR_H4 15
#define KEF_V16_CTR_Z_H4 16
#define KEF_V20_GCM_E4 20
#define KEF_V21_GCM_Z_E4 21

/* Maximum ID length (stored in 1 byte) */
#define KEF_MAX_ID_LEN 255

/* Iteration encoding threshold */
#define KEF_ITER_THRESHOLD 10000

typedef enum {
  KEF_OK = 0,
  KEF_ERR_INVALID_ARG = -1,
  KEF_ERR_UNSUPPORTED_VERSION = -2,
  KEF_ERR_ALLOC = -3,
  KEF_ERR_CRYPTO = -4,
  KEF_ERR_AUTH = -5,
  KEF_ERR_COMPRESS = -6,
  KEF_ERR_DECOMPRESS = -7,
  KEF_ERR_ENVELOPE_TOO_SHORT = -8,
  KEF_ERR_DUPLICATE_BLOCKS = -9,
} kef_error_t;

/*
 * Encrypt plaintext into a KEF envelope.
 *
 * id / id_len        — identifier, used as PBKDF2 salt
 * version            — KEF version (see constants above)
 * password / pw_len  — encryption password
 * iterations         — PBKDF2 effective iteration count
 * plaintext / pt_len — data to encrypt (must be > 0)
 * out / out_len      — receives heap-allocated envelope
 */
kef_error_t kef_encrypt(const uint8_t *id, size_t id_len, uint8_t version,
                        const uint8_t *password, size_t pw_len,
                        uint32_t iterations, const uint8_t *plaintext,
                        size_t pt_len, uint8_t **out, size_t *out_len);

/*
 * Decrypt a KEF envelope.
 *
 * envelope / env_len  — complete KEF envelope
 * password / pw_len   — decryption password
 * out / out_len       — receives heap-allocated plaintext
 */
kef_error_t kef_decrypt(const uint8_t *envelope, size_t env_len,
                        const uint8_t *password, size_t pw_len, uint8_t **out,
                        size_t *out_len);

/*
 * Parse header fields without decrypting.
 * id_out points into the envelope buffer (not a copy).
 * version_out and iterations_out may be NULL if not needed.
 */
kef_error_t kef_parse_header(const uint8_t *envelope, size_t env_len,
                             const uint8_t **id_out, size_t *id_len_out,
                             uint8_t *version_out, uint32_t *iterations_out);

/* Encode effective iteration count → 3-byte big-endian stored value. */
void kef_encode_iterations(uint32_t effective, uint8_t out[3]);

/* Decode 3-byte stored value → effective iteration count. */
uint32_t kef_decode_iterations(const uint8_t stored[3]);

/* Human-readable error string. */
const char *kef_error_str(kef_error_t err);

/*
 * Check if data looks like a valid KEF envelope.
 * Validates header, known version, and minimum payload size.
 */
bool kef_is_envelope(const uint8_t *data, size_t len);

/*
 * Extract a raw KEF envelope from arbitrary file bytes, accepting either a raw
 * binary envelope or a base64-armored one (with optional trailing whitespace,
 * as Kern stores KEF on SD). Returns a heap-allocated raw envelope (caller
 * frees) and its length via out_len, or NULL if the bytes are not a KEF
 * envelope.
 */
uint8_t *kef_envelope_from_bytes(const uint8_t *data, size_t len,
                                 size_t *out_len);

#endif /* KEF_H */
