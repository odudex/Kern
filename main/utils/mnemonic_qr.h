#ifndef MNEMONIC_QR_H
#define MNEMONIC_QR_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Mnemonic QR code format types
 */
typedef enum {
  MNEMONIC_QR_PLAINTEXT, /**< Space-separated BIP39 words */
  MNEMONIC_QR_COMPACT,   /**< Raw binary entropy (16 or 32 bytes) */
  MNEMONIC_QR_SEEDQR,    /**< Numeric indices (4 digits per word, 0000-2047) */
  MNEMONIC_QR_UNKNOWN    /**< Unknown or invalid format */
} mnemonic_qr_format_t;

/**
 * @brief Compact SeedQR size constants
 */
#define COMPACT_SEEDQR_12_WORDS_LEN 16 /**< 128 bits entropy = 12 words */
#define COMPACT_SEEDQR_24_WORDS_LEN 32 /**< 256 bits entropy = 24 words */

/**
 * @brief SeedQR size constants (4 digits per word)
 */
#define SEEDQR_12_WORDS_LEN 48 /**< 12 words * 4 digits */
#define SEEDQR_24_WORDS_LEN 96 /**< 24 words * 4 digits */

/**
 * @brief Detect the format of a mnemonic QR code
 *
 * Analyzes the data to determine if it's a plaintext mnemonic,
 * Compact SeedQR (binary), or SeedQR (numeric indices).
 *
 * @param data QR code data (may be binary or text)
 * @param len Length of the data in bytes
 * @return Detected format type
 */
mnemonic_qr_format_t mnemonic_qr_detect_format(const char *data, size_t len);

/**
 * @brief Convert QR code data to a BIP39 mnemonic phrase
 *
 * Automatically detects the format and converts to a space-separated
 * mnemonic phrase. Supports plaintext, Compact SeedQR, and SeedQR formats.
 *
 * @param data QR code data (may be binary or text)
 * @param len Length of the data in bytes
 * @param format_out Optional pointer to receive the detected format
 * @return Allocated mnemonic string on success (caller must free),
 *         or NULL on failure
 */
char *mnemonic_qr_to_mnemonic(const char *data, size_t len,
                              mnemonic_qr_format_t *format_out);

/**
 * @brief Convert Compact SeedQR binary data to mnemonic
 *
 * @param data Binary entropy data
 * @param len Length (must be 16 or 32 bytes)
 * @return Allocated mnemonic string on success (caller must free),
 *         or NULL on failure
 */
char *mnemonic_qr_compact_to_mnemonic(const unsigned char *data, size_t len);

/**
 * @brief Convert SeedQR numeric string to mnemonic
 *
 * SeedQR format uses 4 decimal digits per word, representing the
 * word index (0000-2047) in the BIP39 wordlist.
 *
 * @param data Numeric string (must be 48 or 96 characters)
 * @param len Length of the string
 * @return Allocated mnemonic string on success (caller must free),
 *         or NULL on failure
 */
char *mnemonic_qr_seedqr_to_mnemonic(const char *data, size_t len);

/**
 * @brief Get a human-readable name for a format
 *
 * @param format The format type
 * @return Static string with format name
 */
const char *mnemonic_qr_format_name(mnemonic_qr_format_t format);

#endif // MNEMONIC_QR_H
