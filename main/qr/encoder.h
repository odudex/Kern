#ifndef QR_ENCODER_H
#define QR_ENCODER_H

#include <lvgl.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Result from QR encoding with module information
 */
typedef struct {
  int modules; /**< QR module count (side length) */
  int scale;   /**< Pixels per module */
} qr_encode_result_t;

/**
 * @brief Update QR code with optimal encoding
 *
 * Automatically selects best encoding mode (numeric/alphanumeric/byte)
 * using qrcodegen_encodeText() and uses LOW ECC with boost for maximum
 * data efficiency while maintaining good error correction.
 *
 * @param qr_obj LVGL QR code object (canvas)
 * @param text Text to encode
 * @param result Optional pointer to receive encoding result info
 * @return LV_RESULT_OK on success, LV_RESULT_INVALID on failure
 */
lv_result_t qr_update_optimal(lv_obj_t *qr_obj, const char *text,
                              qr_encode_result_t *result);

/**
 * @brief Create a QR widget with optimal encoding
 *
 * Creates an lv_qrcode widget of the given size, centers it in the
 * parent and, if text is non-NULL, encodes it via qr_update_optimal().
 * Pass NULL text to fill the widget later.
 *
 * @param parent Parent object
 * @param size Widget size in pixels
 * @param text Text to encode, or NULL to defer
 * @return QR widget on success, NULL on failure
 */
lv_obj_t *qr_create_optimal(lv_obj_t *parent, int32_t size, const char *text);

/**
 * @brief Uppercase a bech32 string for QR alphanumeric mode
 *
 * Bech32 is case-insensitive (BIP-173) and its uppercase form fits the
 * QR alphanumeric charset, yielding a sparser QR. Only converts strings
 * with a known bech32 HRP prefix (bc1/tb1/bcrt1) that are entirely
 * lowercase alphanumeric; case-sensitive data (base58) never matches.
 *
 * @param text Candidate string
 * @return Allocated uppercased copy (caller must free), or NULL if the
 *         string is not a lowercase bech32 string
 */
char *qr_bech32_to_upper(const char *text);

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

/**
 * @brief Convert a BIP39 mnemonic phrase to SeedQR format
 *
 * SeedQR format uses 4 decimal digits per word, representing the
 * word index (0000-2047) in the BIP39 wordlist.
 *
 * @param mnemonic Space-separated BIP39 mnemonic phrase
 * @return Allocated SeedQR string on success (caller must free),
 *         or NULL on failure
 */
char *mnemonic_to_seedqr(const char *mnemonic);

/**
 * @brief Convert a BIP39 mnemonic phrase to Compact SeedQR format
 *
 * Compact SeedQR format is the raw entropy bytes (16 bytes for 12 words,
 * 32 bytes for 24 words).
 *
 * @param mnemonic Space-separated BIP39 mnemonic phrase
 * @param out_len Pointer to receive the output length
 * @return Allocated binary data on success (caller must free),
 *         or NULL on failure
 */
unsigned char *mnemonic_to_compact_seedqr(const char *mnemonic,
                                          size_t *out_len);

/**
 * @brief Update QR code with binary data encoding
 *
 * Encodes binary data using byte mode QR encoding.
 *
 * @param qr_obj LVGL QR code object (canvas)
 * @param data Binary data to encode
 * @param len Length of the data
 * @param result Optional pointer to receive encoding result info
 * @return LV_RESULT_OK on success, LV_RESULT_INVALID on failure
 */
lv_result_t qr_update_binary(lv_obj_t *qr_obj, const unsigned char *data,
                             size_t len, qr_encode_result_t *result);

#endif
