#ifndef QR_ENCODER_H
#define QR_ENCODER_H

#include <lvgl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Bytes a qrcodegen output buffer needs (== qrcodegen_BUFFER_LEN_MAX for
 * version 40). Defined here so callers can allocate a qr_buf without pulling in
 * the qrcodegen header; a _Static_assert in encoder.c keeps them in sync.
 */
#define QR_CODE_BUF_LEN 3918

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
 * @brief Resize an existing QR widget's canvas.
 *
 * Reallocates the draw buffer and clears it, so the caller must re-encode
 * (qr_update_optimal/qr_update_binary) afterwards to repaint.
 *
 * @param qr_obj QR widget created by qr_create_optimal()
 * @param size New widget size in pixels
 */
void qr_resize(lv_obj_t *qr_obj, int32_t size);

/**
 * @brief Encode text/binary into a module buffer without drawing.
 *
 * Mirrors the encode step of qr_update_optimal/qr_update_binary (LOW ECC, auto
 * version/mask, boost). The buffer must hold at least QR_CODE_BUF_LEN bytes.
 * Module bits can then be read with the qrcodegen API or drawn via
 * qr_draw_region(). Returns the module count (side length), or 0 on failure.
 *
 * @param text/data Source to encode
 * @param qr_buf Output buffer (>= QR_CODE_BUF_LEN bytes)
 * @return Module count on success, 0 on failure
 */
int qr_encode_optimal(const char *text, uint8_t *qr_buf);
int qr_encode_binary(const uint8_t *data, size_t len, uint8_t *qr_buf);

/**
 * @brief Draw a sub-rectangle of an encoded QR onto a widget's canvas.
 *
 * Draws modules [x0,x0+w) x [y0,y0+h) of qr_buf, scaled so a span of `cell`
 * modules fills the canvas, centered. Pass cell == w == h == modules to draw
 * the whole QR, or cell == grid interval to magnify one region at a constant
 * module size. The caller retains ownership of qr_buf.
 *
 * @param qr_obj QR widget (canvas)
 * @param qr_buf Buffer previously filled by qr_encode_optimal/binary
 * @param x0,y0 Top-left module of the region
 * @param w,h Module extent to draw (clamped by the caller)
 * @param cell Module span used to compute scale/centering (>= 1)
 */
void qr_draw_region(lv_obj_t *qr_obj, const uint8_t *qr_buf, int x0, int y0,
                    int w, int h, int cell);

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
