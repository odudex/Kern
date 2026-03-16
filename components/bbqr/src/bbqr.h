#ifndef BBQR_H
#define BBQR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief BBQr encoding types
 */
#define BBQR_ENCODING_HEX 'H'    // Hexadecimal encoding
#define BBQR_ENCODING_BASE32 '2' // Base32 encoding (uncompressed)
#define BBQR_ENCODING_ZLIB 'Z'   // Base32 + zlib compression

/**
 * @brief BBQr file types
 */
#define BBQR_TYPE_PSBT 'P'        // PSBT (Partially Signed Bitcoin Transaction)
#define BBQR_TYPE_TRANSACTION 'T' // Raw Bitcoin transaction
#define BBQR_TYPE_JSON 'J'        // JSON data
#define BBQR_TYPE_UNICODE 'U'     // Unicode text

/**
 * @brief Header length for BBQr format
 */
#define BBQR_HEADER_LEN 8

/**
 * @brief Structure to hold parsed BBQr part information
 */
typedef struct {
  char encoding;       // Encoding type ('H', '2', or 'Z')
  char file_type;      // File type ('P', 'T', 'J', 'U')
  int total;           // Total number of parts (1-1295)
  int index;           // Part index (0-based, 0-1294)
  const char *payload; // Pointer to payload data (not null-terminated)
  size_t payload_len;  // Length of payload data
} BBQrPart;

/**
 * @brief Structure to hold BBQr encoded parts for output
 */
typedef struct {
  char **parts;   // Array of null-terminated part strings
  int count;      // Number of parts
  char encoding;  // Encoding used
  char file_type; // File type
} BBQrParts;

/**
 * @brief Check if a character is a valid BBQr encoding type
 *
 * @param c Character to check
 * @return true if valid encoding type, false otherwise
 */
bool bbqr_is_valid_encoding(char c);

/**
 * @brief Check if a character is a valid BBQr file type
 *
 * @param c Character to check
 * @return true if valid file type, false otherwise
 */
bool bbqr_is_valid_file_type(char c);

/**
 * @brief Parse a single BBQr part header and extract information
 *
 * Extracts the encoding type, file type, total parts, part index,
 * and payload from a BBQr QR code string.
 *
 * @param data Raw BBQr string data
 * @param data_len Length of data string
 * @param part Pointer to BBQrPart structure to fill
 * @return true on success, false if invalid BBQr format
 */
bool bbqr_parse_part(const char *data, size_t data_len, BBQrPart *part);

/**
 * @brief Decode assembled BBQr payload data
 *
 * Takes the concatenated payload from all BBQr parts and decodes it
 * according to the encoding type. For 'Z' encoding, this includes
 * decompression.
 *
 * @param encoding Encoding type ('H', '2', or 'Z')
 * @param data Concatenated payload data from all parts
 * @param data_len Length of payload data
 * @param out_len Pointer to store decoded output length
 * @return Allocated buffer with decoded data, or NULL on failure.
 *         Caller must free the returned buffer.
 */
uint8_t *bbqr_decode_payload(char encoding, const char *data, size_t data_len,
                             size_t *out_len);

/**
 * @brief Encode binary data as BBQr parts
 *
 * Encodes the input data using the most efficient encoding (tries compression
 * first, falls back to uncompressed if compression doesn't reduce size).
 * Splits the encoded data into multiple QR-sized parts.
 *
 * @param data Binary data to encode
 * @param data_len Length of data
 * @param file_type File type character ('P', 'T', 'J', 'U')
 * @param max_chars_per_qr Maximum characters per QR code (including header)
 * @return Pointer to BBQrParts structure, or NULL on failure.
 *         Caller must free using bbqr_parts_free().
 */
BBQrParts *bbqr_encode(const uint8_t *data, size_t data_len, char file_type,
                       int max_chars_per_qr);

/**
 * @brief Free BBQrParts structure
 *
 * @param parts Pointer to BBQrParts structure to free
 */
void bbqr_parts_free(BBQrParts *parts);

/**
 * @brief Convert a base36 character pair to integer
 *
 * @param c1 First character
 * @param c2 Second character
 * @return Decoded integer value (0-1295), or -1 on error
 */
int bbqr_base36_decode(char c1, char c2);

/**
 * @brief Encode an integer to base36 character pair
 *
 * @param value Integer value (0-1295)
 * @param c1 Pointer to store first character
 * @param c2 Pointer to store second character
 * @return true on success, false if value out of range
 */
bool bbqr_base36_encode(int value, char *c1, char *c2);

#endif /* BBQR_H */
