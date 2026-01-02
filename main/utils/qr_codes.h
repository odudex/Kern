#ifndef QR_CODES_H
#define QR_CODES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief QR code format constants
 */
#define FORMAT_NONE 0
#define FORMAT_PMOFN 1
#define FORMAT_UR 2
#define FORMAT_BBQR 3

/**
 * @brief Prefix length constants for different QR formats
 */
#define PMOFN_PREFIX_LENGTH_1D 6
#define PMOFN_PREFIX_LENGTH_2D 8
#define BBQR_PREFIX_LENGTH 8
#define UR_GENERIC_PREFIX_LENGTH 22
#define UR_CBOR_PREFIX_LEN 14
#define UR_BYTEWORDS_CRC_LEN 4
#define UR_MIN_FRAGMENT_LENGTH 10

/**
 * @brief Maximum QR code versions supported (limited to version 20)
 */
#define QR_CAPACITY_SIZE 20

/**
 * @brief Structure to hold a single QR part
 */
typedef struct {
  int index;       /**< Part index in the sequence */
  char *data;      /**< Part data content */
  size_t data_len; /**< Length of the data */
} QRPart;

/**
 * @brief Structure for BBQr code information
 */
typedef struct {
  char encoding;  /**< Encoding type */
  char file_type; /**< File type identifier */
  char *payload;  /**< Decoded payload */
} BBQrCode;

/**
 * @brief Main QR Parser structure
 *
 * This structure maintains the state of multi-part QR code parsing,
 * supporting various formats including P M-of-N, UR, and BBQR.
 */
typedef struct {
  QRPart **parts;     /**< Array of parsed QR parts */
  int parts_capacity; /**< Allocated capacity for parts array */
  int parts_count;    /**< Current number of parts */
  int total;          /**< Total expected number of parts */
  int format;         /**< Detected QR format (FORMAT_* constants) */
  BBQrCode *bbqr;     /**< BBQr specific data (if format is BBQR) */
  void *ur_decoder;   /**< UR decoder instance (if format is UR) */
} QRPartParser;

/**
 * @brief Create a new QR part parser instance
 *
 * Allocates and initializes a new QRPartParser structure.
 *
 * @return Pointer to new parser instance, or NULL on failure
 */
QRPartParser *qr_parser_create(void);

/**
 * @brief Destroy parser and free all associated memory
 *
 * Frees all memory associated with the parser, including
 * parsed parts and format-specific data.
 *
 * @param parser Parser instance to destroy
 */
void qr_parser_destroy(QRPartParser *parser);

/**
 * @brief Get the number of successfully parsed parts
 *
 * Returns the count of unique QR parts that have been
 * successfully parsed and stored.
 *
 * @param parser Parser instance
 * @return Number of parsed parts
 */
int qr_parser_parsed_count(QRPartParser *parser);

/**
 * @brief Get the number of processed parts (including duplicates)
 *
 * Returns the total count of parts that have been processed,
 * including any duplicate parts that may have been received.
 *
 * @param parser Parser instance
 * @return Number of processed parts
 */
int qr_parser_processed_parts_count(QRPartParser *parser);

/**
 * @brief Get the total expected number of parts
 *
 * Returns the total number of parts expected for the complete
 * message, as determined from the QR format headers.
 *
 * @param parser Parser instance
 * @return Total expected parts, or -1 if not yet determined
 */
int qr_parser_total_count(QRPartParser *parser);

/**
 * @brief Parse a QR code data string
 *
 * Attempts to parse the provided QR data string, detecting the format
 * on the first call and extracting part information for multi-part formats.
 *
 * @param parser Parser instance
 * @param data QR code data string to parse
 * @return Part index on success, or -1 on failure
 */
int qr_parser_parse(QRPartParser *parser, const char *data);

/**
 * @brief Parse QR code data with explicit length
 *
 * Like qr_parser_parse but accepts an explicit length, which is necessary
 * for binary data that may contain null bytes (e.g., Compact SeedQR).
 *
 * @param parser Parser instance
 * @param data QR code data (may contain null bytes)
 * @param data_len Length of the data in bytes
 * @return Part index on success, or -1 on failure
 */
int qr_parser_parse_with_len(QRPartParser *parser, const char *data,
                             size_t data_len);

/**
 * @brief Check if all expected parts have been received
 *
 * Determines whether all parts of a multi-part QR sequence
 * have been successfully parsed and are ready for assembly.
 *
 * @param parser Parser instance
 * @return true if parsing is complete, false otherwise
 */
bool qr_parser_is_complete(QRPartParser *parser);

/**
 * @brief Get the assembled result from all parsed parts
 *
 * Combines all parsed parts in the correct order to produce
 * the final decoded message. Only call when qr_parser_is_complete()
 * returns true.
 *
 * For UR format, this returns a special marker string "UR_RESULT".
 * Use qr_parser_get_ur_result() to get the actual UR data.
 *
 * @param parser Parser instance
 * @param result_len Pointer to store the result length (optional)
 * @return Allocated string containing the result, or NULL on failure.
 *         Caller must free the returned string.
 */
char *qr_parser_result(QRPartParser *parser, size_t *result_len);

/**
 * @brief Get the UR decoder result (for FORMAT_UR only)
 *
 * Returns the UR result structure containing the type and CBOR data.
 * Only call when format is FORMAT_UR and qr_parser_is_complete() returns true.
 *
 * @param parser Parser instance
 * @param ur_type_out Pointer to store UR type string (do not free, owned by
 * decoder)
 * @param cbor_data_out Pointer to store CBOR data pointer (do not free, owned
 * by decoder)
 * @param cbor_len_out Pointer to store CBOR data length
 * @return true on success, false on failure
 */
bool qr_parser_get_ur_result(QRPartParser *parser, const char **ur_type_out,
                             const uint8_t **cbor_data_out,
                             size_t *cbor_len_out);

/**
 * @brief Get the detected QR format
 *
 * Returns the format detected during parsing.
 *
 * @param parser Parser instance
 * @return QR format (FORMAT_* constants)
 */
int qr_parser_get_format(QRPartParser *parser);

/**
 * @brief Calculate QR code size from encoded data
 *
 * Estimates the QR code size (side length in modules) based
 * on the encoded data length.
 *
 * @param qr_code Encoded QR code data
 * @return Estimated QR code size in modules
 */
int get_qr_size(const char *qr_code);

#endif /* QR_CODES_H */