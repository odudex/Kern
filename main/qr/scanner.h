/*
 * QR Scanner Page Header
 * Displays a 480x480 frame buffer that changes colors every second
 */

#ifndef QR_SCANNER_H
#define QR_SCANNER_H

#include "../components/video/video.h"
#include <lvgl.h>
#include <stdbool.h>

#ifdef K_QUIRC_DEBUG
#define QR_PERF_DEBUG
#endif

/**
 * @brief Create the QR scanner page
 *
 * @param parent Parent LVGL object where the QR scanner page will be created
 * @param return_cb Callback function to call when returning to previous page
 */
void qr_scanner_page_create(lv_obj_t *parent, void (*return_cb)(void));

/**
 * @brief Show the QR scanner page
 */
void qr_scanner_page_show(void);

/**
 * @brief Hide the QR scanner page
 */
void qr_scanner_page_hide(void);

/**
 * @brief Destroy the QR scanner page and free resources
 */
void qr_scanner_page_destroy(void);

/**
 * @brief Get completed QR content if available
 *
 * @return Completed QR content string (caller must free), or NULL if no
 * completed content
 */
char *qr_scanner_get_completed_content(void);

/**
 * @brief Get completed QR content with length information
 *
 * This function is useful for binary QR codes (like Compact SeedQRs)
 * where the content may contain null bytes.
 *
 * @param content_len Pointer to store the content length (can be NULL)
 * @return Completed QR content (caller must free), or NULL if no completed
 * content
 */
char *qr_scanner_get_completed_content_with_len(size_t *content_len);

/**
 * @brief Check if QR scanner is fully initialized and ready
 *
 * @return true if scanner is ready, false otherwise
 */
bool qr_scanner_is_ready(void);

/**
 * @brief Get the detected QR code format
 *
 * @return QR format constant (FORMAT_NONE, FORMAT_PMOFN, FORMAT_UR, etc.)
 *         Returns -1 if no format detected yet
 */
int qr_scanner_get_format(void);

/**
 * @brief Get UR result data (for UR format QR codes only)
 *
 * Call this when qr_scanner_get_format() returns FORMAT_UR.
 * Returns the UR type and CBOR data from the decoded UR.
 *
 * @param ur_type_out Pointer to store UR type string (do not free)
 * @param cbor_data_out Pointer to store CBOR data pointer (do not free)
 * @param cbor_len_out Pointer to store CBOR data length
 * @return true on success, false on failure
 */
bool qr_scanner_get_ur_result(const char **ur_type_out,
                              const uint8_t **cbor_data_out,
                              size_t *cbor_len_out);

#endif // QR_SCANNER_H
