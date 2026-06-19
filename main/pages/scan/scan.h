#ifndef SCAN_H
#define SCAN_H

#include <lvgl.h>

/**
 * Create the scan page — universal QR content detection
 * @param parent Parent LVGL object
 * @param return_cb Callback function to call when returning to home
 */
void scan_page_create(lv_obj_t *parent, void (*return_cb)(void));

/**
 * Process an already-assembled blob (e.g. read from an SD-card file) through
 * the same classify-and-route pipeline as scanned QRs — PSBT, signed message,
 * descriptor, address or mnemonic — skipping the UR/BBQr transport handling.
 * Text content is normalized first (BOM, comment lines, editor line-wrapping).
 * Sets up the scan page's review screens; return_cb is invoked when the flow
 * fails to parse or is backed out of, complete_cb when a signing flow runs to
 * completion (signed PSBT exported, message signature shown); both own the
 * scan_page_destroy() call. Pass complete_cb as NULL to fall back to
 * return_cb.
 * A signed PSBT can be exported back to the same SD-card folder; pass that
 * folder as save_dir (NULL targets the card root) and the original file name
 * as source_name so the saved file is named "signed-<source_name>.<ext>"
 * (.psbt for binary sources, .txt for base64).
 * @param parent Parent LVGL object
 * @param data Raw file contents
 * @param len Length of data in bytes
 * @param save_dir Folder to write a saved signed PSBT into, or NULL for root
 * @param source_name Original file name (no path), or NULL for QR sources
 * @param return_cb Callback invoked when the user fails out / backs out
 * @param complete_cb Callback invoked when a signing flow completes, or NULL
 */
void scan_load_content(lv_obj_t *parent, const uint8_t *data, size_t len,
                       const char *save_dir, const char *source_name,
                       void (*return_cb)(void), void (*complete_cb)(void));

/**
 * Show the scan page
 */
void scan_page_show(void);

/**
 * Hide the scan page
 */
void scan_page_hide(void);

/**
 * Destroy the scan page and free resources
 */
void scan_page_destroy(void);

#endif // SCAN_H
