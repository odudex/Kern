// Capture Entropy Page - Reusable camera page for capturing entropy

#ifndef CAPTURE_ENTROPY_H
#define CAPTURE_ENTROPY_H

#include <lvgl.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Create the capture entropy page
 *
 * @param parent Parent LVGL object where the page will be created
 * @param return_cb Callback function to call when returning to previous page
 */
void capture_entropy_page_create(lv_obj_t *parent, void (*return_cb)(void));

/**
 * @brief Show the capture entropy page
 */
void capture_entropy_page_show(void);

/**
 * @brief Hide the capture entropy page
 */
void capture_entropy_page_hide(void);

/**
 * @brief Destroy the capture entropy page and free resources
 */
void capture_entropy_page_destroy(void);

/**
 * @brief Get the captured 32-byte entropy digest
 *
 * The digest is SHA256(SHA256(frame) || random), where the random half comes
 * from crypto_random_bytes() - hardware RNG conditioned with the entropy pool.
 * Not reproducible from the snapshot alone.
 *
 * @param hash_out Buffer to receive 32 bytes of digest data
 * @return true if hash was captured and copied, false otherwise
 */
bool capture_entropy_get_hash(uint8_t *hash_out);

/**
 * @brief Check if entropy has been captured
 *
 * @return true if entropy hash is available, false otherwise
 */
bool capture_entropy_has_result(void);

/**
 * @brief Clear any captured entropy
 */
void capture_entropy_clear(void);

#endif // CAPTURE_ENTROPY_H
