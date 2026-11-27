/*
 * UI-Free QR Scanner Engine
 *
 * Runs the dual-pass PPA camera pipeline (sensor RGB565 -> YUV420 decode frame
 * -> async RGB565 preview frame) and the background k_quirc decoding task that
 * feeds QRPartParser (single QR, pMofN, UR, BBQr). Has no LVGL or BSP
 * dependencies; the LVGL scanner page polls preview frames and progress
 * snapshots from its timer.
 */

#ifndef QR_SCANNER_ENGINE_H
#define QR_SCANNER_ENGINE_H

#include "../utils/attributes.h"
#include "progress.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  uint32_t input_crop;
  uint32_t decode_size;
  uint32_t preview_frag;
  uint32_t preview_size;
} qr_scanner_geometry_t;

typedef struct {
  int format;
  float percent_complete;
  qr_part_progress_t parts;
} qr_progress_update_t;

/**
 * @brief Compute quantized Q4.4 PPA decode and preview dimensions for a panel.
 *
 * @param screen_min_dim Smaller display dimension in pixels.
 */
qr_scanner_geometry_t qr_scanner_compute_geometry(uint32_t screen_min_dim);

/**
 * @brief Allocate frame pools, start the k_quirc decode task, and start the
 *        dual-pass PPA camera pipeline.
 */
bool qr_scanner_engine_start(const qr_scanner_geometry_t *geom);

/**
 * @brief Immediately stop accepting new camera frames (e.g. on scan completion
 *        or user cancel) while keeping decoded results readable until stop().
 */
void qr_scanner_engine_request_stop(void);

/**
 * @brief Stop camera streaming, drain PPA, and tear down the decode task and
 *        parser.
 *
 * Frame buffers are NOT freed here because the UI may still hold a preview
 * pointer; delete the preview widget and then call
 * qr_scanner_engine_release_buffers() with the returned value.
 *
 * @return true if the PPA pipeline is confirmed idle and buffers may be freed.
 */
bool qr_scanner_engine_stop(void);

/**
 * @brief Free frame buffers if pipeline_idle is true; otherwise retain them
 *        until a subsequent start confirms the PPA has finished DMA.
 */
void qr_scanner_engine_release_buffers(bool pipeline_idle);

/**
 * @brief Pause/throttle decoding and preview updates while settings are open.
 */
void qr_scanner_engine_set_settings_active(bool active);

/**
 * @brief Claim the latest completed RGB565 preview buffer, or NULL if none.
 */
const uint8_t *qr_scanner_engine_claim_preview(void);

/**
 * @brief Pop the latest multi-part progress snapshot if one is pending.
 */
bool qr_scanner_engine_poll_progress(qr_progress_update_t *out);

/**
 * @brief Check whether a complete QR payload has been assembled.
 */
bool qr_scanner_engine_is_completed(void);

/**
 * @brief Check whether scanning failed on an invalid/oversized QR sequence.
 */
bool qr_scanner_engine_is_failed(const char **msg_out);

KERN_WARN_UNUSED_RESULT char *
qr_scanner_engine_get_completed_content_with_len(size_t *content_len);

KERN_WARN_UNUSED_RESULT bool qr_scanner_engine_has_completed_result(void);

KERN_WARN_UNUSED_RESULT int qr_scanner_engine_get_format(void);

char qr_scanner_engine_get_bbqr_file_type(void);

KERN_WARN_UNUSED_RESULT bool
qr_scanner_engine_get_ur_result(const char **ur_type_out,
                                const uint8_t **cbor_data_out,
                                size_t *cbor_len_out);

#endif // QR_SCANNER_ENGINE_H
