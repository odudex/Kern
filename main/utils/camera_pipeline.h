/*
 * Shared Camera & PPA Pipeline
 *
 * Owns the common V4L2 frame callback guard, EventGroup lifecycle, cache-line
 * aligned DMA buffer allocation, sensor entropy stirring, PPA SRM client
 * management, and safe shutdown handshake shared by the QR scanner and
 * camera-entropy capture pages.
 */

#ifndef CAMERA_PIPELINE_H
#define CAMERA_PIPELINE_H

#include <driver/ppa.h>
#include <esp_err.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Frame callback invoked on the camera task while the pipeline is open.
 *
 * Guaranteed to run only while the pipeline is active and not closing;
 * active_frame_ops is tracked automatically around each invocation.
 */
typedef void (*camera_pipeline_frame_cb_t)(ppa_client_handle_t ppa,
                                           uint8_t *camera_buf, uint32_t width,
                                           uint32_t height, size_t len,
                                           void *ctx);

/**
 * @brief Optional extra idle predicate (e.g. non-blocking PPA pass in flight).
 */
typedef bool (*camera_pipeline_idle_cb_t)(void *ctx);

typedef struct {
  camera_pipeline_frame_cb_t on_frame;
  ppa_event_callback_t on_ppa_done;
  camera_pipeline_idle_cb_t is_idle;
  void *ctx;
  uint32_t max_pending_trans_num;
  int core_id;
  bool stir_entropy;
} camera_pipeline_config_t;

typedef struct {
  EventGroupHandle_t event_group;
  ppa_client_handle_t ppa_client;
  volatile int active_frame_ops;
  volatile bool closing;
  volatile bool running;
  camera_pipeline_config_t cfg;
} camera_pipeline_t;

/**
 * @brief Round a buffer size up to the L2 cache line boundary required by PPA.
 */
size_t camera_pipeline_align_size(size_t size);

/**
 * @brief Allocate a zeroed, cache-line-aligned DMA buffer (SPIRAM -> internal).
 */
uint8_t *camera_pipeline_alloc_buffer(size_t size);

/**
 * @brief Stir three samples from a camera frame into the global entropy pool.
 */
void camera_pipeline_stir_entropy(const uint8_t *buf, size_t len);

/**
 * @brief True once neither the camera callback nor any async PPA pass can
 * touch the pipeline's frame buffers.
 */
bool camera_pipeline_is_idle(const camera_pipeline_t *pipeline);

/**
 * @brief Register the PPA client and start V4L2 camera streaming.
 *
 * Reuses a previously retained PPA client / event group if an earlier stop
 * could not confirm idle before returning (once idle is now confirmed).
 */
bool camera_pipeline_start(camera_pipeline_t *pipeline,
                           const camera_pipeline_config_t *cfg);

/**
 * @brief Signal the camera callback to stop accepting new frames immediately.
 */
void camera_pipeline_request_stop(camera_pipeline_t *pipeline);

/**
 * @brief Stop V4L2 streaming, drain active callbacks and PPA passes, and
 * release the PPA client and event group once idle.
 *
 * @return true if the pipeline is confirmed idle and caller-owned DMA buffers
 *         may safely be freed; false if PPA still owns them (caller must keep
 *         the buffers allocated until the next session confirms idle).
 */
bool camera_pipeline_stop(camera_pipeline_t *pipeline);

/**
 * @brief Largest centred even crop <= crop_max that an even Q4.4 PPA fraction
 * scales to exactly `target` (required for PPA YUV420 output).
 */
uint32_t camera_pipeline_snap_yuv420_crop(uint32_t crop_max, uint32_t target);

/**
 * @brief Blocking single-pass centred square RGB565 -> RGB565 crop & scale.
 *
 * @param max_crop Optional upper bound on the square crop dimension in pixels
 *                 (0 uses min(src_w, src_h)).
 */
esp_err_t camera_pipeline_scale_rgb565_crop(ppa_client_handle_t ppa,
                                            const uint8_t *src, uint32_t src_w,
                                            uint32_t src_h, uint32_t max_crop,
                                            uint8_t *dst, size_t dst_buf_size,
                                            uint32_t dst_size);

#endif // CAMERA_PIPELINE_H
