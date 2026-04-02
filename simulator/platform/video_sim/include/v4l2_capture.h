#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct v4l2_capture v4l2_capture_t;

/**
 * Open a V4L2 video capture device and negotiate format/resolution.
 * Tries YUYV first, falls back to MJPEG.
 * Returns NULL on failure.
 */
v4l2_capture_t *v4l2_capture_open(const char *device,
                                   uint32_t desired_width,
                                   uint32_t desired_height);

/**
 * Get the negotiated (actual) capture resolution.
 */
void v4l2_capture_get_resolution(const v4l2_capture_t *cap,
                                  uint32_t *width, uint32_t *height);

/**
 * Grab one frame, convert to RGB565, write into caller-provided buffer.
 * Blocks until a frame is available (with 1-second timeout).
 * Returns number of bytes written, or 0 on failure/timeout.
 */
size_t v4l2_capture_read_rgb565(v4l2_capture_t *cap,
                                 uint8_t *rgb565_buf,
                                 size_t buf_size);

/**
 * Stop streaming, unmap buffers, close device, free handle.
 */
void v4l2_capture_close(v4l2_capture_t *cap);
