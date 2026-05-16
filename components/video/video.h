#pragma once

/* C standard includes */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* System includes */
#include "esp_err.h"
#include "esp_log.h"
#include "esp_video_device.h"
#include "esp_video_init.h"
#include "linux/videodev2.h"

/* BSP includes */
#include "bsp/esp-bsp.h"

/* ----------------------- Type Definitions ----------------------- */

/**
 * @brief Video format enumeration
 *
 * Defines supported video pixel formats mapped to V4L2 format constants.
 */
typedef enum {
  APP_VIDEO_FMT_RAW8 = V4L2_PIX_FMT_SBGGR8, /**< 8-bit raw Bayer BGGR format */
  APP_VIDEO_FMT_RAW10 =
      V4L2_PIX_FMT_SBGGR10,               /**< 10-bit raw Bayer BGGR format */
  APP_VIDEO_FMT_GREY = V4L2_PIX_FMT_GREY, /**< 8-bit greyscale format */
  APP_VIDEO_FMT_RGB565 = V4L2_PIX_FMT_RGB565,  /**< RGB565 16-bit format */
  APP_VIDEO_FMT_RGB888 = V4L2_PIX_FMT_RGB24,   /**< RGB888 24-bit format */
  APP_VIDEO_FMT_YUV422 = V4L2_PIX_FMT_YUV422P, /**< YUV422 planar format */
  APP_VIDEO_FMT_YUV420 = V4L2_PIX_FMT_YUV420,  /**< YUV420 planar format */
} video_fmt_t;

/**
 * @brief Video frame operation callback type
 *
 * @param camera_buf Pointer to the camera buffer containing frame data
 * @param camera_buf_index Index of the current buffer
 * @param camera_buf_hes Horizontal resolution (width) of the frame
 * @param camera_buf_ves Vertical resolution (height) of the frame
 * @param camera_buf_len Length of the buffer in bytes
 */
typedef void (*app_video_frame_operation_cb_t)(uint8_t *camera_buf,
                                               uint8_t camera_buf_index,
                                               uint32_t camera_buf_hes,
                                               uint32_t camera_buf_ves,
                                               size_t camera_buf_len);

/* ----------------------- Macros and Constants ----------------------- */

#define CAM_DEV_PATH                                                           \
  (ESP_VIDEO_MIPI_CSI_DEVICE_NAME) /**< Default camera device path */
#define CAM_BUF_NUM (2)            /**< Default number of camera buffers */

/* Configure video format based on LCD color format */
#if CONFIG_BSP_LCD_COLOR_FORMAT_RGB888
#define APP_VIDEO_FMT (APP_VIDEO_FMT_RGB888)
#else
#define APP_VIDEO_FMT (APP_VIDEO_FMT_RGB565)
#endif

/* ----------------------- Function Declarations ----------------------- */

/**
 * @brief Initialize the boot-owned video pipeline once.
 *
 * Initializes the ESP video subsystem, opens the camera device, configures the
 * capture format, maps V4L2 buffers, and caches camera capabilities. Streaming
 * remains stopped until app_video_start() is called by a camera page.
 *
 * @param i2c_bus_handle Existing I2C bus handle (or NULL to create new one)
 * @return ESP_OK on success, or an ESP-IDF error on failure
 */
esp_err_t app_video_init_once(i2c_master_bus_handle_t i2c_bus_handle);

/**
 * @brief Check whether the boot-owned video pipeline is ready.
 *
 * @return true when init succeeded and the camera device is available
 */
bool app_video_is_ready(void);

/**
 * @brief Get the size of the video buffer.
 *
 * Calculates and returns the size of the video buffer based on the
 * camera's width, height, and pixel format (RGB565 or RGB888).
 *
 * @return Size of the video buffer in bytes.
 */
uint32_t app_video_get_buf_size(void);

/**
 * @brief Get the current video resolution.
 *
 * Retrieves the current width and height of the video stream.
 * Must be called after app_video_init_once() to get valid values.
 *
 * @param width Pointer to store the width value.
 * @param height Pointer to store the height value.
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_get_resolution(uint32_t *width, uint32_t *height);

/**
 * @brief Check whether the video stream is currently running.
 *
 * @return true when app_video_start() has succeeded and app_video_stop() has
 *         not yet been called.
 */
bool app_video_is_streaming(void);

/**
 * @brief Start camera streaming with a page-owned frame callback.
 *
 * Queues the persistent V4L2 buffers, starts the stream, and creates a FreeRTOS
 * task to deliver frames to the callback on the specified core.
 *
 * @param operation_cb Callback function to handle captured frames
 * @param core_id Core ID to which the task will be pinned.
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_start(app_video_frame_operation_cb_t operation_cb,
                          int core_id);

/**
 * @brief Stop camera streaming synchronously.
 *
 * Stops the V4L2 stream, waits for the stream task to exit, and clears the
 * active frame callback while keeping the opened device and mapped buffers for
 * later app_video_start() calls.
 *
 * @return ESP_OK on success, or ESP_ERR_TIMEOUT if the task did not exit.
 */
esp_err_t app_video_stop(void);

/**
 * @brief Set the sensor auto-exposure target level.
 *
 * Controls how bright the sensor tries to make the image.
 * Lower values reduce exposure time and gain, which decreases
 * motion blur and saturated regions. Default is 0x50 (80).
 *
 * @param level AE target level (range: 2-235).
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_set_ae_target(uint32_t level);

/**
 * @brief Set the camera focus position (DW9714 motor).
 *
 * Manually sets the lens focal position, bypassing auto-focus.
 * Lower values focus closer, higher values focus farther.
 *
 * @param position Focus position (range: 0-1023).
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_set_focus(uint32_t position);

/**
 * @brief Check if a focus motor (DW9714) is available.
 *
 * Probes the V4L2_CID_FOCUS_ABSOLUTE control at runtime.
 *
 * @return true if focus motor is available, false otherwise.
 */
bool app_video_has_focus_motor(void);
