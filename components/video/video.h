#pragma once

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
 * @brief Initialize the video system
 *
 * Initializes the ESP video subsystem with CSI configuration.
 * Can use an existing I2C bus handle or create a new one.
 *
 * @param i2c_bus_handle Existing I2C bus handle (or NULL to create new one)
 * @return ESP_OK on success, or ESP_FAIL on failure
 */
esp_err_t app_video_main(i2c_master_bus_handle_t i2c_bus_handle);

/**
 * @brief Open a video device
 *
 * Opens the specified video device, queries its capabilities,
 * and configures the video format if needed.
 *
 * @param dev Path to the video device (e.g., "/dev/video0")
 * @param init_fmt Desired video format to initialize
 * @return File descriptor on success, or -1 on failure
 */
int app_video_open(char *dev, video_fmt_t init_fmt);

/**
 * @brief Set up video capture buffers.
 *
 * Configures the video device to use the specified number of buffers for
 * capturing video frames. Ensures the buffer count is within acceptable limits
 * and allocates buffers either via memory-mapped I/O or user pointers.
 * Closes the device on failure.
 *
 * @param video_fd File descriptor for the video device.
 * @param fb_num Number of frame buffers to allocate.
 * @param fb Array of pointers to user-provided frame buffers (if applicable).
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_set_bufs(int video_fd, uint32_t fb_num, const void **fb);

/**
 * @brief Retrieve video capture buffers.
 *
 * Fills the provided array with pointers to the allocated frame buffers for
 * capturing video frames. Checks that the specified buffer count is within
 * acceptable limits.
 *
 * @param fb_num Number of frame buffers to retrieve.
 * @param fb Array of pointers to receive the frame buffers.
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_get_bufs(int fb_num, void **fb);

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
 * Must be called after app_video_open() to get valid values.
 *
 * @param width Pointer to store the width value.
 * @param height Pointer to store the height value.
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_get_resolution(uint32_t *width, uint32_t *height);

/**
 * @brief Start the video stream task.
 *
 * Initiates the video streaming by starting the video stream and creating
 * a FreeRTOS task to handle the streaming process on a specified core.
 * Stops the video stream if task creation fails.
 *
 * @param video_fd File descriptor for the video device.
 * @param core_id Core ID to which the task will be pinned.
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_stream_task_start(int video_fd, int core_id);

/**
 * @brief Stop the video stream task.
 *
 * Deletes the video stream task if it is running and stops the video stream.
 * Ensures the task handle is reset to NULL after deletion.
 *
 * @param video_fd File descriptor for the video device.
 * @return ESP_OK on success.
 */
esp_err_t app_video_stream_task_stop(int video_fd);

/**
 * @brief Register a callback for video frame operations
 *
 * Sets a user-defined callback function that will be called for each
 * captured video frame. This allows custom processing of video data.
 *
 * @param operation_cb Callback function to handle video frames
 * @return ESP_OK on success
 */
esp_err_t app_video_register_frame_operation_cb(
    app_video_frame_operation_cb_t operation_cb);

/**
 * @brief Close video device and clean up video system.
 *
 * Stops the video stream, closes the video device file descriptor,
 * and deinitializes the video hardware system.
 *
 * @param video_fd File descriptor for the video device to close.
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_close(int video_fd);

/**
 * @brief Set the sensor auto-exposure target level.
 *
 * Controls how bright the sensor tries to make the image.
 * Lower values reduce exposure time and gain, which decreases
 * motion blur and saturated regions. Default is 0x50 (80).
 *
 * @param video_fd File descriptor for the video device.
 * @param level AE target level (range: 2-235).
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_set_ae_target(int video_fd, uint32_t level);

/**
 * @brief Set the camera focus position (DW9714 motor).
 *
 * Manually sets the lens focal position, bypassing auto-focus.
 * Lower values focus closer, higher values focus farther.
 *
 * @param video_fd File descriptor for the video device.
 * @param position Focus position (range: 0-1023).
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_set_focus(int video_fd, uint32_t position);

/**
 * @brief Check if a focus motor (DW9714) is available.
 *
 * Probes the V4L2_CID_FOCUS_ABSOLUTE control at runtime.
 *
 * @param video_fd File descriptor for the video device.
 * @return true if focus motor is available, false otherwise.
 */
bool app_video_has_focus_motor(int video_fd);

/**
 * @brief Deinitialize the video system.
 *
 * Calls esp_video_deinit() to clean up all video hardware resources.
 *
 * @return ESP_OK on success, or ESP_FAIL on failure.
 */
esp_err_t app_video_deinit(void);
