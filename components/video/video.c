#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>

#include "driver/i2c_master.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_sccb_i2c.h"
#include "esp_sccb_intf.h"
#include "esp_video_init.h"
#include "esp_video_ioctl.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "video.h"

static const char *TAG = "video";

// OV5647 SCCB handle used to widen on-sensor AE hysteresis past the +/-8%
// window the managed sensor driver writes. The sensor's hunting response to
// that narrow band made luminance visibly pulse under high-contrast scenes.
#define OV5647_SCCB_ADDR 0x36
#define OV5647_SCCB_FREQ_HZ 100000
#define OV5647_AE_HYST_NUM_LOW 7   // BPT = target * 7/10
#define OV5647_AE_HYST_NUM_HIGH 13 // WPT = target * 13/10
#define OV5647_AE_HYST_DEN 10
// Gain ceiling (register pair 0x3a18/0x3a19). Sensor default is 0x03FF (~64x)
// which enables a digital-gain multiplier stage; that stage produces discrete
// ~2x jumps as AE steps in/out of it, appearing as square-wave luminance.
// 0x01FF (~32x) stays entirely in the analog-gain range.
#define OV5647_MAX_GAIN_HI 0x01
#define OV5647_MAX_GAIN_LO 0xFF

static i2c_master_bus_handle_t s_i2c_bus = NULL;
static esp_sccb_io_handle_t s_sensor_sccb = NULL;

static esp_err_t ensure_sensor_sccb(void) {
  if (s_sensor_sccb)
    return ESP_OK;
  if (!s_i2c_bus)
    return ESP_ERR_INVALID_STATE;
  sccb_i2c_config_t cfg = {
      .dev_addr_length = I2C_ADDR_BIT_LEN_7,
      .device_address = OV5647_SCCB_ADDR,
      .scl_speed_hz = OV5647_SCCB_FREQ_HZ,
      .addr_bits_width = 16,
      .val_bits_width = 8,
  };
  return sccb_new_i2c_io(s_i2c_bus, &cfg, &s_sensor_sccb);
}

#define MAX_BUFFER_COUNT 6
#define MIN_BUFFER_COUNT 2
// 8KB needed: motor driver init (DW9714) deepens SCCB/I2C call stack.
#define VIDEO_TASK_STACK_SIZE (8 * 1024)
#define VIDEO_TASK_PRIORITY 3
#define VIDEO_STOP_TIMEOUT_MS 1000
#define VIDEO_DQBUF_TIMEOUT_MS 100

typedef struct {
  uint8_t *camera_buffer[MAX_BUFFER_COUNT];
  size_t camera_buf_size;
  uint32_t camera_buf_hes;
  uint32_t camera_buf_ves;
  uint32_t buffer_count;
  int video_fd;
  bool ready;
  bool streaming;
  bool has_focus_motor;
  app_video_frame_operation_cb_t frame_cb;
  TaskHandle_t task_handle;
} app_video_t;

static app_video_t app_video = {.video_fd = -1};
static volatile bool s_stop_requested = false;
static SemaphoreHandle_t s_task_done = NULL;

static esp_err_t video_driver_init(i2c_master_bus_handle_t i2c_bus_handle);
static esp_err_t video_device_open(video_fmt_t fmt);
static esp_err_t configure_dqbuf_timeout(void);
static esp_err_t request_capture_buffers(uint32_t fb_num);
static esp_err_t queue_capture_buffers(void);
static esp_err_t stream_on(void);
static esp_err_t stream_off(void);
static void stream_task(void *arg);

static esp_err_t video_driver_init(i2c_master_bus_handle_t i2c_bus_handle) {
  if (!i2c_bus_handle)
    return ESP_ERR_INVALID_ARG;
  s_i2c_bus = i2c_bus_handle;

  esp_video_init_csi_config_t csi_config = {
      .sccb_config = {.init_sccb = false,
                      .i2c_handle = i2c_bus_handle,
                      .freq = 100000},
      .reset_pin = -1,
      .pwdn_pin = -1,
  };
  esp_video_init_config_t cam_config = {.csi = &csi_config};

#if BSP_CAM_HAS_MOTOR
  esp_video_init_cam_motor_config_t cam_motor_config = {
      .sccb_config = {.init_sccb = false,
                      .i2c_handle = i2c_bus_handle,
                      .freq = 100000},
      .reset_pin = -1,
      .pwdn_pin = -1,
      .signal_pin = -1,
  };
  cam_config.cam_motor = &cam_motor_config;
#endif

  return esp_video_init(&cam_config);
}

static bool query_focus_motor(void) {
#if BSP_CAM_HAS_MOTOR
  struct v4l2_query_ext_ctrl qctrl = {.id = V4L2_CID_FOCUS_ABSOLUTE};
  return (ioctl(app_video.video_fd, VIDIOC_QUERY_EXT_CTRL, &qctrl) == 0);
#else
  return false;
#endif
}

static esp_err_t configure_dqbuf_timeout(void) {
  struct timeval timeout = {
      .tv_sec = VIDEO_DQBUF_TIMEOUT_MS / 1000,
      .tv_usec = (VIDEO_DQBUF_TIMEOUT_MS % 1000) * 1000,
  };

  if (ioctl(app_video.video_fd, VIDIOC_S_DQBUF_TIMEOUT, &timeout)) {
    ESP_LOGE(TAG, "Set DQBUF timeout failed: %s", strerror(errno));
    return ESP_FAIL;
  }
  return ESP_OK;
}

static esp_err_t video_device_open(video_fmt_t fmt) {
  struct v4l2_format default_format = {.type = V4L2_BUF_TYPE_VIDEO_CAPTURE};
  struct v4l2_capability cap;

  int fd = open(CAM_DEV_PATH, O_RDWR);
  if (fd < 0) {
    ESP_LOGE(TAG, "Open failed: %s", strerror(errno));
    return ESP_FAIL;
  }
  app_video.video_fd = fd;

  if (ioctl(fd, VIDIOC_QUERYCAP, &cap)) {
    ESP_LOGE(TAG, "QUERYCAP failed");
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "Driver: %s, Card: %s", cap.driver, cap.card);

  if (ioctl(fd, VIDIOC_G_FMT, &default_format)) {
    ESP_LOGE(TAG, "G_FMT failed");
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "Resolution: %" PRIu32 "x%" PRIu32,
           default_format.fmt.pix.width, default_format.fmt.pix.height);

  app_video.camera_buf_hes = default_format.fmt.pix.width;
  app_video.camera_buf_ves = default_format.fmt.pix.height;

  if (default_format.fmt.pix.pixelformat != fmt) {
    struct v4l2_format format = {
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .fmt.pix.width = default_format.fmt.pix.width,
        .fmt.pix.height = default_format.fmt.pix.height,
        .fmt.pix.pixelformat = fmt,
    };
    if (ioctl(fd, VIDIOC_S_FMT, &format)) {
      ESP_LOGE(TAG, "S_FMT failed");
      return ESP_FAIL;
    }
  }

#if CONFIG_ENABLE_CAM_SENSOR_PIC_VFLIP || CONFIG_ENABLE_CAM_SENSOR_PIC_HFLIP
  struct v4l2_ext_controls controls = {.ctrl_class = V4L2_CTRL_CLASS_USER,
                                       .count = 1};
  struct v4l2_ext_control control[1];
  controls.controls = control;
#endif

#if CONFIG_ENABLE_CAM_SENSOR_PIC_VFLIP
  control[0].id = V4L2_CID_VFLIP;
  control[0].value = 1;
  if (ioctl(fd, VIDIOC_S_EXT_CTRLS, &controls))
    ESP_LOGW(TAG, "VFLIP failed");
#endif

#if CONFIG_ENABLE_CAM_SENSOR_PIC_HFLIP
  control[0].id = V4L2_CID_HFLIP;
  control[0].value = 1;
  if (ioctl(fd, VIDIOC_S_EXT_CTRLS, &controls))
    ESP_LOGW(TAG, "HFLIP failed");
#endif

  app_video.has_focus_motor = query_focus_motor();
  return configure_dqbuf_timeout();
}

static esp_err_t request_capture_buffers(uint32_t fb_num) {
  if (fb_num > MAX_BUFFER_COUNT || fb_num < MIN_BUFFER_COUNT) {
    ESP_LOGE(TAG, "Invalid buffer count: %" PRIu32, fb_num);
    return ESP_ERR_INVALID_ARG;
  }
  if (app_video.video_fd < 0)
    return ESP_ERR_INVALID_STATE;

  struct v4l2_requestbuffers req = {
      .count = fb_num,
      .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
      .memory = V4L2_MEMORY_MMAP,
  };

  if (ioctl(app_video.video_fd, VIDIOC_REQBUFS, &req)) {
    ESP_LOGE(TAG, "REQBUFS failed");
    return ESP_FAIL;
  }

  for (uint32_t i = 0; i < fb_num; i++) {
    struct v4l2_buffer buf = {
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .memory = V4L2_MEMORY_MMAP,
        .index = i,
    };

    if (ioctl(app_video.video_fd, VIDIOC_QUERYBUF, &buf)) {
      ESP_LOGE(TAG, "QUERYBUF failed");
      return ESP_FAIL;
    }

    app_video.camera_buffer[i] =
        mmap(NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED,
             app_video.video_fd, buf.m.offset);
    if (app_video.camera_buffer[i] == MAP_FAILED) {
      ESP_LOGE(TAG, "mmap failed: %s", strerror(errno));
      app_video.camera_buffer[i] = NULL;
      return ESP_FAIL;
    }

    app_video.camera_buf_size = buf.length;
  }

  app_video.buffer_count = fb_num;
  return ESP_OK;
}

static esp_err_t queue_capture_buffers(void) {
  if (!app_video.ready || app_video.video_fd < 0 || app_video.buffer_count == 0)
    return ESP_ERR_INVALID_STATE;

  for (uint32_t i = 0; i < app_video.buffer_count; i++) {
    struct v4l2_buffer buf = {
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .memory = V4L2_MEMORY_MMAP,
        .index = i,
        .length = app_video.camera_buf_size,
    };

    if (ioctl(app_video.video_fd, VIDIOC_QBUF, &buf)) {
      ESP_LOGE(TAG, "QBUF failed");
      return ESP_FAIL;
    }
  }

  return ESP_OK;
}

uint32_t app_video_get_buf_size(void) {
  if (app_video.camera_buf_size)
    return (uint32_t)app_video.camera_buf_size;
  return app_video.camera_buf_hes * app_video.camera_buf_ves * 2;
}

esp_err_t app_video_get_resolution(uint32_t *width, uint32_t *height) {
  if (!width || !height)
    return ESP_ERR_INVALID_ARG;
  if (!app_video.ready)
    return ESP_ERR_INVALID_STATE;
  *width = app_video.camera_buf_hes;
  *height = app_video.camera_buf_ves;
  return ESP_OK;
}

static esp_err_t receive_frame(struct v4l2_buffer *buf) {
  memset(buf, 0, sizeof(*buf));
  buf->type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  buf->memory = V4L2_MEMORY_MMAP;

  if (ioctl(app_video.video_fd, VIDIOC_DQBUF, buf)) {
    if (s_stop_requested)
      return ESP_ERR_INVALID_STATE;
    if (errno == ETIMEDOUT || errno == EPERM)
      return ESP_ERR_TIMEOUT;
    ESP_LOGE(TAG, "DQBUF failed: %s", strerror(errno));
    return ESP_FAIL;
  }
  return ESP_OK;
}

static void process_frame(const struct v4l2_buffer *buf) {
  uint8_t idx = buf->index;
  if (idx >= app_video.buffer_count) {
    ESP_LOGE(TAG, "Buffer index %u out of range", idx);
    return;
  }

  app_video_frame_operation_cb_t cb = app_video.frame_cb;
  if (!cb)
    return;

  cb(app_video.camera_buffer[idx], idx, app_video.camera_buf_hes,
     app_video.camera_buf_ves, app_video.camera_buf_size);
}

static esp_err_t release_frame(struct v4l2_buffer *buf) {
  if (s_stop_requested)
    return ESP_OK;

  if (ioctl(app_video.video_fd, VIDIOC_QBUF, buf)) {
    if (!s_stop_requested) {
      ESP_LOGE(TAG, "QBUF failed");
    }
    return ESP_FAIL;
  }
  return ESP_OK;
}

static esp_err_t stream_on(void) {
  int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  if (ioctl(app_video.video_fd, VIDIOC_STREAMON, &type)) {
    ESP_LOGE(TAG, "STREAMON failed: %s", strerror(errno));
    return ESP_FAIL;
  }
  app_video.streaming = true;
  ESP_LOGI(TAG, "Stream started");
  return ESP_OK;
}

static esp_err_t stream_off(void) {
  if (app_video.video_fd < 0 || !app_video.streaming)
    return ESP_OK;

  app_video.streaming = false;

  int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  esp_err_t ret = ESP_OK;
  if (ioctl(app_video.video_fd, VIDIOC_STREAMOFF, &type) && errno != EINVAL) {
    ESP_LOGW(TAG, "STREAMOFF failed: %s", strerror(errno));
    ret = ESP_FAIL;
  }

  ESP_LOGI(TAG, "Stream stopped");
  return ret;
}

static void stream_task(void *arg) {
  (void)arg;
  struct v4l2_buffer v4l2_buf;

  while (!s_stop_requested) {
    esp_err_t ret = receive_frame(&v4l2_buf);
    if (ret == ESP_ERR_TIMEOUT)
      continue;
    if (ret != ESP_OK)
      break;

    if (s_stop_requested)
      break;

    if (v4l2_buf.flags & V4L2_BUF_FLAG_DONE)
      process_frame(&v4l2_buf);

    if (release_frame(&v4l2_buf) != ESP_OK)
      break;
  }

  if (!s_stop_requested)
    (void)stream_off();
  app_video.task_handle = NULL;
  xSemaphoreGive(s_task_done);
  vTaskDelete(NULL);
}

esp_err_t app_video_init_once(i2c_master_bus_handle_t i2c_bus_handle) {
  if (app_video.ready)
    return ESP_OK;

  if (!s_task_done) {
    s_task_done = xSemaphoreCreateBinary();
    if (!s_task_done)
      return ESP_ERR_NO_MEM;
  }

  esp_err_t ret = video_driver_init(i2c_bus_handle);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Driver init failed: %s", esp_err_to_name(ret));
    return ret;
  }

  ret = video_device_open(APP_VIDEO_FMT_RGB565);
  if (ret != ESP_OK)
    return ret;

  ret = request_capture_buffers(CAM_BUF_NUM);
  if (ret != ESP_OK)
    return ret;

  app_video.ready = true;
  ESP_LOGI(TAG, "Video pipeline initialized once");
  return ESP_OK;
}

bool app_video_is_ready(void) { return app_video.ready; }

bool app_video_is_streaming(void) { return app_video.streaming; }

esp_err_t app_video_start(app_video_frame_operation_cb_t cb, int core_id) {
  if (!app_video.ready)
    return ESP_ERR_INVALID_STATE;
  if (!cb)
    return ESP_ERR_INVALID_ARG;
  if (app_video.task_handle || app_video.streaming)
    return ESP_ERR_INVALID_STATE;

  s_stop_requested = false;
  while (xSemaphoreTake(s_task_done, 0) == pdTRUE) {
  }

  esp_err_t ret = queue_capture_buffers();
  if (ret != ESP_OK)
    return ret;

  app_video.frame_cb = cb;
  ret = stream_on();
  if (ret != ESP_OK) {
    app_video.frame_cb = NULL;
    return ret;
  }

  if (xTaskCreatePinnedToCore(stream_task, "video_stream",
                              VIDEO_TASK_STACK_SIZE, NULL, VIDEO_TASK_PRIORITY,
                              &app_video.task_handle, core_id) != pdPASS) {
    ESP_LOGE(TAG, "Task create failed");
    app_video.frame_cb = NULL;
    (void)stream_off();
    return ESP_FAIL;
  }

  return ESP_OK;
}

esp_err_t app_video_stop(void) {
  if (!s_task_done)
    return ESP_OK;

  TaskHandle_t task = app_video.task_handle;
  if (!task && !app_video.streaming) {
    app_video.frame_cb = NULL;
    return ESP_OK;
  }

  s_stop_requested = true;
  app_video.frame_cb = NULL;
  esp_err_t ret = stream_off();

  if (task) {
    TickType_t timeout = pdMS_TO_TICKS(VIDEO_STOP_TIMEOUT_MS);
    if (xSemaphoreTake(s_task_done, timeout) != pdTRUE) {
      ESP_LOGW(TAG, "Timeout waiting for stream task");
      ret = ESP_ERR_TIMEOUT;
    }
  }

  s_stop_requested = false;
  return ret;
}

esp_err_t app_video_set_ae_target(uint32_t level) {
  // Bypass V4L2_CID_EXPOSURE: the OV5647 driver's ov5647_set_AE_target() writes
  // a +/-8% stable band, which causes AE to hunt on small luma shifts under
  // high-contrast scenes. Write the same target registers here with +/-20%.
  if (!app_video.ready)
    return ESP_ERR_INVALID_STATE;
  if (ensure_sensor_sccb() != ESP_OK) {
    ESP_LOGW(TAG, "Set AE target: SCCB handle unavailable");
    return ESP_FAIL;
  }
  if (level == 0)
    level = 1;
  if (level > 255)
    level = 255;
  uint32_t low = (level * OV5647_AE_HYST_NUM_LOW) / OV5647_AE_HYST_DEN;
  uint32_t high = (level * OV5647_AE_HYST_NUM_HIGH) / OV5647_AE_HYST_DEN;
  if (high > 255)
    high = 255;
  uint32_t fast_high = high * 2;
  if (fast_high > 255)
    fast_high = 255;
  uint32_t fast_low = low / 2;

  const struct {
    uint16_t reg;
    uint8_t val;
  } writes[] = {
      {0x3a0f, (uint8_t)high},      // WPT  (stable window high)
      {0x3a10, (uint8_t)low},       // BPT  (stable window low)
      {0x3a1b, (uint8_t)high},      // WPT2
      {0x3a1e, (uint8_t)low},       // BPT2
      {0x3a11, (uint8_t)fast_high}, // VPT  (fast-step high)
      {0x3a1f, (uint8_t)fast_low},  // fast-step low
      {0x3a18, OV5647_MAX_GAIN_HI}, // AE gain ceiling high
      {0x3a19, OV5647_MAX_GAIN_LO}, // AE gain ceiling low
  };
  for (size_t i = 0; i < sizeof(writes) / sizeof(writes[0]); i++) {
    if (esp_sccb_transmit_reg_a16v8(s_sensor_sccb, writes[i].reg,
                                    writes[i].val) != ESP_OK) {
      ESP_LOGW(TAG, "Set AE target: SCCB write to 0x%04x failed",
               writes[i].reg);
      return ESP_FAIL;
    }
  }
  return ESP_OK;
}

esp_err_t app_video_set_focus(uint32_t position) {
  if (!app_video.ready || app_video.video_fd < 0)
    return ESP_ERR_INVALID_STATE;
  if (!app_video.has_focus_motor)
    return ESP_ERR_NOT_SUPPORTED;

  struct v4l2_ext_controls controls = {.ctrl_class = V4L2_CTRL_CLASS_CAMERA,
                                       .count = 1};
  struct v4l2_ext_control control = {.id = V4L2_CID_FOCUS_ABSOLUTE,
                                     .value = position};
  controls.controls = &control;
  if (ioctl(app_video.video_fd, VIDIOC_S_EXT_CTRLS, &controls)) {
    ESP_LOGW(TAG, "Set focus position failed");
    return ESP_FAIL;
  }
  return ESP_OK;
}

bool app_video_has_focus_motor(void) {
  return app_video.ready && app_video.has_focus_motor;
}
