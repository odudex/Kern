#include <fcntl.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/param.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_video_init.h"
#include "video.h"

static const char *TAG = "video";

#define MAX_BUFFER_COUNT 6
#define MIN_BUFFER_COUNT 2
#define VIDEO_TASK_STACK_SIZE (4 * 1024)
#define VIDEO_TASK_PRIORITY 3

typedef enum {
  VIDEO_TASK_DELETE = BIT(0),
  VIDEO_TASK_DELETE_DONE = BIT(1),
} video_event_id_t;

typedef struct {
  uint8_t *camera_buffer[MAX_BUFFER_COUNT];
  size_t camera_buf_size;
  uint32_t camera_buf_hes;
  uint32_t camera_buf_ves;
  struct v4l2_buffer v4l2_buf;
  uint8_t camera_mem_mode;
  int video_fd;
  app_video_frame_operation_cb_t frame_cb;
  TaskHandle_t task_handle;
  EventGroupHandle_t event_group;
} app_video_t;

static const esp_video_init_csi_config_t s_csi_config = {
    .sccb_config = {.init_sccb = true,
                    .i2c_config = {.port = 0,
                                   .scl_pin = BSP_I2C_SCL,
                                   .sda_pin = BSP_I2C_SDA},
                    .freq = 100000},
    .reset_pin = -1,
    .pwdn_pin = -1,
};

#if CONFIG_CAM_MOTOR_DW9714
static const esp_video_init_cam_motor_config_t s_cam_motor_config = {
    .sccb_config = {.init_sccb = true,
                    .i2c_config = {.port = 0,
                                   .scl_pin = BSP_I2C_SCL,
                                   .sda_pin = BSP_I2C_SDA},
                    .freq = 100000},
    .reset_pin = -1,
    .pwdn_pin = -1,
    .signal_pin = -1,
};
#endif

static const esp_video_init_config_t s_cam_config = {
    .csi = &s_csi_config,
#if CONFIG_CAM_MOTOR_DW9714
    .cam_motor = &s_cam_motor_config,
#endif
};

static app_video_t app_video = {.video_fd = -1};
static bool s_initialized = false;

static esp_err_t stream_start(int fd);
static esp_err_t stream_stop(int fd);
static void stream_task(void *arg);

esp_err_t app_video_main(i2c_master_bus_handle_t i2c_bus_handle) {
  if (s_initialized) {
    ESP_LOGW(TAG, "Already initialized");
    return ESP_OK;
  }

  esp_err_t ret;

  if (i2c_bus_handle) {
    static esp_video_init_csi_config_t csi_config;
    static esp_video_init_config_t cam_config;
#if CONFIG_CAM_MOTOR_DW9714
    static esp_video_init_cam_motor_config_t cam_motor_config;
    cam_motor_config = s_cam_motor_config;
    cam_motor_config.sccb_config.init_sccb = false;
    cam_motor_config.sccb_config.i2c_handle = i2c_bus_handle;
#endif
    csi_config = s_csi_config;
    csi_config.sccb_config.init_sccb = false;
    csi_config.sccb_config.i2c_handle = i2c_bus_handle;

    cam_config = (esp_video_init_config_t){
        .csi = &csi_config,
#if CONFIG_CAM_MOTOR_DW9714
        .cam_motor = &cam_motor_config,
#endif
    };
    ret = esp_video_init(&cam_config);
  } else {
    ret = esp_video_init(&s_cam_config);
  }

  if (ret == ESP_OK)
    s_initialized = true;
  return ret;
}

int app_video_open(char *dev, video_fmt_t fmt) {
  struct v4l2_format default_format = {.type = V4L2_BUF_TYPE_VIDEO_CAPTURE};
  struct v4l2_capability cap;

  int fd = open(dev, O_RDWR);
  if (fd < 0) {
    ESP_LOGE(TAG, "Open failed");
    return -1;
  }

  if (ioctl(fd, VIDIOC_QUERYCAP, &cap)) {
    ESP_LOGE(TAG, "QUERYCAP failed");
    goto fail;
  }

  ESP_LOGI(TAG, "Driver: %s, Card: %s", cap.driver, cap.card);

  if (ioctl(fd, VIDIOC_G_FMT, &default_format)) {
    ESP_LOGE(TAG, "G_FMT failed");
    goto fail;
  }

  ESP_LOGI(TAG, "Resolution: %" PRIu32 "x%" PRIu32, default_format.fmt.pix.width,
           default_format.fmt.pix.height);

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
      goto fail;
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

  return fd;

fail:
  close(fd);
  return -1;
}

esp_err_t app_video_set_bufs(int fd, uint32_t fb_num, const void **fb) {
  if (fb_num > MAX_BUFFER_COUNT || fb_num < MIN_BUFFER_COUNT) {
    ESP_LOGE(TAG, "Invalid buffer count: %" PRIu32, fb_num);
    return ESP_FAIL;
  }

  struct v4l2_requestbuffers req = {
      .count = fb_num,
      .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
      .memory = fb ? V4L2_MEMORY_USERPTR : V4L2_MEMORY_MMAP,
  };
  app_video.camera_mem_mode = req.memory;

  if (ioctl(fd, VIDIOC_REQBUFS, &req)) {
    ESP_LOGE(TAG, "REQBUFS failed");
    goto fail;
  }

  for (int i = 0; i < fb_num; i++) {
    struct v4l2_buffer buf = {
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .memory = req.memory,
        .index = i,
    };

    if (ioctl(fd, VIDIOC_QUERYBUF, &buf)) {
      ESP_LOGE(TAG, "QUERYBUF failed");
      goto fail;
    }

    if (req.memory == V4L2_MEMORY_MMAP) {
      app_video.camera_buffer[i] =
          mmap(NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
               buf.m.offset);
      if (app_video.camera_buffer[i] == MAP_FAILED) {
        ESP_LOGE(TAG, "mmap failed: %s", strerror(errno));
        goto fail;
      }
    } else {
      if (!fb[i]) {
        ESP_LOGE(TAG, "NULL buffer");
        goto fail;
      }
      buf.m.userptr = (unsigned long)fb[i];
      app_video.camera_buffer[i] = (uint8_t *)fb[i];
    }

    app_video.camera_buf_size = buf.length;

    if (ioctl(fd, VIDIOC_QBUF, &buf)) {
      ESP_LOGE(TAG, "QBUF failed");
      goto fail;
    }
  }

  return ESP_OK;

fail:
  if (req.memory == V4L2_MEMORY_MMAP) {
    for (int i = 0; i < MAX_BUFFER_COUNT; i++) {
      if (app_video.camera_buffer[i] &&
          app_video.camera_buffer[i] != MAP_FAILED) {
        munmap(app_video.camera_buffer[i], app_video.camera_buf_size);
        app_video.camera_buffer[i] = NULL;
      }
    }
  }
  close(fd);
  return ESP_FAIL;
}

esp_err_t app_video_get_bufs(int fb_num, void **fb) {
  if (fb_num > MAX_BUFFER_COUNT || fb_num < MIN_BUFFER_COUNT) {
    ESP_LOGE(TAG, "Invalid buffer count");
    return ESP_FAIL;
  }

  for (int i = 0; i < fb_num; i++) {
    if (!app_video.camera_buffer[i]) {
      ESP_LOGE(TAG, "NULL buffer at %d", i);
      return ESP_FAIL;
    }
    fb[i] = app_video.camera_buffer[i];
  }
  return ESP_OK;
}

uint32_t app_video_get_buf_size(void) {
  return app_video.camera_buf_hes * app_video.camera_buf_ves *
         (APP_VIDEO_FMT == APP_VIDEO_FMT_RGB565 ? 2 : 3);
}

esp_err_t app_video_get_resolution(uint32_t *width, uint32_t *height) {
  if (!width || !height)
    return ESP_FAIL;
  *width = app_video.camera_buf_hes;
  *height = app_video.camera_buf_ves;
  return ESP_OK;
}

static esp_err_t receive_frame(int fd) {
  memset(&app_video.v4l2_buf, 0, sizeof(app_video.v4l2_buf));
  app_video.v4l2_buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  app_video.v4l2_buf.memory = app_video.camera_mem_mode;

  if (ioctl(fd, VIDIOC_DQBUF, &app_video.v4l2_buf)) {
    ESP_LOGE(TAG, "DQBUF failed");
    return ESP_FAIL;
  }
  return ESP_OK;
}

static void process_frame(void) {
  uint8_t idx = app_video.v4l2_buf.index;
  app_video.v4l2_buf.m.userptr = (unsigned long)app_video.camera_buffer[idx];
  app_video.v4l2_buf.length = app_video.camera_buf_size;

  app_video.frame_cb(app_video.camera_buffer[idx], idx, app_video.camera_buf_hes,
                     app_video.camera_buf_ves, app_video.camera_buf_size);
}

static esp_err_t release_frame(int fd) {
  if (ioctl(fd, VIDIOC_QBUF, &app_video.v4l2_buf)) {
    ESP_LOGE(TAG, "QBUF failed");
    return ESP_FAIL;
  }
  return ESP_OK;
}

static esp_err_t stream_start(int fd) {
  int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  if (ioctl(fd, VIDIOC_STREAMON, &type)) {
    ESP_LOGE(TAG, "STREAMON failed: %s", strerror(errno));
    return ESP_FAIL;
  }
  ESP_LOGI(TAG, "Stream started");
  return ESP_OK;
}

static esp_err_t stream_stop(int fd) {
  int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  if (ioctl(fd, VIDIOC_STREAMOFF, &type)) {
    ESP_LOGE(TAG, "STREAMOFF failed");
    return ESP_FAIL;
  }
  xEventGroupSetBits(app_video.event_group, VIDEO_TASK_DELETE_DONE);
  ESP_LOGI(TAG, "Stream stopped");
  return ESP_OK;
}

static void stream_task(void *arg) {
  int fd = app_video.video_fd;
  ESP_ERROR_CHECK(stream_start(fd));

  while (1) {
    ESP_ERROR_CHECK(receive_frame(fd));

    if (app_video.v4l2_buf.flags & V4L2_BUF_FLAG_DONE)
      process_frame();

    ESP_ERROR_CHECK(release_frame(fd));

    if (xEventGroupGetBits(app_video.event_group) & VIDEO_TASK_DELETE) {
      xEventGroupClearBits(app_video.event_group, VIDEO_TASK_DELETE);
      ESP_ERROR_CHECK(stream_stop(fd));
      vTaskDelete(NULL);
    }
  }
}

esp_err_t app_video_stream_task_start(int fd, int core_id) {
  if (!app_video.event_group)
    app_video.event_group = xEventGroupCreate();
  xEventGroupClearBits(app_video.event_group, VIDEO_TASK_DELETE_DONE);

  app_video.video_fd = fd;

  if (xTaskCreatePinnedToCore(stream_task, "video_stream", VIDEO_TASK_STACK_SIZE,
                              NULL, VIDEO_TASK_PRIORITY, &app_video.task_handle,
                              core_id) != pdPASS) {
    ESP_LOGE(TAG, "Task create failed");
    return ESP_FAIL;
  }
  return ESP_OK;
}

esp_err_t app_video_stream_task_stop(int fd) {
  xEventGroupSetBits(app_video.event_group, VIDEO_TASK_DELETE);
  return ESP_OK;
}

esp_err_t app_video_register_frame_operation_cb(
    app_video_frame_operation_cb_t cb) {
  app_video.frame_cb = cb;
  return ESP_OK;
}

esp_err_t app_video_close(int fd) {
  esp_err_t ret = ESP_OK;

  app_video_stream_task_stop(fd);

  if (app_video.event_group) {
    xEventGroupWaitBits(app_video.event_group, VIDEO_TASK_DELETE_DONE, pdFALSE,
                        pdFALSE, pdMS_TO_TICKS(1000));
  }

  if (fd >= 0) {
    // Release mmap'd buffers before closing FD
    if (app_video.camera_mem_mode == V4L2_MEMORY_MMAP) {
      for (int i = 0; i < MAX_BUFFER_COUNT; i++) {
        if (app_video.camera_buffer[i] &&
            app_video.camera_buffer[i] != MAP_FAILED) {
          munmap(app_video.camera_buffer[i], app_video.camera_buf_size);
          app_video.camera_buffer[i] = NULL;
        }
      }
    }

    // Explicitly release V4L2 buffers
    struct v4l2_requestbuffers req = {
        .count = 0,
        .type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
        .memory = app_video.camera_mem_mode,
    };
    ioctl(fd, VIDIOC_REQBUFS, &req);

    if (close(fd)) {
      ESP_LOGE(TAG, "Close failed: %s", strerror(errno));
      ret = ESP_FAIL;
    }
  }

  if (app_video.event_group) {
    vEventGroupDelete(app_video.event_group);
    app_video.event_group = NULL;
  }

  memset(&app_video, 0, sizeof(app_video));
  app_video.video_fd = -1;

  return ret;
}

esp_err_t app_video_deinit(void) {
  if (!s_initialized) {
    ESP_LOGW(TAG, "Not initialized");
    return ESP_OK;
  }

  esp_err_t ret = esp_video_deinit();
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Deinit failed: %s", esp_err_to_name(ret));
    return ESP_FAIL;
  }

  s_initialized = false;
  return ESP_OK;
}
