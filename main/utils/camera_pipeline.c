// Shared Camera & PPA Pipeline

#include "camera_pipeline.h"
#include "../core/entropy_pool.h"
#include "video.h"
#include <esp_heap_caps.h>
#include <esp_log.h>
#include <freertos/task.h>
#include <string.h>

static const char *TAG = "CAMERA_PIPELINE";

typedef enum {
  CAMERA_PIPELINE_EVENT_RUN = BIT(0),
  CAMERA_PIPELINE_EVENT_DELETE = BIT(1),
} camera_pipeline_event_t;

// app_video_start() takes a bare function pointer with no context argument;
// only one camera page streams at a time.
static camera_pipeline_t *volatile s_active_pipeline = NULL;

size_t camera_pipeline_align_size(size_t size) {
  const size_t line = CONFIG_CACHE_L2_CACHE_LINE_SIZE;
  return (size + line - 1) & ~(line - 1);
}

uint8_t *camera_pipeline_alloc_buffer(size_t size) {
  // PPA writes directly into these buffers, so they must be cache-line
  // aligned in both base address and byte length.
  size_t aligned = camera_pipeline_align_size(size);
  uint8_t *buf = heap_caps_aligned_calloc(CONFIG_CACHE_L2_CACHE_LINE_SIZE,
                                          aligned, 1, MALLOC_CAP_SPIRAM);
  if (!buf) {
    buf = heap_caps_aligned_calloc(CONFIG_CACHE_L2_CACHE_LINE_SIZE, aligned, 1,
                                   MALLOC_CAP_INTERNAL);
  }
  return buf;
}

void camera_pipeline_stir_entropy(const uint8_t *buf, size_t len) {
  // Sensor shot noise is real physical entropy and the frame is already here.
  // memcpy rather than a uint32_t cast: the callback contract hands over a
  // uint8_t *, so alignment is an assumption about today's allocator, not a
  // guarantee. Three separate stirs rather than one XOR of the three, which
  // would let equal samples cancel on a uniform frame.
  if (!buf || len < sizeof(uint32_t))
    return;

  size_t last = (len - sizeof(uint32_t)) & ~(size_t)3;
  size_t offsets[3] = {0, (last / 2) & ~(size_t)3, last};
  for (size_t i = 0; i < 3; i++) {
    uint32_t word;
    memcpy(&word, buf + offsets[i], sizeof(word));
    entropy_pool_stir(word);
  }
}

bool camera_pipeline_is_idle(const camera_pipeline_t *pipeline) {
  if (!pipeline)
    return true;
  if (__atomic_load_n(&pipeline->active_frame_ops, __ATOMIC_SEQ_CST) != 0)
    return false;
  if (pipeline->cfg.is_idle && !pipeline->cfg.is_idle(pipeline->cfg.ctx))
    return false;
  return true;
}

static void pipeline_frame_trampoline(uint8_t *camera_buf,
                                      uint8_t camera_buf_index,
                                      uint32_t camera_buf_hes,
                                      uint32_t camera_buf_ves,
                                      size_t camera_buf_len) {
  (void)camera_buf_index;
  camera_pipeline_t *p = __atomic_load_n(&s_active_pipeline, __ATOMIC_SEQ_CST);
  if (!p)
    return;

  __atomic_add_fetch(&p->active_frame_ops, 1, __ATOMIC_SEQ_CST);

  if (p->closing || !p->running || !p->event_group) {
    __atomic_sub_fetch(&p->active_frame_ops, 1, __ATOMIC_SEQ_CST);
    return;
  }

  EventBits_t bits = xEventGroupGetBits(p->event_group);
  if (!(bits & CAMERA_PIPELINE_EVENT_RUN) ||
      (bits & CAMERA_PIPELINE_EVENT_DELETE)) {
    __atomic_sub_fetch(&p->active_frame_ops, 1, __ATOMIC_SEQ_CST);
    return;
  }

  if (p->cfg.stir_entropy)
    camera_pipeline_stir_entropy(camera_buf, camera_buf_len);

  if (p->cfg.on_frame) {
    p->cfg.on_frame(p->ppa_client, camera_buf, camera_buf_hes, camera_buf_ves,
                    camera_buf_len, p->cfg.ctx);
  }

  __atomic_sub_fetch(&p->active_frame_ops, 1, __ATOMIC_SEQ_CST);
}

bool camera_pipeline_start(camera_pipeline_t *pipeline,
                           const camera_pipeline_config_t *cfg) {
  if (!pipeline || !cfg || !cfg->on_frame)
    return false;

  if (app_video_is_streaming())
    return true;

  if (!app_video_is_ready()) {
    ESP_LOGE(TAG, "Video pipeline is not ready");
    return false;
  }

  if (!camera_pipeline_is_idle(pipeline)) {
    ESP_LOGE(TAG, "Camera pipeline is still busy from previous session");
    return false;
  }

  pipeline->cfg = *cfg;
  pipeline->closing = false;

  bool created_event_group = false;
  if (!pipeline->event_group) {
    pipeline->event_group = xEventGroupCreate();
    if (!pipeline->event_group) {
      ESP_LOGE(TAG, "Failed to create camera event group");
      return false;
    }
    created_event_group = true;
  }
  xEventGroupClearBits(pipeline->event_group, CAMERA_PIPELINE_EVENT_DELETE);
  xEventGroupSetBits(pipeline->event_group, CAMERA_PIPELINE_EVENT_RUN);

  bool created_ppa = false;
  if (!pipeline->ppa_client) {
    ppa_client_config_t ppa_cfg = {
        .oper_type = PPA_OPERATION_SRM,
        .max_pending_trans_num = cfg->max_pending_trans_num,
    };
    if (ppa_register_client(&ppa_cfg, &pipeline->ppa_client) != ESP_OK) {
      ESP_LOGE(TAG, "Failed to register PPA client");
      pipeline->ppa_client = NULL;
      goto fail;
    }
    created_ppa = true;

    if (cfg->on_ppa_done) {
      ppa_event_callbacks_t ppa_cbs = {.on_trans_done = cfg->on_ppa_done};
      if (ppa_client_register_event_callbacks(pipeline->ppa_client, &ppa_cbs) !=
          ESP_OK) {
        ESP_LOGE(TAG, "Failed to register PPA completion callback");
        goto fail;
      }
    }
  }

  __atomic_store_n(&s_active_pipeline, pipeline, __ATOMIC_SEQ_CST);
  pipeline->running = true;

  esp_err_t start_err =
      app_video_start(pipeline_frame_trampoline, cfg->core_id);
  if (start_err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start camera stream task: %s",
             esp_err_to_name(start_err));
    pipeline->running = false;
    __atomic_store_n(&s_active_pipeline, NULL, __ATOMIC_SEQ_CST);
    goto fail;
  }

  return true;

fail:
  if (created_ppa && pipeline->ppa_client) {
    ppa_unregister_client(pipeline->ppa_client);
    pipeline->ppa_client = NULL;
  }
  if (created_event_group && pipeline->event_group) {
    vEventGroupDelete(pipeline->event_group);
    pipeline->event_group = NULL;
  }
  return false;
}

void camera_pipeline_request_stop(camera_pipeline_t *pipeline) {
  if (!pipeline)
    return;
  pipeline->closing = true;
  if (pipeline->event_group)
    xEventGroupClearBits(pipeline->event_group, CAMERA_PIPELINE_EVENT_RUN);
}

bool camera_pipeline_stop(camera_pipeline_t *pipeline) {
  if (!pipeline)
    return true;

  pipeline->closing = true;
  pipeline->running = false;

  if (pipeline->event_group) {
    xEventGroupClearBits(pipeline->event_group, CAMERA_PIPELINE_EVENT_RUN);
    xEventGroupSetBits(pipeline->event_group, CAMERA_PIPELINE_EVENT_DELETE);
  }

  for (int wait = 0;
       __atomic_load_n(&pipeline->active_frame_ops, __ATOMIC_SEQ_CST) > 0 &&
       wait < 30;
       wait++) {
    vTaskDelay(pdMS_TO_TICKS(10));
  }

  int remaining =
      __atomic_load_n(&pipeline->active_frame_ops, __ATOMIC_SEQ_CST);
  if (remaining > 0) {
    ESP_LOGW(TAG, "Timeout waiting for frame operations (remaining: %d)",
             remaining);
  }

  esp_err_t stop_err = app_video_stop();
  if (stop_err != ESP_OK)
    ESP_LOGW(TAG, "Camera stop failed: %s", esp_err_to_name(stop_err));

  // A non-blocking PPA pass or a stalled camera callback may still own DMA
  // buffers. Confirm completion rather than releasing them on a timeout.
  for (int i = 0; i < 200 && !camera_pipeline_is_idle(pipeline); i++)
    vTaskDelay(pdMS_TO_TICKS(5));
  bool idle = camera_pipeline_is_idle(pipeline);

  if (idle) {
    if (__atomic_load_n(&s_active_pipeline, __ATOMIC_SEQ_CST) == pipeline)
      __atomic_store_n(&s_active_pipeline, NULL, __ATOMIC_SEQ_CST);

    if (pipeline->ppa_client &&
        ppa_unregister_client(pipeline->ppa_client) == ESP_OK) {
      pipeline->ppa_client = NULL;
    }

    if (pipeline->event_group) {
      vEventGroupDelete(pipeline->event_group);
      pipeline->event_group = NULL;
    }
  } else {
    ESP_LOGE(TAG, "PPA still owns camera frame buffers; keeping client");
  }

  return idle;
}

uint32_t camera_pipeline_snap_yuv420_crop(uint32_t crop_max, uint32_t target) {
  // Even Q4.4 fractions only: the ESP32-P4 PPA drops odd fractions when
  // writing YUV420, and an odd crop cannot be centred on whole pixels.
  for (uint32_t n = 2; n <= 16; n += 2) {
    if ((target * 16u) % n != 0)
      continue;
    uint32_t crop = target * 16u / n;
    if (crop <= crop_max && crop % 2 == 0)
      return crop;
  }
  return target <= crop_max ? target : crop_max;
}

esp_err_t camera_pipeline_scale_rgb565_crop(ppa_client_handle_t ppa,
                                            const uint8_t *src, uint32_t src_w,
                                            uint32_t src_h, uint32_t max_crop,
                                            uint8_t *dst, size_t dst_buf_size,
                                            uint32_t dst_size) {
  if (!ppa || !src || !dst || src_w == 0 || src_h == 0 || dst_size == 0)
    return ESP_ERR_INVALID_ARG;

  uint32_t crop_max = (src_w < src_h) ? src_w : src_h;
  if (max_crop > 0 && crop_max > max_crop)
    crop_max = max_crop;
  // Snap crop so PPA's Q4.4 scale produces exactly dst_size; otherwise the
  // truncated scale leaves a noisy column on the right edge.
  uint32_t crop = app_video_ppa_snap_crop(crop_max, dst_size);
  uint32_t crop_ox = (src_w - crop) / 2;
  uint32_t crop_oy = (src_h - crop) / 2;
  float scale = (float)dst_size / (float)crop;

  ppa_srm_oper_config_t srm = {
      .in.buffer = src,
      .in.pic_w = src_w,
      .in.pic_h = src_h,
      .in.block_w = crop,
      .in.block_h = crop,
      .in.block_offset_x = crop_ox,
      .in.block_offset_y = crop_oy,
      .in.srm_cm = PPA_SRM_COLOR_MODE_RGB565,
      .out.buffer = dst,
      .out.buffer_size = dst_buf_size,
      .out.pic_w = dst_size,
      .out.pic_h = dst_size,
      .out.block_offset_x = 0,
      .out.block_offset_y = 0,
      .out.srm_cm = PPA_SRM_COLOR_MODE_RGB565,
      .rotation_angle = PPA_SRM_ROTATION_ANGLE_0,
      .scale_x = scale,
      .scale_y = scale,
      .mode = PPA_TRANS_MODE_BLOCKING,
  };
  return ppa_do_scale_rotate_mirror(ppa, &srm);
}
