// UI-Free QR Scanner Engine (dual-pass PPA + k_quirc decode task)

#include "scanner_engine.h"
#include "../utils/camera_pipeline.h"
#include "../utils/memory_utils.h"
#include "../utils/secure_mem.h"
#include "frame_pool.h"
#include "parser.h"
#include "ur_decoder.h"
#include "yuv420.h"
#include <driver/ppa.h>
#include <esp_heap_caps.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <inttypes.h>
#include <k_quirc.h>
#include <stdlib.h>
#include <string.h>

// The OV5647 outputs 800x800, the centre of its 1280x960 binning mode. Every
// camera frame takes two PPA passes:
//   1. a centred square crop, scaled to the decode frame: up to 640 px whatever
//      the screen, in packed YUV420, whose luma the decoder reads directly;
//   2. the decode frame, scaled to the preview: RGB565, sized to the smaller
//      display dimension.
// The decoder used to read the preview, so a narrow screen also capped the
// pixels per QR module. Measured on a version 18 code, 3.6 px per module read
// 46% of captures and 4.8 px read 66%.
//
// The ESP32-P4 PPA uses Q4.4 fixed-point scaling (fractional scale quantized
// to 1/16), so an arbitrary scale like 2/3 truncates to 10/16 = 0.625 and
// leaves the last rows/cols unwritten. Both sizes are therefore derived from a
// scale already quantized down - to 1/8 for the YUV420 pass, where the PPA
// drops an odd fraction - so each output exactly fills its buffer.
//   wave_4b: crop 800 -> 12/16 -> 600x600 decode -> 16/16 -> 600x600 preview
//   wave_43: crop 800 -> 12/16 -> 600x600 decode -> 12/16 -> 450x450 preview
//   wave_35: crop 640 -> 16/16 -> 640x640 decode ->  8/16 -> 320x320 preview
//
// A PPA pass costs by the pixel it reads (~36 ns, measured; bytes per pixel and
// output size barely matter), and the first one paces the whole scan: the
// decoder waits on it. So the crop is no wider than the decode frame needs to
// stay sharp. 960 px read 44% more pixels than 800 for the same 600 out, and
// cost a sixth of the camera frames; the price is a field of view a sixth
// narrower. The sensor windows that same 800 px itself, so the camera writes
// half the bytes to PSRAM: with PSRAM at 80MHz (ESP32-P4 v3.x) camera frames
// rose from 7.7 to 13 a second and decoder passes from 7.6 to 12.8.
#define CAMERA_INPUT_WIDTH 800u
#define CAMERA_INPUT_HEIGHT 800u
#define CAMERA_INPUT_CROP_MAX 800u
#define DECODE_TARGET 640u

#define QR_DECODE_TASK_STACK_SIZE 32768
#define QR_DECODE_TASK_PRIORITY 5
// With a frame always waiting, the decoder never blocks for one, and a task
// that never blocks starves its core's idle task: the task watchdog fires and
// deleted tasks are never reaped. One tick every few passes is enough.
#define QR_DECODE_PASSES_PER_YIELD 8
// While the settings overlay is open, only every Nth camera frame is
// processed so PPA work and full-image LVGL invalidations don't starve
// touch handling; the preview still updates enough to judge exposure.
#define SETTINGS_PREVIEW_FRAME_DIVISOR 8
// Once parts of a sequence are coming in, the code is framed and the user is
// watching progress, while each preview pass holds the PPA from the next
// decode frame for its whole length: a third of the camera's frame rate,
// measured. So the preview then takes every Nth frame only. Aiming, and codes
// read in a frame or two, keep the full rate.
#define SEQUENCE_PREVIEW_FRAME_DIVISOR 2

static const char *TAG = "QR_SCANNER";

static camera_pipeline_t pipeline;
static qr_scanner_geometry_t active_geom;

// Decode frames (YUV420) go from the camera to the decoder, preview frames
// (RGB565) from the camera to LVGL. Neither consumer is waited for: the camera
// task never takes the LVGL lock, since waiting out a render there held a
// capture buffer past the sensor's frame period, and a frame the decoder has
// not reached is simply superseded. Instead each buffer has one owner at a
// time, handed on under this lock by the camera task, the PPA interrupt, the
// decoder task and the UI timer.
static uint8_t *decode_buffers[FRAME_POOL_SIZE];
static uint8_t *preview_buffers[FRAME_POOL_SIZE];
static size_t decode_buffer_size = 0;
static size_t preview_buffer_size = 0;
static frame_pool_t decode_pool;
static frame_pool_t preview_pool;
static portMUX_TYPE pool_lock = portMUX_INITIALIZER_UNLOCKED;
// The decode frame a preview pass is still reading, NULL when none is in
// flight. That pass is not waited for: camera frames arrive on sensor frame
// boundaries, so a callback a little over three periods long cost four.
static uint8_t *preview_pass_source = NULL;

static k_quirc_t *qr_decoder = NULL;
static TaskHandle_t qr_decode_task_handle = NULL;
// Given whenever a decode frame becomes ready.
static SemaphoreHandle_t qr_frame_ready = NULL;
// Latest complete progress snapshot, consumed by the UI timer.
static QueueHandle_t qr_progress_queue = NULL;
static SemaphoreHandle_t qr_task_done_sem = NULL;
static QRPartParser *qr_parser = NULL;

static volatile bool closing = false;
static volatile bool sequence_in_progress = false;
static volatile bool scan_completed = false;
static volatile bool scan_failed = false;
static const char *volatile scan_failure_msg = NULL;
static volatile bool settings_active = false;
static uint8_t settings_frame_count = 0;
static uint8_t frames_since_preview = 0;

// Opt-in pipeline timing, summarised once a second. Each field has a single
// writer; the reporter reads and clears without locking, so a sample can
// occasionally be lost, which is fine for a development aid.
#if CONFIG_KERN_SCAN_PROFILING
#include <esp_timer.h>

typedef struct {
  uint32_t count;
  uint32_t total_us;
  uint32_t max_us;
} scan_stat_t;

// Edges sit between whole frame periods of a 45 fps (22 ms) and a 30 fps
// (33 ms) sensor, so a dropped camera frame lands in its own bucket.
static const uint32_t scan_gap_edges_us[] = {28000, 39000, 55000, 78000};
#define SCAN_GAP_BUCKETS                                                       \
  (sizeof(scan_gap_edges_us) / sizeof(scan_gap_edges_us[0]) + 1)

static struct {
  uint32_t camera_gaps[SCAN_GAP_BUCKETS]; // between camera callbacks
  scan_stat_t ppa;                        // sensor frame -> decode frame
  scan_stat_t ppa_preview;                // decode frame -> preview
  scan_stat_t wait;                       // decoder idle, waiting for a frame
  scan_stat_t gray;
  scan_stat_t identify;
  scan_stat_t decode;
  uint32_t camera_frames;
  uint32_t no_buffer;   // camera frames skipped for want of a PPA target
  uint32_t presented;   // preview frames handed to LVGL
  uint32_t no_code;     // nothing QR-like found
  uint32_t undecodable; // found but unreadable: torn, blurred or clipped
  uint32_t decoded;
  uint32_t distinct; // decoded payload differs from the previous one
  uint32_t skipped;  // sequential parts the animation showed and we missed
  uint32_t errors[K_QUIRC_ERROR_INVALID_SYMBOL + 1]; // failed reads, by cause
  uint16_t qr_version;                               // of the last code read
  uint16_t qr_side_px;
} scan_profile;

// Written by the camera task when it queues a preview pass, read by the PPA
// interrupt that ends it; the pass is never waited for, so nothing brackets it.
static int64_t preview_pass_start;

static void scan_stat_add(scan_stat_t *stat, int64_t elapsed_us) {
  stat->count++;
  stat->total_us += (uint32_t)elapsed_us;
  if ((uint32_t)elapsed_us > stat->max_us)
    stat->max_us = (uint32_t)elapsed_us;
}

static uint32_t scan_stat_avg(const scan_stat_t *stat) {
  return stat->count ? stat->total_us / stat->count : 0;
}

#define PROFILE_START(name) int64_t profile_##name = esp_timer_get_time()
#define PROFILE_END(name)                                                      \
  scan_stat_add(&scan_profile.name, esp_timer_get_time() - profile_##name)
#define PROFILE_COUNT(field) scan_profile.field++

// A line costs ~15 ms of UART time. Printing from an idle-priority task keeps
// that off the camera, decoder and UI tasks, where it would itself be a
// once-a-second stall of the kind being hunted.
static void scan_profile_task(void *arg) {
  (void)arg;
  int64_t window_start = esp_timer_get_time();
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(1000));
    int64_t now = esp_timer_get_time();
    uint32_t window_ms = (uint32_t)((now - window_start) / 1000);
    window_start = now;

    typeof(scan_profile) p = scan_profile;
    memset(&scan_profile, 0, sizeof(scan_profile));
    if (!p.camera_frames && !p.identify.count)
      continue;

    uint32_t other_errors = 0;
    for (size_t i = K_QUIRC_ERROR_UNKNOWN_DATA_TYPE;
         i < sizeof(p.errors) / sizeof(p.errors[0]); i++)
      other_errors += p.errors[i];

    ESP_LOGI(
        TAG,
        "PROF cam %" PRIu32 "/s gaps %" PRIu32 "/%" PRIu32 "/%" PRIu32
        "/%" PRIu32 "/%" PRIu32 " ppa %" PRIu32 "/%" PRIu32 " prev %" PRIu32
        "/%" PRIu32 " nobuf %" PRIu32 " ui %" PRIu32 "/s | dec %" PRIu32
        "/s wait %" PRIu32 "/%" PRIu32 " gray %" PRIu32 "/%" PRIu32
        " find %" PRIu32 "/%" PRIu32 " read %" PRIu32 "/%" PRIu32
        " | ok %" PRIu32 " new %" PRIu32 " skip %" PRIu32 " none %" PRIu32
        " bad %" PRIu32 " | err grid %" PRIu32 " ver %" PRIu32 " fmt %" PRIu32
        " ecc %" PRIu32 " other %" PRIu32 " | qr v%u %upx",
        p.camera_frames * 1000 / window_ms, p.camera_gaps[0], p.camera_gaps[1],
        p.camera_gaps[2], p.camera_gaps[3], p.camera_gaps[4],
        scan_stat_avg(&p.ppa), p.ppa.max_us, scan_stat_avg(&p.ppa_preview),
        p.ppa_preview.max_us, p.no_buffer, p.presented * 1000 / window_ms,
        p.identify.count * 1000 / window_ms, scan_stat_avg(&p.wait),
        p.wait.max_us, scan_stat_avg(&p.gray), p.gray.max_us,
        scan_stat_avg(&p.identify), p.identify.max_us, scan_stat_avg(&p.decode),
        p.decode.max_us, p.decoded, p.distinct, p.skipped, p.no_code,
        p.undecodable, p.errors[K_QUIRC_ERROR_INVALID_GRID_SIZE],
        p.errors[K_QUIRC_ERROR_INVALID_VERSION],
        p.errors[K_QUIRC_ERROR_FORMAT_ECC], p.errors[K_QUIRC_ERROR_DATA_ECC],
        other_errors, (unsigned)p.qr_version, (unsigned)p.qr_side_px);
  }
}

// Left running once started: it only ever touches static storage, and
// deleting a task that may be inside printf risks stranding the stdout lock.
static void scan_profile_start(void) {
  static bool started;
  if (!started && xTaskCreate(scan_profile_task, "scan_prof", 4096, NULL, 1,
                              NULL) == pdPASS)
    started = true;
}
#else
#define PROFILE_START(name) ((void)0)
#define PROFILE_END(name) ((void)0)
#define PROFILE_COUNT(field) ((void)0)
#endif

qr_scanner_geometry_t qr_scanner_compute_geometry(uint32_t screen_min_dim) {
  uint32_t camera_target = screen_min_dim < 640u ? screen_min_dim : 640u;
  uint32_t input_crop = (camera_target * 2u <= CAMERA_INPUT_CROP_MAX)
                            ? (camera_target * 2u)
                            : CAMERA_INPUT_CROP_MAX;
  uint32_t decode_frag_max = (DECODE_TARGET * 16u) / input_crop;
  uint32_t decode_frag = (decode_frag_max > 16u ? 16u : decode_frag_max) & ~1u;
  uint32_t decode_size = (input_crop * decode_frag) / 16u;
  uint32_t preview_frag_max = (camera_target * 16u) / decode_size;
  uint32_t preview_frag = preview_frag_max > 16u ? 16u : preview_frag_max;
  uint32_t preview_size = (decode_size * preview_frag) / 16u;
  return (qr_scanner_geometry_t){
      .input_crop = input_crop,
      .decode_size = decode_size,
      .preview_frag = preview_frag,
      .preview_size = preview_size,
  };
}

static bool preview_pass_idle(void *ctx) {
  (void)ctx;
  return __atomic_load_n(&preview_pass_source, __ATOMIC_SEQ_CST) == NULL;
}

static void reset_frame_bookkeeping(void) {
  portENTER_CRITICAL_SAFE(&pool_lock);
  decode_pool = (frame_pool_t){0};
  preview_pool = (frame_pool_t){0};
  portEXIT_CRITICAL_SAFE(&pool_lock);
  __atomic_store_n(&preview_pass_source, NULL, __ATOMIC_SEQ_CST);
}

static void free_frame_buffers(void) {
  reset_frame_bookkeeping();
  for (size_t i = 0; i < FRAME_POOL_SIZE; i++)
    SAFE_FREE_STATIC(decode_buffers[i]);
  for (size_t i = 0; i < FRAME_POOL_SIZE; i++)
    SAFE_FREE_STATIC(preview_buffers[i]);
  decode_buffer_size = 0;
  preview_buffer_size = 0;
}

static bool allocate_frame_buffers(const qr_scanner_geometry_t *geom) {
  if (decode_buffers[0]) {
    // Kept by a shutdown that could not confirm the PPA had let go of them.
    if (!camera_pipeline_is_idle(&pipeline)) {
      ESP_LOGE(TAG, "Camera frame buffers are still in use");
      return false;
    }
    reset_frame_bookkeeping();
    return true;
  }

  // The PPA checks the size it is handed, not just the allocation.
  decode_buffer_size = camera_pipeline_align_size(
      YUV420_FRAME_BYTES(geom->decode_size, geom->decode_size));
  preview_buffer_size = camera_pipeline_align_size((size_t)geom->preview_size *
                                                   geom->preview_size * 2);

  for (size_t i = 0; i < FRAME_POOL_SIZE; i++) {
    decode_buffers[i] = camera_pipeline_alloc_buffer(decode_buffer_size);
    if (!decode_buffers[i])
      goto error;
  }
  for (size_t i = 0; i < FRAME_POOL_SIZE; i++) {
    preview_buffers[i] = camera_pipeline_alloc_buffer(preview_buffer_size);
    if (!preview_buffers[i])
      goto error;
  }
  reset_frame_bookkeeping();
  return true;

error:
  ESP_LOGE(TAG, "Failed to allocate camera frame buffers");
  free_frame_buffers();
  return false;
}

static const char *scan_failure_message(QRPartParser *parser) {
  if (parser && parser->alloc_failed) {
    ESP_LOGE(TAG, "QR scan aborted: allocation failure while storing parts");
    return "QR scan failed: out of memory";
  }

  if (parser && parser->too_large)
    return "QR sequence too large to decode";

  if (!parser || parser->format != FORMAT_UR || !parser->ur_decoder)
    return "Invalid QR sequence";

  switch (ur_decoder_get_state((ur_decoder_t *)parser->ur_decoder)) {
  case UR_DECODER_ERROR_INVALID_CHECKSUM:
    return "Invalid QR sequence: checksum mismatch";
  case UR_DECODER_ERROR_UNSUPPORTED_SIZE:
    return "QR sequence too large to decode";
  case UR_DECODER_NO_RESULT:
    return "Invalid QR sequence: no result";
  default:
    return "Invalid QR sequence";
  }
}

static void qr_decode_task(void *pvParameters) {
  (void)pvParameters;
  k_quirc_result_t qr_result;
  qr_progress_update_t progress_update = {0};
  uint8_t passes_since_yield = 0;
#if CONFIG_KERN_SCAN_PROFILING
  uint32_t last_payload_hash = 0;
  int last_part_index = -1;
#endif

  while (true) {
    if (closing)
      break;

    PROFILE_START(wait);
    if (xSemaphoreTake(qr_frame_ready, pdMS_TO_TICKS(100)) != pdTRUE)
      continue;
    PROFILE_END(wait);

    // Skip decoding while settings panel is open (camera feed continues)
    if (closing || settings_active)
      continue;

    portENTER_CRITICAL_SAFE(&pool_lock);
    int frame = frame_pool_claim(&decode_pool);
    portEXIT_CRITICAL_SAFE(&pool_lock);
    if (frame < 0)
      continue;

    uint8_t *qr_buf = k_quirc_begin(qr_decoder, NULL, NULL);
    if (qr_buf) {
      PROFILE_START(gray);
      yuv420_extract_luma(decode_buffers[frame], active_geom.decode_size,
                          active_geom.decode_size, qr_buf);
      PROFILE_END(gray);
      PROFILE_START(identify);
      k_quirc_end(qr_decoder, false);
      PROFILE_END(identify);

      int num_codes = k_quirc_count(qr_decoder);
#if CONFIG_KERN_SCAN_PROFILING
      bool frame_decoded = false;
#endif
      for (int i = 0; i < num_codes; i++) {
        if (closing)
          break;

        PROFILE_START(decode);
        k_quirc_error_t err = k_quirc_decode(qr_decoder, i, &qr_result);
        PROFILE_END(decode);
#if CONFIG_KERN_SCAN_PROFILING
        if (err != K_QUIRC_SUCCESS &&
            (size_t)err <
                sizeof(scan_profile.errors) / sizeof(scan_profile.errors[0]))
          scan_profile.errors[err]++;
#endif
        if (err == K_QUIRC_SUCCESS && qr_result.valid && qr_parser) {
#if CONFIG_KERN_SCAN_PROFILING
          // Pixels per module tell a marginal resolution from a torn capture.
          int side_x = abs(qr_result.corners[1].x - qr_result.corners[0].x);
          int side_y = abs(qr_result.corners[1].y - qr_result.corners[0].y);
          scan_profile.qr_version = (uint16_t)qr_result.data.version;
          scan_profile.qr_side_px =
              (uint16_t)(side_x > side_y ? side_x : side_y);
          // FNV-1a: tells a newly captured animation frame from a re-read.
          uint32_t payload_hash = 2166136261u;
          for (int b = 0; b < qr_result.data.payload_len; b++)
            payload_hash =
                (payload_hash ^ qr_result.data.payload[b]) * 16777619u;
          if (payload_hash != last_payload_hash)
            PROFILE_COUNT(distinct);
          last_payload_hash = payload_hash;
          PROFILE_COUNT(decoded);
          frame_decoded = true;
#endif

          int part_index = qr_parser_parse_with_len(
              qr_parser, (const char *)qr_result.data.payload,
              qr_result.data.payload_len);
#if CONFIG_KERN_SCAN_PROFILING
          // Sequential animations only: a jump of more than one part is a
          // frame that was on screen and never decoded.
          if (part_index >= 0 && qr_parser->total > 1 &&
              (qr_parser->format == FORMAT_PMOFN ||
               qr_parser->format == FORMAT_BBQR)) {
            if (last_part_index >= 0 && part_index != last_part_index) {
              int step = (part_index - last_part_index + qr_parser->total) %
                         qr_parser->total;
              scan_profile.skipped += (uint32_t)(step - 1);
            }
            last_part_index = part_index;
          }
#endif

          if (part_index >= 0 || qr_parser->total == 1) {
            progress_update.format = qr_parser->format;
            bool publish_progress = (qr_parser->format == FORMAT_PMOFN ||
                                     qr_parser->format == FORMAT_BBQR) &&
                                    qr_parser->total > 1;

            if (qr_parser->format == FORMAT_UR && qr_parser->ur_decoder) {
              progress_update.percent_complete =
                  ur_decoder_estimated_percent_complete(
                      (ur_decoder_t *)qr_parser->ur_decoder);
              publish_progress = true;
            } else if (publish_progress) {
              progress_update.parts.total = qr_parser->total;
              qr_part_progress_record(&progress_update.parts, part_index);
            }

            if (publish_progress && qr_progress_queue) {
              sequence_in_progress = true;
              xQueueOverwrite(qr_progress_queue, &progress_update);
            }

            if (qr_parser_is_complete(qr_parser)) {
              scan_completed = true;
              break;
            }
          }

          if (qr_parser_is_failed(qr_parser)) {
            scan_failure_msg = scan_failure_message(qr_parser);
            scan_failed = true;
            break;
          }
        }
      }

#if CONFIG_KERN_SCAN_PROFILING
      if (num_codes == 0)
        PROFILE_COUNT(no_code);
      else if (!frame_decoded)
        PROFILE_COUNT(undecodable);
#endif

      // k_quirc clears its own copies on return; the decoded payload - a
      // mnemonic or PSBT fragment - now lives only here, on a task stack that
      // outlives the scan.
      secure_memzero(&qr_result, sizeof(qr_result));
    }

    if (++passes_since_yield >= QR_DECODE_PASSES_PER_YIELD) {
      passes_since_yield = 0;
      vTaskDelay(1);
    }
  }

  if (qr_task_done_sem)
    xSemaphoreGive(qr_task_done_sem);
  vTaskSuspend(NULL);
}

static bool qr_decoder_init(uint32_t width, uint32_t height) {
  qr_decoder = k_quirc_new();
  if (!qr_decoder) {
    ESP_LOGE(TAG, "Failed to create QR decoder");
    goto error;
  }

  if (k_quirc_resize(qr_decoder, width, height) < 0) {
    ESP_LOGE(TAG, "Failed to resize QR decoder");
    goto error;
  }

  qr_frame_ready = xSemaphoreCreateBinary();
  if (!qr_frame_ready) {
    ESP_LOGE(TAG, "Failed to create QR frame semaphore");
    goto error;
  }

  qr_progress_queue = xQueueCreate(1, sizeof(qr_progress_update_t));
  if (!qr_progress_queue) {
    ESP_LOGE(TAG, "Failed to create QR progress queue");
    goto error;
  }

  qr_task_done_sem = xSemaphoreCreateBinary();
  if (!qr_task_done_sem) {
    ESP_LOGE(TAG, "Failed to create QR task done semaphore");
    goto error;
  }

  // Pin decode task to Core 1 to avoid competing with camera task on Core 0.
  // Stack lives in PSRAM: the ISP pipeline controller (when enabled on
  // crowpanel) holds enough internal DRAM for its task + IPA algorithm
  // state that a 32 KB internal-DRAM stack here fails to allocate. The decode
  // task never writes flash/NVS, so the SPI-cache-disabled caveat for PSRAM
  // stacks does not apply.
  BaseType_t task_result = xTaskCreatePinnedToCoreWithCaps(
      qr_decode_task, "qr_decode", QR_DECODE_TASK_STACK_SIZE, NULL,
      QR_DECODE_TASK_PRIORITY, &qr_decode_task_handle, 1, MALLOC_CAP_SPIRAM);
  if (task_result != pdPASS) {
    ESP_LOGE(TAG, "Failed to create QR decode task");
    goto error;
  }

  qr_parser = qr_parser_create();
  if (!qr_parser) {
    ESP_LOGE(TAG, "Failed to create QR parser");
    goto error;
  }
  return true;

error:
  if (qr_parser) {
    qr_parser_destroy(qr_parser);
    qr_parser = NULL;
  }
  if (qr_decode_task_handle) {
    vTaskDeleteWithCaps(qr_decode_task_handle);
    qr_decode_task_handle = NULL;
  }
  if (qr_task_done_sem) {
    vSemaphoreDelete(qr_task_done_sem);
    qr_task_done_sem = NULL;
  }
  if (qr_frame_ready) {
    vSemaphoreDelete(qr_frame_ready);
    qr_frame_ready = NULL;
  }
  if (qr_progress_queue) {
    vQueueDelete(qr_progress_queue);
    qr_progress_queue = NULL;
  }
  if (qr_decoder) {
    k_quirc_destroy(qr_decoder);
    qr_decoder = NULL;
  }
  return false;
}

static void qr_decoder_cleanup(void) {
  closing = true;

  if (qr_decode_task_handle && qr_task_done_sem) {
    // Let the decoder release its local allocations before deleting its
    // stack; forced deletion mid-decode can strand secrets and heap locks.
    xSemaphoreTake(qr_task_done_sem, portMAX_DELAY);
    vTaskDeleteWithCaps(qr_decode_task_handle);
    qr_decode_task_handle = NULL;
  }

  if (qr_task_done_sem) {
    vSemaphoreDelete(qr_task_done_sem);
    qr_task_done_sem = NULL;
  }

  if (qr_frame_ready) {
    vSemaphoreDelete(qr_frame_ready);
    qr_frame_ready = NULL;
  }

  if (qr_progress_queue) {
    vQueueDelete(qr_progress_queue);
    qr_progress_queue = NULL;
  }

  if (qr_decoder) {
    k_quirc_destroy(qr_decoder);
    qr_decoder = NULL;
  }

  if (qr_parser) {
    qr_parser_destroy(qr_parser);
    qr_parser = NULL;
  }
}

// PPA interrupt. Every transaction ends here, the blocking ones too; only the
// preview pass carries user data: its preview buffer's index, plus one.
static bool preview_pass_done_cb(ppa_client_handle_t client,
                                 ppa_event_data_t *event_data,
                                 void *user_data) {
  (void)client;
  (void)event_data;
  if (user_data) {
#if CONFIG_KERN_SCAN_PROFILING
    scan_stat_add(&scan_profile.ppa_preview,
                  esp_timer_get_time() - preview_pass_start);
#endif
    portENTER_CRITICAL_SAFE(&pool_lock);
    frame_pool_finish(&preview_pool, (int)(uintptr_t)user_data - 1);
    portEXIT_CRITICAL_SAFE(&pool_lock);
    __atomic_store_n(&preview_pass_source, NULL, __ATOMIC_SEQ_CST);
  }
  return false;
}

static void on_camera_frame(ppa_client_handle_t ppa, uint8_t *camera_buf,
                            uint32_t width, uint32_t height, size_t len,
                            void *ctx) {
  (void)len;
  (void)ctx;

  // Allocated all or none.
  if (closing || !decode_buffers[0] || !preview_buffers[0] || width == 0 ||
      height == 0)
    return;

#if CONFIG_KERN_SCAN_PROFILING
  static int64_t last_camera_frame;
  int64_t camera_frame_time = esp_timer_get_time();
  // A gap over a second is a new scan session, not a dropped frame.
  if (last_camera_frame && camera_frame_time - last_camera_frame < 1000000) {
    uint32_t gap_us = (uint32_t)(camera_frame_time - last_camera_frame);
    size_t bucket = 0;
    while (bucket < SCAN_GAP_BUCKETS - 1 && gap_us >= scan_gap_edges_us[bucket])
      bucket++;
    scan_profile.camera_gaps[bucket]++;
  }
  last_camera_frame = camera_frame_time;
  PROFILE_COUNT(camera_frames);
#endif

  if (settings_active) {
    if (++settings_frame_count < SETTINGS_PREVIEW_FRAME_DIVISOR)
      return;
    settings_frame_count = 0;

    // Decoder is paused while settings are open: scale RGB565 -> RGB565
    // directly into the preview pool in a single PPA pass instead of running
    // both Pass 1 (YUV420) and Pass 2 (RGB565).
    if (!ppa || __atomic_load_n(&preview_pass_source, __ATOMIC_SEQ_CST))
      return;

    int preview_index = -1;
    portENTER_CRITICAL_SAFE(&pool_lock);
    if (!frame_pool_has_ready(&preview_pool))
      preview_index = frame_pool_acquire(&preview_pool);
    portEXIT_CRITICAL_SAFE(&pool_lock);
    if (preview_index < 0)
      return;

    PROFILE_START(ppa);
    esp_err_t err = camera_pipeline_scale_rgb565_crop(
        ppa, camera_buf, width, height, active_geom.input_crop,
        preview_buffers[preview_index], preview_buffer_size,
        active_geom.preview_size);
    PROFILE_END(ppa);

    portENTER_CRITICAL_SAFE(&pool_lock);
    if (err == ESP_OK)
      frame_pool_finish(&preview_pool, preview_index);
    else
      frame_pool_abandon(&preview_pool, preview_index);
    portEXIT_CRITICAL_SAFE(&pool_lock);
    return;
  }

  static bool resolution_mismatch_logged = false;
  if (!resolution_mismatch_logged &&
      (width != CAMERA_INPUT_WIDTH || height != CAMERA_INPUT_HEIGHT)) {
    ESP_LOGW(TAG,
             "Camera resolution %" PRIu32 "x%" PRIu32
             " differs from expected %" PRIu32 "x%" PRIu32
             "; cropping dynamically",
             width, height, CAMERA_INPUT_WIDTH, CAMERA_INPUT_HEIGHT);
    resolution_mismatch_logged = true;
  }

  // Readers may share a decode frame; the PPA must not write one the decoder
  // or a preview pass could be reading. The pool keeps the decoder's. A preview
  // pass reads a frame that outlives it, ready or claimed, since the PPA runs
  // its passes in order: checked rather than assumed.
  int decode_index = -1;
  if (ppa && !closing) {
    portENTER_CRITICAL_SAFE(&pool_lock);
    decode_index = frame_pool_acquire(&decode_pool);
    if (decode_index >= 0 &&
        decode_buffers[decode_index] ==
            __atomic_load_n(&preview_pass_source, __ATOMIC_SEQ_CST)) {
      frame_pool_abandon(&decode_pool, decode_index);
      decode_index = -1;
    }
    portEXIT_CRITICAL_SAFE(&pool_lock);
  }
  if (decode_index < 0) {
    PROFILE_COUNT(no_buffer);
    return;
  }
  uint8_t *decode_frame = decode_buffers[decode_index];

  // Pass 1: centred square crop of the sensor frame -> decode frame.
  uint32_t crop_max = (width < height) ? width : height;
  if (crop_max > active_geom.input_crop)
    crop_max = active_geom.input_crop;
  uint32_t crop =
      camera_pipeline_snap_yuv420_crop(crop_max, active_geom.decode_size);
  ppa_srm_oper_config_t to_decode = {
      .in.buffer = camera_buf,
      .in.pic_w = width,
      .in.pic_h = height,
      .in.block_w = crop,
      .in.block_h = crop,
      .in.block_offset_x = (width - crop) / 2,
      .in.block_offset_y = (height - crop) / 2,
      .in.srm_cm = PPA_SRM_COLOR_MODE_RGB565,
      .out.buffer = decode_frame,
      .out.buffer_size = decode_buffer_size,
      .out.pic_w = active_geom.decode_size,
      .out.pic_h = active_geom.decode_size,
      .out.srm_cm = PPA_SRM_COLOR_MODE_YUV420,
      .out.yuv_range = PPA_COLOR_RANGE_FULL,
      .out.yuv_std = PPA_COLOR_CONV_STD_RGB_YUV_BT601,
      .rotation_angle = PPA_SRM_ROTATION_ANGLE_0,
      .scale_x = (float)active_geom.decode_size / (float)crop,
      .scale_y = (float)active_geom.decode_size / (float)crop,
      .mode = PPA_TRANS_MODE_BLOCKING,
  };
  PROFILE_START(ppa);
  esp_err_t ppa_err = ppa_do_scale_rotate_mirror(ppa, &to_decode);
  PROFILE_END(ppa);
  portENTER_CRITICAL_SAFE(&pool_lock);
  if (ppa_err == ESP_OK)
    frame_pool_finish(&decode_pool, decode_index);
  else
    frame_pool_abandon(&decode_pool, decode_index);
  portEXIT_CRITICAL_SAFE(&pool_lock);
  if (ppa_err != ESP_OK)
    return;

  // Decoder first: it gets the un-rotated frame (QR codes are
  // orientation-invariant) the moment it exists, before the preview pass. The
  // frame this one supersedes stayed ready all through the PPA pass: giving it
  // up before left the decoder idle for a quarter of its time.
  if (qr_frame_ready)
    xSemaphoreGive(qr_frame_ready);

  // Pass 2: decode frame -> preview, not waited for. The PPA runs its
  // transactions in order, so the next pass 1 queues behind this one and this
  // point is only reached once the previous preview pass has ended. That is
  // checked rather than assumed: the pass's source and target are tracked one
  // at a time, and shutdown counts on it. Skip Pass 2 if LVGL has not yet
  // claimed the previously finished preview frame so we don't burn PPA/PSRAM
  // bandwidth producing a preview that would just be overwritten.
  bool preview_due = !sequence_in_progress ||
                     ++frames_since_preview >= SEQUENCE_PREVIEW_FRAME_DIVISOR;
  int preview_index = -1;
  if (preview_due && !__atomic_load_n(&preview_pass_source, __ATOMIC_SEQ_CST)) {
    portENTER_CRITICAL_SAFE(&pool_lock);
    if (!frame_pool_has_ready(&preview_pool))
      preview_index = frame_pool_acquire(&preview_pool);
    portEXIT_CRITICAL_SAFE(&pool_lock);
  }
  if (preview_index >= 0) {
    frames_since_preview = 0;
    // The sizes are exact by construction.
    ppa_srm_oper_config_t to_preview = {
        .in.buffer = decode_frame,
        .in.pic_w = active_geom.decode_size,
        .in.pic_h = active_geom.decode_size,
        .in.block_w = active_geom.decode_size,
        .in.block_h = active_geom.decode_size,
        .in.srm_cm = PPA_SRM_COLOR_MODE_YUV420,
        .in.yuv_range = PPA_COLOR_RANGE_FULL,
        .in.yuv_std = PPA_COLOR_CONV_STD_RGB_YUV_BT601,
        .out.buffer = preview_buffers[preview_index],
        .out.buffer_size = preview_buffer_size,
        .out.pic_w = active_geom.preview_size,
        .out.pic_h = active_geom.preview_size,
        .out.srm_cm = PPA_SRM_COLOR_MODE_RGB565,
        .rotation_angle = PPA_SRM_ROTATION_ANGLE_0,
        .scale_x = (float)active_geom.preview_frag / 16.0f,
        .scale_y = (float)active_geom.preview_frag / 16.0f,
        .mode = PPA_TRANS_MODE_NON_BLOCKING,
        .user_data = (void *)(uintptr_t)(preview_index + 1),
    };
    // The PPA owns both buffers from here until preview_pass_done_cb().
    __atomic_store_n(&preview_pass_source, decode_frame, __ATOMIC_SEQ_CST);
#if CONFIG_KERN_SCAN_PROFILING
    preview_pass_start = esp_timer_get_time();
#endif
    if (ppa_do_scale_rotate_mirror(ppa, &to_preview) != ESP_OK) {
      portENTER_CRITICAL_SAFE(&pool_lock);
      frame_pool_abandon(&preview_pool, preview_index);
      portEXIT_CRITICAL_SAFE(&pool_lock);
      __atomic_store_n(&preview_pass_source, NULL, __ATOMIC_SEQ_CST);
    }
  }
}

bool qr_scanner_engine_start(const qr_scanner_geometry_t *geom) {
  if (!geom || geom->decode_size == 0 || (geom->decode_size % 2u) != 0 ||
      geom->preview_size == 0)
    return false;

#if CONFIG_KERN_SCAN_PROFILING
  scan_profile_start();
#endif

  active_geom = *geom;
  closing = false;
  sequence_in_progress = false;
  scan_completed = false;
  scan_failed = false;
  scan_failure_msg = NULL;
  settings_active = false;
  settings_frame_count = 0;
  frames_since_preview = 0;

  if (!allocate_frame_buffers(geom))
    return false;

  if (!qr_decoder_init(geom->decode_size, geom->decode_size))
    ESP_LOGE(TAG, "Failed to initialize QR decoder");

  // The PPA scales every frame twice: to the decode frame, then the preview.
  // A preview pass can still be pending when the next decode pass is queued.
  const camera_pipeline_config_t cfg = {
      .on_frame = on_camera_frame,
      .on_ppa_done = preview_pass_done_cb,
      .is_idle = preview_pass_idle,
      .ctx = NULL,
      .max_pending_trans_num = 2,
      .core_id = 0,
      .stir_entropy = true,
  };
  if (!camera_pipeline_start(&pipeline, &cfg)) {
    qr_decoder_cleanup();
    if (camera_pipeline_is_idle(&pipeline))
      free_frame_buffers();
    return false;
  }

  return true;
}

void qr_scanner_engine_request_stop(void) {
  closing = true;
  camera_pipeline_request_stop(&pipeline);
}

bool qr_scanner_engine_stop(void) {
  closing = true;
  settings_active = false;
  scan_completed = false;
  scan_failed = false;
  scan_failure_msg = NULL;

  bool pipeline_idle = camera_pipeline_stop(&pipeline);
  qr_decoder_cleanup();
  closing = false;
  return pipeline_idle;
}

void qr_scanner_engine_release_buffers(bool pipeline_idle) {
  if (pipeline_idle) {
    free_frame_buffers();
  } else {
    ESP_LOGE(TAG, "PPA still owns camera frame buffers; keeping them");
  }
}

void qr_scanner_engine_set_settings_active(bool active) {
  if (active)
    settings_frame_count = 0;
  settings_active = active;
}

const uint8_t *qr_scanner_engine_claim_preview(void) {
  if (closing || !preview_buffers[0])
    return NULL;

  portENTER_CRITICAL_SAFE(&pool_lock);
  int index = frame_pool_claim(&preview_pool);
  portEXIT_CRITICAL_SAFE(&pool_lock);
  if (index < 0)
    return NULL;

  PROFILE_COUNT(presented);
  return preview_buffers[index];
}

bool qr_scanner_engine_poll_progress(qr_progress_update_t *out) {
  if (!out || !qr_progress_queue)
    return false;
  return xQueueReceive(qr_progress_queue, out, 0) == pdTRUE;
}

bool qr_scanner_engine_is_completed(void) { return scan_completed; }

bool qr_scanner_engine_is_failed(const char **msg_out) {
  if (!scan_failed)
    return false;
  if (msg_out)
    *msg_out = scan_failure_msg;
  return true;
}

char *qr_scanner_engine_get_completed_content_with_len(size_t *content_len) {
  if (qr_parser && qr_parser_is_complete(qr_parser)) {
    size_t result_len;
    char *complete_result = qr_parser_result(qr_parser, &result_len);
    if (content_len)
      *content_len = result_len;
    return complete_result;
  }
  if (content_len)
    *content_len = 0;
  return NULL;
}

bool qr_scanner_engine_has_completed_result(void) {
  return qr_parser && qr_parser_is_complete(qr_parser);
}

int qr_scanner_engine_get_format(void) {
  return qr_parser ? qr_parser_get_format(qr_parser) : -1;
}

char qr_scanner_engine_get_bbqr_file_type(void) {
  return qr_parser_get_bbqr_file_type(qr_parser);
}

bool qr_scanner_engine_get_ur_result(const char **ur_type_out,
                                     const uint8_t **cbor_data_out,
                                     size_t *cbor_len_out) {
  if (qr_parser) {
    return qr_parser_get_ur_result(qr_parser, ur_type_out, cbor_data_out,
                                   cbor_len_out);
  }
  return false;
}
