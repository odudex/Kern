// QR Scanner

#include "scanner.h"
#include "../components/cUR/src/ur_decoder.h"
#include "../core/entropy_pool.h"
#include "../core/settings.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/theme_widgets.h"
#include "../utils/memory_utils.h"
#include "../utils/secure_mem.h"
#include "../utils/session_cleanup.h"
#include "frame_pool.h"
#include "parser.h"
#include "progress.h"
#include "yuv420.h"
#include <bsp/esp-bsp.h>
#include <driver/ppa.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <k_quirc.h>
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>

// The sensor outputs 1280x960 (binning mode). Every camera frame takes two PPA
// passes:
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
// narrower.
#define CAMERA_SCREEN_DIM_MIN                                                  \
  ((BSP_LCD_H_RES) < (BSP_LCD_V_RES) ? (BSP_LCD_H_RES) : (BSP_LCD_V_RES))
#define CAMERA_TARGET                                                          \
  ((CAMERA_SCREEN_DIM_MIN) < 640 ? (CAMERA_SCREEN_DIM_MIN) : 640)
#define CAMERA_INPUT_WIDTH 1280
#define CAMERA_INPUT_HEIGHT 960
#define CAMERA_INPUT_CROP_MAX 800
#define CAMERA_INPUT_CROP                                                      \
  ((CAMERA_TARGET * 2 <= CAMERA_INPUT_CROP_MAX) ? (CAMERA_TARGET * 2)          \
                                                : CAMERA_INPUT_CROP_MAX)
#define DECODE_TARGET 640
#define DECODE_PPA_FRAG_MAX ((DECODE_TARGET * 16) / CAMERA_INPUT_CROP)
#define DECODE_PPA_FRAG                                                        \
  ((DECODE_PPA_FRAG_MAX > 16 ? 16 : DECODE_PPA_FRAG_MAX) & ~1)
#define DECODE_FRAME_SIZE ((CAMERA_INPUT_CROP * DECODE_PPA_FRAG) / 16)
#define PREVIEW_PPA_FRAG_MAX ((CAMERA_TARGET * 16) / DECODE_FRAME_SIZE)
#define PREVIEW_PPA_FRAG (PREVIEW_PPA_FRAG_MAX > 16 ? 16 : PREVIEW_PPA_FRAG_MAX)
#define CAMERA_SCREEN_SIZE ((DECODE_FRAME_SIZE * PREVIEW_PPA_FRAG) / 16)
#define CAMERA_SCREEN_WIDTH CAMERA_SCREEN_SIZE
#define CAMERA_SCREEN_HEIGHT CAMERA_SCREEN_SIZE
// YUV420 packs luma by pixel pair and the PPA takes only even sizes for it.
_Static_assert(DECODE_FRAME_SIZE % 2 == 0, "decode frame size must be even");
#define QR_FRAME_QUEUE_SIZE 1
#define QR_DECODE_TASK_STACK_SIZE 32768
#define QR_DECODE_TASK_PRIORITY 5
// With a frame always waiting, the decoder never blocks on its queue, and a
// task that never blocks starves its core's idle task: the task watchdog fires
// and deleted tasks are never reaped. One tick every few passes is enough.
#define QR_DECODE_PASSES_PER_YIELD 8
#define PROGRESS_BAR_HEIGHT 20
#define PROGRESS_FRAME_INSET 6
// One LVGL timer presents the newest preview frame, applies scan progress and
// notices completion. It also caps the preview rate below the sensor's, which
// leaves PSRAM bandwidth to the decoder.
#define UI_UPDATE_INTERVAL_MS 30
#define QR_ROI_MARGIN_PERCENT 20
#define QR_ROI_MIN_SIZE 64
#define QR_ROI_SIZE_QUANTUM 16
#define QR_ROI_SHRINK_HYSTERESIS (2 * QR_ROI_SIZE_QUANTUM)
#define QR_ROI_FAILED_DECODE_LIMIT 10
// While the settings overlay is open, only every Nth camera frame is
// processed so PPA work and full-image LVGL invalidations don't starve
// touch handling; the preview still updates enough to judge exposure.
#define SETTINGS_PREVIEW_FRAME_DIVISOR 8

typedef enum {
  CAMERA_EVENT_TASK_RUN = BIT(0),
  CAMERA_EVENT_DELETE = BIT(1),
} camera_event_id_t;

typedef struct {
  uint8_t *frame_data;
  uint32_t width;
  uint32_t height;
} qr_frame_data_t;

typedef struct {
  int format;
  float percent_complete;
  qr_part_progress_t parts;
} qr_progress_update_t;

typedef struct {
  bool active;
  uint32_t x;
  uint32_t y;
  uint32_t width;
  uint32_t height;
  uint8_t failed_decodes;
} qr_decode_roi_t;

static const char *TAG = "QR_SCANNER";

static lv_obj_t *qr_scanner_screen = NULL;
static lv_obj_t *camera_img = NULL;
static lv_obj_t *progress_frame = NULL;
static lv_obj_t *progress_grid = NULL;
static lv_obj_t *progress_label = NULL;
static qr_part_progress_t displayed_progress;
static qr_progress_grid_t progress_layout;
static qr_progress_canvas_t progress_canvas;
static lv_obj_t *ur_progress_bar = NULL;
static lv_obj_t *ur_progress_indicator = NULL;
static int ur_progress_bar_inner_width = 0;
static void (*return_callback)(void) = NULL;

static lv_img_dsc_t img_refresh_dsc;
static EventGroupHandle_t camera_event_group = NULL;

// Decode frames (YUV420): one queued for the decoder, one it may still be
// reading, one for the PPA to write. Preview frames (RGB565): one on screen,
// one finished and unclaimed, one for the PPA to write. With three of each the
// PPA always has a target, so a queued frame never has to be withdrawn early.
#define DECODE_BUFFER_COUNT 3
#define PREVIEW_BUFFER_COUNT FRAME_POOL_SIZE
static uint8_t *decode_buffers[DECODE_BUFFER_COUNT];
static uint8_t *preview_buffers[PREVIEW_BUFFER_COUNT];
static size_t decode_buffer_size = 0;
static size_t preview_buffer_size = 0;

// Preview handoff. The camera task never takes the LVGL lock: waiting out a
// render there held a capture buffer past the sensor's frame period, so the
// driver dropped frames, and it delayed every frame's trip to the decoder.
// Instead each preview buffer has one owner at a time, handed on under this
// lock by the camera task, the PPA interrupt and the UI timer.
static frame_pool_t preview_pool;
static portMUX_TYPE preview_lock = portMUX_INITIALIZER_UNLOCKED;
// The decode frame a preview pass is still reading, NULL when none is in
// flight. That pass is not waited for: camera frames arrive on sensor frame
// boundaries, so a callback a little over three periods long cost four.
static uint8_t *preview_pass_source = NULL;

// Decode-lease bookkeeping, owned by the camera task: a buffer handed to the
// decoder must not be reused as a PPA target until the decoder returns it.
// "queued" is what sits in the frame queue; it is promoted to "held" when the
// drain comes back empty (the decoder took it) and cleared when the decoder
// sends it back on the return queue.
static uint8_t *queued_decode_buffer = NULL;
static uint8_t *held_decode_buffer = NULL;

static k_quirc_t *qr_decoder = NULL;
static TaskHandle_t qr_decode_task_handle = NULL;
static QueueHandle_t qr_frame_queue = NULL;
// Latest complete progress snapshot, consumed by the LVGL timer.
static QueueHandle_t qr_progress_queue = NULL;
// Buffers the decoder is done reading, returned to the camera task.
static QueueHandle_t qr_buffer_return_queue = NULL;
static SemaphoreHandle_t qr_task_done_sem = NULL;
static QRPartParser *qr_parser = NULL;

static volatile bool closing = false;
static volatile bool scan_completed = false;
static volatile bool scan_failed = false;
static const char *volatile scan_failure_msg = NULL;
static volatile bool is_fully_initialized = false;
static volatile bool destruction_in_progress = false;

// Camera settings overlay
static lv_obj_t *settings_overlay = NULL;
static lv_obj_t *ae_slider = NULL;
static lv_obj_t *focus_slider = NULL;
static bool has_focus_motor = false;
static bool has_ae_control = false;
static volatile bool settings_active = false;

static ppa_client_handle_t cam_ppa_client = NULL;

// Camera callbacks in progress. Balanced on every path and never forced to
// zero: camera_pipeline_idle() must not lie about one that is still running.
static volatile int active_frame_operations = 0;
static lv_timer_t *completion_timer = NULL;

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
  uint32_t roi_frames;  // decoder passes restricted to the ROI
  uint32_t roi_side_px; // side of the last ROI used
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
        "/s wait %" PRIu32 "/%" PRIu32 " roi %" PRIu32 "@%" PRIu32
        " gray %" PRIu32 "/%" PRIu32 " find %" PRIu32 "/%" PRIu32
        " read %" PRIu32 "/%" PRIu32 " | ok %" PRIu32 " new %" PRIu32
        " skip %" PRIu32 " none %" PRIu32 " bad %" PRIu32 " | err grid %" PRIu32
        " ver %" PRIu32 " fmt %" PRIu32 " ecc %" PRIu32 " other %" PRIu32
        " | qr v%u %upx",
        p.camera_frames * 1000 / window_ms, p.camera_gaps[0], p.camera_gaps[1],
        p.camera_gaps[2], p.camera_gaps[3], p.camera_gaps[4],
        scan_stat_avg(&p.ppa), p.ppa.max_us, scan_stat_avg(&p.ppa_preview),
        p.ppa_preview.max_us, p.no_buffer, p.presented * 1000 / window_ms,
        p.identify.count * 1000 / window_ms, scan_stat_avg(&p.wait),
        p.wait.max_us, p.roi_frames, p.roi_side_px, scan_stat_avg(&p.gray),
        p.gray.max_us, scan_stat_avg(&p.identify), p.identify.max_us,
        scan_stat_avg(&p.decode), p.decode.max_us, p.decoded, p.distinct,
        p.skipped, p.no_code, p.undecodable,
        p.errors[K_QUIRC_ERROR_INVALID_GRID_SIZE],
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

static void touch_event_cb(lv_event_t *e);
static void camera_video_frame_operation(uint8_t *camera_buf,
                                         uint8_t camera_buf_index,
                                         uint32_t camera_buf_hes,
                                         uint32_t camera_buf_ves,
                                         size_t camera_buf_len);
static bool allocate_frame_buffers(void);
static void free_frame_buffers(void);
static void update_decode_roi(qr_decode_roi_t *roi,
                              const k_quirc_result_t *result,
                              uint32_t decode_origin_x,
                              uint32_t decode_origin_y, uint32_t frame_width,
                              uint32_t frame_height);
static void qr_decode_task(void *pvParameters);
static bool qr_decoder_init(uint32_t width, uint32_t height);
static void qr_decoder_cleanup(void);
static bool camera_run(void);
static bool camera_init(void);
static void create_progress_indicators(int total_parts);
static void update_progress_indicators(const qr_part_progress_t *progress);
static void cleanup_progress_indicators(void);
static void create_ur_progress_bar(void);
static void update_ur_progress_bar(float percent_complete);
static void cleanup_ur_progress_bar(void);
static void process_pending_progress_update(void);

// The canvas only borrows its pixels, so they must outlive it: tie the buffer
// to the widget rather than to the order the page is torn down in.
static void progress_grid_deleted_cb(lv_event_t *event) {
  lv_draw_buf_destroy(lv_event_get_user_data(event));
}

// The grid covers the camera preview, which LVGL redraws on every frame. One
// cell per draw task would queue up to two thousand tasks per frame, so cells
// are painted into a canvas when they change and blitted as a single image.
static void create_progress_grid(void) {
  lv_draw_buf_t *buf =
      lv_draw_buf_create(progress_layout.width, progress_layout.height,
                         LV_COLOR_FORMAT_RGB565, LV_STRIDE_AUTO);
  if (!buf)
    return;

  progress_grid = lv_canvas_create(progress_frame);
  if (!progress_grid) {
    lv_draw_buf_destroy(buf);
    return;
  }
  lv_canvas_set_draw_buf(progress_grid, buf);
  lv_obj_add_event_cb(progress_grid, progress_grid_deleted_cb, LV_EVENT_DELETE,
                      buf);
  lv_obj_set_size(progress_grid, progress_layout.width, progress_layout.height);
  lv_obj_align(progress_grid, LV_ALIGN_BOTTOM_MID, 0, 0);

  progress_canvas = (qr_progress_canvas_t){
      .pixels = (uint16_t *)buf->data,
      .stride = buf->header.stride / sizeof(uint16_t),
      .gap = lv_color_to_u16(panel_color()),
      .missing = lv_color_to_u16(bg_color()),
      .missing_border = lv_color_to_u16(
          lv_color_mix(secondary_color(), bg_color(), LV_OPA_50)),
      .received = lv_color_to_u16(primary_color()),
      .latest = lv_color_to_u16(highlight_color()),
  };
}

static void create_progress_indicators(int total_parts) {
  if (total_parts <= 1 || !qr_scanner_screen)
    return;

  lv_obj_update_layout(qr_scanner_screen);
  int width = lv_obj_get_width(qr_scanner_screen) * 80 / 100;
  progress_layout =
      qr_progress_grid_layout(total_parts, width - 2 * PROGRESS_FRAME_INSET);
  if (!progress_layout.columns)
    return;

  progress_frame = lv_obj_create(qr_scanner_screen);
  theme_apply_frame(progress_frame);
  lv_obj_set_style_bg_opa(progress_frame, LV_OPA_COVER, 0);
  lv_obj_set_style_pad_all(progress_frame, PROGRESS_FRAME_INSET - 2, 0);
  lv_obj_remove_flag(progress_frame, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(progress_frame, LV_OBJ_FLAG_EVENT_BUBBLE);

  progress_label = theme_create_label(progress_frame, "", false);
  lv_obj_align(progress_label, LV_ALIGN_TOP_MID, 0, 0);

  // Without memory for the grid the frame count alone still shows progress.
  create_progress_grid();
  int height =
      lv_font_get_line_height(theme_font_small()) + 2 * PROGRESS_FRAME_INSET;
  if (progress_grid)
    height += progress_layout.height + 4;
  lv_obj_set_size(progress_frame,
                  progress_layout.width + 2 * PROGRESS_FRAME_INSET, height);
  lv_obj_align(progress_frame, LV_ALIGN_BOTTOM_MID, 0, -10);
}

static void update_progress_indicators(const qr_part_progress_t *progress) {
  bool created = false;
  if (!progress_frame) {
    create_progress_indicators(progress->total);
    if (!progress_frame)
      return;
    created = true;
  } else if (displayed_progress.received == progress->received &&
             displayed_progress.latest == progress->latest) {
    return;
  }

  if (created || displayed_progress.received != progress->received)
    lv_label_set_text_fmt(progress_label, "%d / %d frames", progress->received,
                          progress->total);
  if (progress_grid &&
      qr_progress_paint(&progress_canvas, &progress_layout,
                        created ? NULL : &displayed_progress, progress))
    lv_obj_invalidate(progress_grid);
  displayed_progress = *progress;
}

static void cleanup_progress_indicators(void) {
  progress_frame = NULL;
  progress_grid = NULL;
  progress_label = NULL;
  progress_canvas = (qr_progress_canvas_t){0};
  displayed_progress = (qr_part_progress_t){0};
  progress_layout = (qr_progress_grid_t){0};
}

static void create_ur_progress_bar(void) {
  if (!qr_scanner_screen || ur_progress_bar)
    return;

  int bar_width = lv_obj_get_width(qr_scanner_screen) * 80 / 100;
  int bar_height = PROGRESS_BAR_HEIGHT;
  ur_progress_bar_inner_width = bar_width - 4;

  ur_progress_bar = lv_obj_create(qr_scanner_screen);
  lv_obj_set_size(ur_progress_bar, bar_width, bar_height);
  lv_obj_align(ur_progress_bar, LV_ALIGN_BOTTOM_MID, 0, -10);
  theme_apply_frame(ur_progress_bar);
  lv_obj_set_style_pad_all(ur_progress_bar, 2, 0);

  ur_progress_indicator = lv_obj_create(ur_progress_bar);
  lv_obj_set_size(ur_progress_indicator, 0, 12);
  lv_obj_set_pos(ur_progress_indicator, 0, 0);
  theme_apply_solid_rectangle(ur_progress_indicator);
  lv_obj_set_style_bg_color(ur_progress_indicator, highlight_color(), 0);
}

static void update_ur_progress_bar(float percent_complete) {
  if (!ur_progress_bar || !ur_progress_indicator ||
      ur_progress_bar_inner_width <= 0)
    return;

  int indicator_width = (int)(ur_progress_bar_inner_width * percent_complete);
  if (indicator_width < 0)
    indicator_width = 0;
  if (indicator_width > ur_progress_bar_inner_width)
    indicator_width = ur_progress_bar_inner_width;

  lv_obj_set_width(ur_progress_indicator, indicator_width);
}

static void cleanup_ur_progress_bar(void) {
  ur_progress_bar = NULL;
  ur_progress_indicator = NULL;
  ur_progress_bar_inner_width = 0;
}

static void process_pending_progress_update(void) {
  if (!qr_progress_queue)
    return;

  qr_progress_update_t update;
  if (xQueueReceive(qr_progress_queue, &update, 0) == pdTRUE) {
    if (closing || destruction_in_progress || !qr_scanner_screen)
      return;

    // This runs from an LVGL timer, so progress objects can be mutated without
    // taking the display lock from the decoder task.
    if (update.format == FORMAT_UR) {
      if (!ur_progress_bar)
        create_ur_progress_bar();
      update_ur_progress_bar(update.percent_complete);
      return;
    }

    if ((update.format == FORMAT_PMOFN || update.format == FORMAT_BBQR) &&
        update.parts.total > 1) {
      update_progress_indicators(&update.parts);
    }
  }
}

static void present_pending_preview(void) {
  if (!camera_img || closing || destruction_in_progress)
    return;

  portENTER_CRITICAL_SAFE(&preview_lock);
  int index = frame_pool_claim(&preview_pool);
  portEXIT_CRITICAL_SAFE(&preview_lock);
  if (index < 0)
    return;

  img_refresh_dsc.data = preview_buffers[index];
  lv_img_set_src(camera_img, &img_refresh_dsc);
  PROFILE_COUNT(presented);
  // Active scanning counts as activity: hold off screensaver/session lock
  lv_display_trigger_activity(NULL);
}

static void completion_timer_cb(lv_timer_t *timer) {
  present_pending_preview();
  process_pending_progress_update();

  if ((scan_completed || scan_failed) && return_callback && !closing &&
      !destruction_in_progress) {
    closing = true;
    lv_timer_del(completion_timer);
    completion_timer = NULL;

    if (camera_event_group)
      xEventGroupClearBits(camera_event_group, CAMERA_EVENT_TASK_RUN);

    vTaskDelay(pdMS_TO_TICKS(50));
    if (scan_failed)
      dialog_show_error_timeout(scan_failure_msg ? scan_failure_msg
                                                 : "Invalid QR sequence",
                                return_callback, 0);
    else
      return_callback();
  }
}

static void touch_event_cb(lv_event_t *e) {
  if (closing || settings_overlay)
    return;
  closing = true;
  if (return_callback)
    return_callback();
}

// --- Camera settings overlay ---

static void destroy_settings_overlay(void) {
  if (!settings_overlay)
    return;

  // Save current values to NVS (invert focus slider back to hardware range)
  if (ae_slider)
    settings_set_ae_target((uint8_t)lv_slider_get_value(ae_slider));
  if (focus_slider)
    settings_set_focus_position(
        (uint16_t)(FOCUS_POSITION_MAX - lv_slider_get_value(focus_slider)));

  lv_obj_del(settings_overlay);
  settings_overlay = NULL;
  ae_slider = NULL;
  focus_slider = NULL;
  settings_active = false;
}

static void ae_slider_cb(lv_event_t *e) {
  int32_t val = lv_slider_get_value(lv_event_get_target(e));
  app_video_set_ae_target((uint32_t)val);
}

static void focus_slider_cb(lv_event_t *e) {
  int32_t val = lv_slider_get_value(lv_event_get_target(e));
  app_video_set_focus((uint32_t)(FOCUS_POSITION_MAX - val));
}

static void settings_close_cb(lv_event_t *e) { destroy_settings_overlay(); }

static void style_settings_slider(lv_obj_t *slider) {
  lv_obj_set_width(slider, LV_PCT(90));
  theme_apply_slider(slider);
  lv_obj_set_style_margin_ver(slider, theme_slider_knob_pad(), 0);
}

static void create_settings_overlay(void) {
  if (settings_overlay)
    return;

  settings_active = true;

  // Full-screen blocker
  settings_overlay = lv_obj_create(qr_scanner_screen);
  lv_obj_remove_style_all(settings_overlay);
  lv_obj_set_size(settings_overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_opa(settings_overlay, LV_OPA_TRANSP, 0);
  lv_obj_add_flag(settings_overlay, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_clear_flag(settings_overlay, LV_OBJ_FLAG_SCROLLABLE);

  // Bottom-aligned panel
  lv_obj_t *panel = lv_obj_create(settings_overlay);
  lv_obj_set_size(panel, LV_PCT(85), LV_SIZE_CONTENT);
  lv_obj_align(panel, LV_ALIGN_BOTTOM_MID, 0, -12);
  theme_apply_frame(panel);
  lv_obj_set_style_bg_opa(panel, LV_OPA_COVER, 0);
  lv_obj_set_flex_flow(panel, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(panel, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_ver(panel, 12, 0);
  lv_obj_set_style_pad_hor(panel, 12, 0);
  lv_obj_set_style_pad_row(panel, 10, 0);
  lv_obj_clear_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_flag(panel, LV_OBJ_FLAG_OVERFLOW_VISIBLE);

  // Exposure label + slider (only when sensor exposes AE control)
  if (has_ae_control) {
    lv_obj_t *ae_title = lv_label_create(panel);
    lv_label_set_text(ae_title, "Exposure");
    lv_obj_set_style_text_font(ae_title, theme_font_small(), 0);
    lv_obj_set_style_text_color(ae_title, primary_color(), 0);

    ae_slider = lv_slider_create(panel);
    lv_slider_set_range(ae_slider, AE_TARGET_MIN, AE_TARGET_MAX);
    lv_slider_set_value(ae_slider, settings_get_ae_target(), LV_ANIM_OFF);
    style_settings_slider(ae_slider);
    lv_obj_add_event_cb(ae_slider, ae_slider_cb, LV_EVENT_VALUE_CHANGED, NULL);
  }

  // Focus label + slider (only if motor detected, inverted: left=near
  // right=far)
  if (has_focus_motor) {
    lv_obj_t *focus_title = lv_label_create(panel);
    lv_label_set_text(focus_title, "Focus");
    lv_obj_set_style_text_font(focus_title, theme_font_small(), 0);
    lv_obj_set_style_text_color(focus_title, primary_color(), 0);

    focus_slider = lv_slider_create(panel);
    lv_slider_set_range(focus_slider, 0, FOCUS_POSITION_MAX);
    lv_slider_set_value(focus_slider,
                        FOCUS_POSITION_MAX - settings_get_focus_position(),
                        LV_ANIM_OFF);
    style_settings_slider(focus_slider);
    lv_obj_add_event_cb(focus_slider, focus_slider_cb, LV_EVENT_VALUE_CHANGED,
                        NULL);
  }

  // Close button
  lv_obj_t *close_btn = theme_create_button(panel, "Close", true);
  lv_obj_set_width(close_btn, LV_PCT(60));
  lv_obj_set_style_bg_opa(close_btn, LV_OPA_COVER, 0);
  lv_obj_set_style_margin_top(close_btn, 16, 0);
  lv_obj_add_event_cb(close_btn, settings_close_cb, LV_EVENT_CLICKED, NULL);
}

static void settings_btn_cb(lv_event_t *e) { create_settings_overlay(); }

static uint8_t *allocate_buffer_with_fallback(size_t size) {
  // PPA writes directly into these buffers, so they must be cache-line
  // aligned in size and base address.
  size_t aligned = (size + CONFIG_CACHE_L2_CACHE_LINE_SIZE - 1) &
                   ~(CONFIG_CACHE_L2_CACHE_LINE_SIZE - 1);
  uint8_t *buffer = heap_caps_aligned_calloc(CONFIG_CACHE_L2_CACHE_LINE_SIZE,
                                             aligned, 1, MALLOC_CAP_SPIRAM);
  if (!buffer) {
    buffer = heap_caps_aligned_calloc(CONFIG_CACHE_L2_CACHE_LINE_SIZE, aligned,
                                      1, MALLOC_CAP_INTERNAL);
  }
  return buffer;
}

// True once neither the camera callback nor the PPA can touch a frame buffer:
// the blocking decode pass ends inside the callback, the preview pass in its
// interrupt.
static bool camera_pipeline_idle(void) {
  return __atomic_load_n(&active_frame_operations, __ATOMIC_SEQ_CST) == 0 &&
         __atomic_load_n(&preview_pass_source, __ATOMIC_SEQ_CST) == NULL;
}

static void reset_frame_bookkeeping(void) {
  portENTER_CRITICAL_SAFE(&preview_lock);
  preview_pool = (frame_pool_t){0};
  portEXIT_CRITICAL_SAFE(&preview_lock);
  __atomic_store_n(&preview_pass_source, NULL, __ATOMIC_SEQ_CST);
  queued_decode_buffer = NULL;
  held_decode_buffer = NULL;
}

static bool allocate_frame_buffers(void) {
  if (decode_buffers[0]) {
    // Kept by a shutdown that could not confirm the PPA had let go of them.
    if (!camera_pipeline_idle()) {
      ESP_LOGE(TAG, "Camera frame buffers are still in use");
      return false;
    }
    reset_frame_bookkeeping();
    return true;
  }

  // The PPA checks the size it is handed, not just the allocation.
  const size_t line = CONFIG_CACHE_L2_CACHE_LINE_SIZE;
  decode_buffer_size =
      (YUV420_FRAME_BYTES(DECODE_FRAME_SIZE, DECODE_FRAME_SIZE) + line - 1) &
      ~(line - 1);
  preview_buffer_size =
      ((size_t)CAMERA_SCREEN_WIDTH * CAMERA_SCREEN_HEIGHT * 2 + line - 1) &
      ~(line - 1);

  for (size_t i = 0; i < DECODE_BUFFER_COUNT; i++) {
    decode_buffers[i] = allocate_buffer_with_fallback(decode_buffer_size);
    if (!decode_buffers[i])
      goto error;
  }
  for (size_t i = 0; i < PREVIEW_BUFFER_COUNT; i++) {
    preview_buffers[i] = allocate_buffer_with_fallback(preview_buffer_size);
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

// Only once camera_pipeline_idle(): the PPA writes these by DMA.
static void free_frame_buffers(void) {
  reset_frame_bookkeeping();
  for (size_t i = 0; i < DECODE_BUFFER_COUNT; i++)
    SAFE_FREE_STATIC(decode_buffers[i]);
  for (size_t i = 0; i < PREVIEW_BUFFER_COUNT; i++)
    SAFE_FREE_STATIC(preview_buffers[i]);
  decode_buffer_size = 0;
  preview_buffer_size = 0;
}

static void update_decode_roi(qr_decode_roi_t *roi,
                              const k_quirc_result_t *result,
                              uint32_t decode_origin_x,
                              uint32_t decode_origin_y, uint32_t frame_width,
                              uint32_t frame_height) {
  roi->failed_decodes = 0;

  int min_x = result->corners[0].x;
  int max_x = result->corners[0].x;
  int min_y = result->corners[0].y;
  int max_y = result->corners[0].y;
  for (int i = 1; i < 4; i++) {
    if (result->corners[i].x < min_x)
      min_x = result->corners[i].x;
    if (result->corners[i].x > max_x)
      max_x = result->corners[i].x;
    if (result->corners[i].y < min_y)
      min_y = result->corners[i].y;
    if (result->corners[i].y > max_y)
      max_y = result->corners[i].y;
  }

  int qr_width = max_x - min_x + 1;
  int qr_height = max_y - min_y + 1;
  if (qr_width <= 0 || qr_height <= 0 || frame_width == 0 || frame_height == 0)
    return;

  uint32_t qr_side = (uint32_t)((qr_width > qr_height) ? qr_width : qr_height);
  uint32_t margin = (qr_side * QR_ROI_MARGIN_PERCENT + 99) / 100; // Round up.
  uint32_t target_side = qr_side + 2 * margin;
  if (target_side < QR_ROI_MIN_SIZE)
    target_side = QR_ROI_MIN_SIZE;
  target_side =
      ((target_side + QR_ROI_SIZE_QUANTUM - 1) / QR_ROI_SIZE_QUANTUM) *
      QR_ROI_SIZE_QUANTUM;

  uint32_t frame_min =
      (frame_width < frame_height) ? frame_width : frame_height;
  if (target_side > frame_min)
    target_side = frame_min;

  // Keep the ROI stable across small apparent-size changes. Position is still
  // refreshed after every successful decode, growth is immediate, and shrinkage
  // occurs once it crosses the hysteresis window.
  if (roi->active && target_side < roi->width &&
      target_side + QR_ROI_SHRINK_HYSTERESIS >= roi->width) {
    target_side = roi->width;
  }

  int center_x = (int)decode_origin_x + min_x + qr_width / 2;
  int center_y = (int)decode_origin_y + min_y + qr_height / 2;
  int origin_x = center_x - (int)target_side / 2;
  int origin_y = center_y - (int)target_side / 2;
  if (origin_x < 0)
    origin_x = 0;
  if (origin_y < 0)
    origin_y = 0;
  if ((uint32_t)origin_x + target_side > frame_width)
    origin_x = (int)(frame_width - target_side);
  if ((uint32_t)origin_y + target_side > frame_height)
    origin_y = (int)(frame_height - target_side);

  roi->active = target_side < frame_width || target_side < frame_height;
  // Luma is addressed by pixel pair.
  roi->x = (uint32_t)origin_x & ~1u;
  roi->y = (uint32_t)origin_y;
  roi->width = target_side;
  roi->height = target_side;
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

static void release_decode_frame(uint8_t *frame_buffer) {
  if (qr_buffer_return_queue)
    xQueueSend(qr_buffer_return_queue, &frame_buffer, 0);
}

static void qr_decode_task(void *pvParameters) {
  qr_frame_data_t frame_data;
  k_quirc_result_t qr_result;
  qr_decode_roi_t roi = {0};
  qr_progress_update_t progress_update = {0};
  uint8_t passes_since_yield = 0;
#if CONFIG_KERN_SCAN_PROFILING
  uint32_t last_payload_hash = 0;
  int last_part_index = -1;
#endif

  while (true) {
    if (closing || destruction_in_progress)
      break;

    PROFILE_START(wait);
    if (xQueueReceive(qr_frame_queue, &frame_data, pdMS_TO_TICKS(100)) !=
        pdTRUE)
      continue;
    PROFILE_END(wait);

    if (closing || destruction_in_progress) {
      release_decode_frame(frame_data.frame_data);
      break;
    }

    // Skip decoding while settings panel is open (camera feed continues)
    if (settings_active) {
      release_decode_frame(frame_data.frame_data);
      continue;
    }

    uint32_t decode_x = roi.active ? roi.x : 0;
    uint32_t decode_y = roi.active ? roi.y : 0;
    uint32_t decode_width = roi.active ? roi.width : frame_data.width;
    uint32_t decode_height = roi.active ? roi.height : frame_data.height;

    if (decode_x + decode_width > frame_data.width ||
        decode_y + decode_height > frame_data.height) {
      roi = (qr_decode_roi_t){0};
      decode_x = 0;
      decode_y = 0;
      decode_width = frame_data.width;
      decode_height = frame_data.height;
    }

    // Initialization reserves the full frame, so all valid ROI transitions
    // (including returning to the full frame) reuse that capacity.
    if (k_quirc_resize(qr_decoder, decode_width, decode_height) < 0) {
      ESP_LOGW(TAG, "Invalid QR decoder dimensions %" PRIu32 "x%" PRIu32,
               decode_width, decode_height);
      release_decode_frame(frame_data.frame_data);
      continue;
    }

    uint8_t *qr_buf = k_quirc_begin(qr_decoder, NULL, NULL);
    if (qr_buf) {
      PROFILE_START(gray);
      yuv420_extract_luma(frame_data.frame_data, frame_data.width, decode_x,
                          decode_y, decode_width, decode_height, qr_buf);
      PROFILE_END(gray);
      // The luma is fully copied into the decoder's grayscale buffer; hand the
      // frame back so the camera can reuse it as a PPA target.
      release_decode_frame(frame_data.frame_data);
      PROFILE_START(identify);
      k_quirc_end(qr_decoder, false);
      PROFILE_END(identify);
#if CONFIG_KERN_SCAN_PROFILING
      if (roi.active) {
        scan_profile.roi_frames++;
        scan_profile.roi_side_px = decode_width;
      }
#endif

      int num_codes = k_quirc_count(qr_decoder);
      bool frame_decoded = false;
      for (int i = 0; i < num_codes; i++) {
        if (closing || destruction_in_progress)
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
#endif
          if (!frame_decoded) {
            update_decode_roi(&roi, &qr_result, decode_x, decode_y,
                              frame_data.width, frame_data.height);
            frame_decoded = true;
          }

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

            if (publish_progress && qr_progress_queue)
              xQueueOverwrite(qr_progress_queue, &progress_update);

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

      if (!frame_decoded && roi.active) {
        if (num_codes > 0) {
          // A code was detected inside the ROI; decode failures (torn
          // animation frames) shouldn't evict a well-placed ROI.
          roi.failed_decodes = 0;
        } else {
          roi.failed_decodes++;
          if (roi.failed_decodes >= QR_ROI_FAILED_DECODE_LIMIT) {
            ESP_LOGD(TAG, "Discarding QR ROI after %d failed decodes",
                     QR_ROI_FAILED_DECODE_LIMIT);
            roi = (qr_decode_roi_t){0};
          }
        }
      }

    } else {
      release_decode_frame(frame_data.frame_data);
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

  qr_frame_queue = xQueueCreate(QR_FRAME_QUEUE_SIZE, sizeof(qr_frame_data_t));
  if (!qr_frame_queue) {
    ESP_LOGE(TAG, "Failed to create QR frame queue");
    goto error;
  }

  qr_progress_queue = xQueueCreate(1, sizeof(qr_progress_update_t));
  if (!qr_progress_queue) {
    ESP_LOGE(TAG, "Failed to create QR progress queue");
    goto error;
  }

  qr_buffer_return_queue = xQueueCreate(2, sizeof(uint8_t *));
  if (!qr_buffer_return_queue) {
    ESP_LOGE(TAG, "Failed to create QR buffer return queue");
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
  if (qr_frame_queue) {
    vQueueDelete(qr_frame_queue);
    qr_frame_queue = NULL;
  }
  if (qr_progress_queue) {
    vQueueDelete(qr_progress_queue);
    qr_progress_queue = NULL;
  }
  if (qr_buffer_return_queue) {
    vQueueDelete(qr_buffer_return_queue);
    qr_buffer_return_queue = NULL;
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

  if (qr_frame_queue) {
    qr_frame_data_t frame_data;
    while (xQueueReceive(qr_frame_queue, &frame_data, 0) == pdTRUE) {
    }
    vQueueDelete(qr_frame_queue);
    qr_frame_queue = NULL;
  }

  if (qr_progress_queue) {
    vQueueDelete(qr_progress_queue);
    qr_progress_queue = NULL;
  }

  if (qr_buffer_return_queue) {
    vQueueDelete(qr_buffer_return_queue);
    qr_buffer_return_queue = NULL;
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
    portENTER_CRITICAL_SAFE(&preview_lock);
    frame_pool_finish(&preview_pool, (int)(uintptr_t)user_data - 1);
    portEXIT_CRITICAL_SAFE(&preview_lock);
    __atomic_store_n(&preview_pass_source, NULL, __ATOMIC_SEQ_CST);
  }
  return false;
}

// Largest centred crop that a Q4.4 scale takes to exactly the decode frame.
// Even fractions only: the PPA drops an odd one when it writes YUV420.
static uint32_t snap_decode_crop(uint32_t crop_max) {
  for (uint32_t n = 2; n <= 16; n += 2) {
    if ((DECODE_FRAME_SIZE * 16u) % n != 0)
      continue;
    uint32_t crop = DECODE_FRAME_SIZE * 16u / n;
    // YUV420 aside, an odd crop cannot be centred on whole pixels.
    if (crop <= crop_max && crop % 2 == 0)
      return crop;
  }
  return DECODE_FRAME_SIZE <= crop_max ? DECODE_FRAME_SIZE : crop_max;
}

// Camera task only. The decoder returns a frame as soon as it has copied it to
// grayscale, always before it takes the next one.
static void reclaim_returned_decode_buffers(void) {
  uint8_t *returned_buffer;
  while (qr_buffer_return_queue &&
         xQueueReceive(qr_buffer_return_queue, &returned_buffer, 0) == pdTRUE) {
    if (returned_buffer == held_decode_buffer)
      held_decode_buffer = NULL;
    if (returned_buffer == queued_decode_buffer)
      queued_decode_buffer = NULL;
  }
}

static void camera_video_frame_operation(uint8_t *camera_buf,
                                         uint8_t camera_buf_index,
                                         uint32_t camera_buf_hes,
                                         uint32_t camera_buf_ves,
                                         size_t camera_buf_len) {
  __atomic_add_fetch(&active_frame_operations, 1, __ATOMIC_SEQ_CST);

  if (closing || destruction_in_progress || !is_fully_initialized ||
      !camera_event_group) {
    __atomic_sub_fetch(&active_frame_operations, 1, __ATOMIC_SEQ_CST);
    return;
  }

  EventBits_t current_bits = xEventGroupGetBits(camera_event_group);
  if (!(current_bits & CAMERA_EVENT_TASK_RUN) ||
      (current_bits & CAMERA_EVENT_DELETE)) {
    __atomic_sub_fetch(&active_frame_operations, 1, __ATOMIC_SEQ_CST);
    return;
  }

  // Allocated all or none.
  if (!decode_buffers[0] || !preview_buffers[0]) {
    __atomic_sub_fetch(&active_frame_operations, 1, __ATOMIC_SEQ_CST);
    return;
  }

  if (camera_buf_hes == 0 || camera_buf_ves == 0) {
    __atomic_sub_fetch(&active_frame_operations, 1, __ATOMIC_SEQ_CST);
    return;
  }

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

  // Sensor shot noise is real physical entropy and the frame is already here.
  // memcpy rather than a uint32_t cast: the callback contract hands over a
  // uint8_t *, so alignment is an assumption about today's allocator, not a
  // guarantee. Three separate stirs rather than one XOR of the three, which
  // would let equal samples cancel on a uniform frame.
  if (camera_buf && camera_buf_len >= sizeof(uint32_t)) {
    size_t last = (camera_buf_len - sizeof(uint32_t)) & ~(size_t)3;
    size_t offsets[3] = {0, (last / 2) & ~(size_t)3, last};
    for (size_t i = 0; i < 3; i++) {
      uint32_t word;
      memcpy(&word, camera_buf + offsets[i], sizeof(word));
      entropy_pool_stir(word);
    }
  }

  if (settings_active) {
    static uint8_t settings_frame_count = 0;
    if (++settings_frame_count < SETTINGS_PREVIEW_FRAME_DIVISOR) {
      __atomic_sub_fetch(&active_frame_operations, 1, __ATOMIC_SEQ_CST);
      return;
    }
    settings_frame_count = 0;
  }

  static bool resolution_mismatch_logged = false;
  if (!resolution_mismatch_logged && (camera_buf_hes != CAMERA_INPUT_WIDTH ||
                                      camera_buf_ves != CAMERA_INPUT_HEIGHT)) {
    ESP_LOGW(TAG,
             "Camera resolution %" PRIu32 "x%" PRIu32
             " differs from expected %dx%d; cropping dynamically",
             camera_buf_hes, camera_buf_ves, CAMERA_INPUT_WIDTH,
             CAMERA_INPUT_HEIGHT);
    resolution_mismatch_logged = true;
  }

  reclaim_returned_decode_buffers();

  // Readers may share a decode frame; the PPA must not write one the decoder
  // or a preview pass could be reading.
  uint8_t *preview_source =
      __atomic_load_n(&preview_pass_source, __ATOMIC_SEQ_CST);
  uint8_t *decode_frame = NULL;
  for (size_t i = 0; i < DECODE_BUFFER_COUNT; i++) {
    if (decode_buffers[i] != queued_decode_buffer &&
        decode_buffers[i] != held_decode_buffer &&
        decode_buffers[i] != preview_source) {
      decode_frame = decode_buffers[i];
      break;
    }
  }
  if (!decode_frame || !cam_ppa_client || closing) {
    PROFILE_COUNT(no_buffer);
    __atomic_sub_fetch(&active_frame_operations, 1, __ATOMIC_SEQ_CST);
    return;
  }

  // Pass 1: centred square crop of the sensor frame -> decode frame.
  uint32_t crop_max =
      (camera_buf_hes < camera_buf_ves) ? camera_buf_hes : camera_buf_ves;
  if (crop_max > CAMERA_INPUT_CROP)
    crop_max = CAMERA_INPUT_CROP;
  uint32_t crop = snap_decode_crop(crop_max);
  ppa_srm_oper_config_t to_decode = {
      .in.buffer = camera_buf,
      .in.pic_w = camera_buf_hes,
      .in.pic_h = camera_buf_ves,
      .in.block_w = crop,
      .in.block_h = crop,
      .in.block_offset_x = (camera_buf_hes - crop) / 2,
      .in.block_offset_y = (camera_buf_ves - crop) / 2,
      .in.srm_cm = PPA_SRM_COLOR_MODE_RGB565,
      .out.buffer = decode_frame,
      .out.buffer_size = decode_buffer_size,
      .out.pic_w = DECODE_FRAME_SIZE,
      .out.pic_h = DECODE_FRAME_SIZE,
      .out.srm_cm = PPA_SRM_COLOR_MODE_YUV420,
      .out.yuv_range = PPA_COLOR_RANGE_FULL,
      .out.yuv_std = PPA_COLOR_CONV_STD_RGB_YUV_BT601,
      .rotation_angle = PPA_SRM_ROTATION_ANGLE_0,
      .scale_x = (float)DECODE_FRAME_SIZE / (float)crop,
      .scale_y = (float)DECODE_FRAME_SIZE / (float)crop,
      .mode = PPA_TRANS_MODE_BLOCKING,
  };
  PROFILE_START(ppa);
  esp_err_t ppa_err = ppa_do_scale_rotate_mirror(cam_ppa_client, &to_decode);
  PROFILE_END(ppa);
  if (ppa_err != ESP_OK) {
    __atomic_sub_fetch(&active_frame_operations, 1, __ATOMIC_SEQ_CST);
    return;
  }

  // Decoder first: it gets the un-rotated frame (QR codes are
  // orientation-invariant) the moment it exists, before the preview pass. The
  // frame it supersedes is withdrawn only now: taking it back before the PPA
  // left the queue empty for the whole scale pass, and the decoder idle for a
  // quarter of its time. An empty queue means the decoder took that frame and
  // may still be reading it.
  reclaim_returned_decode_buffers();
  if (qr_frame_queue) {
    qr_frame_data_t stale_frame;
    if (xQueueReceive(qr_frame_queue, &stale_frame, 0) == pdTRUE) {
      if (stale_frame.frame_data == queued_decode_buffer)
        queued_decode_buffer = NULL;
    } else if (queued_decode_buffer) {
      held_decode_buffer = queued_decode_buffer;
      queued_decode_buffer = NULL;
    }

    if (!settings_active) {
      qr_frame_data_t frame_data = {.frame_data = decode_frame,
                                    .width = DECODE_FRAME_SIZE,
                                    .height = DECODE_FRAME_SIZE};
      if (xQueueSend(qr_frame_queue, &frame_data, 0) == pdTRUE)
        queued_decode_buffer = decode_frame;
    }
  }

  // Pass 2: decode frame -> preview, not waited for. The PPA runs its
  // transactions in order, so the next pass 1 queues behind this one and this
  // point is only reached once the previous preview pass has ended. That is
  // checked rather than assumed: the pass's source and target are tracked one
  // at a time, and shutdown counts on it.
  int preview_index = -1;
  if (!__atomic_load_n(&preview_pass_source, __ATOMIC_SEQ_CST)) {
    portENTER_CRITICAL_SAFE(&preview_lock);
    preview_index = frame_pool_acquire(&preview_pool);
    portEXIT_CRITICAL_SAFE(&preview_lock);
  }
  if (preview_index >= 0) {
    // The sizes are exact by construction.
    ppa_srm_oper_config_t to_preview = {
        .in.buffer = decode_frame,
        .in.pic_w = DECODE_FRAME_SIZE,
        .in.pic_h = DECODE_FRAME_SIZE,
        .in.block_w = DECODE_FRAME_SIZE,
        .in.block_h = DECODE_FRAME_SIZE,
        .in.srm_cm = PPA_SRM_COLOR_MODE_YUV420,
        .in.yuv_range = PPA_COLOR_RANGE_FULL,
        .in.yuv_std = PPA_COLOR_CONV_STD_RGB_YUV_BT601,
        .out.buffer = preview_buffers[preview_index],
        .out.buffer_size = preview_buffer_size,
        .out.pic_w = CAMERA_SCREEN_WIDTH,
        .out.pic_h = CAMERA_SCREEN_HEIGHT,
        .out.srm_cm = PPA_SRM_COLOR_MODE_RGB565,
        .rotation_angle = PPA_SRM_ROTATION_ANGLE_0,
        .scale_x = (float)PREVIEW_PPA_FRAG / 16.0f,
        .scale_y = (float)PREVIEW_PPA_FRAG / 16.0f,
        .mode = PPA_TRANS_MODE_NON_BLOCKING,
        .user_data = (void *)(uintptr_t)(preview_index + 1),
    };
    // The PPA owns both buffers from here until preview_pass_done_cb().
    __atomic_store_n(&preview_pass_source, decode_frame, __ATOMIC_SEQ_CST);
#if CONFIG_KERN_SCAN_PROFILING
    preview_pass_start = esp_timer_get_time();
#endif
    if (ppa_do_scale_rotate_mirror(cam_ppa_client, &to_preview) != ESP_OK) {
      portENTER_CRITICAL_SAFE(&preview_lock);
      frame_pool_abandon(&preview_pool, preview_index);
      portEXIT_CRITICAL_SAFE(&preview_lock);
      __atomic_store_n(&preview_pass_source, NULL, __ATOMIC_SEQ_CST);
    }
  }

  __atomic_sub_fetch(&active_frame_operations, 1, __ATOMIC_SEQ_CST);
}

static bool camera_init(void) {
  if (app_video_is_streaming())
    return true;

  if (!app_video_is_ready()) {
    ESP_LOGE(TAG, "Video pipeline is not ready");
    return false;
  }

  camera_event_group = xEventGroupCreate();
  if (!camera_event_group) {
    ESP_LOGE(TAG, "Failed to create camera event group");
    return false;
  }

  xEventGroupSetBits(camera_event_group, CAMERA_EVENT_TASK_RUN);

  img_refresh_dsc = (lv_img_dsc_t){
      .header = {.cf = LV_COLOR_FORMAT_RGB565,
                 .w = CAMERA_SCREEN_WIDTH,
                 .h = CAMERA_SCREEN_HEIGHT},
      .data_size = CAMERA_SCREEN_WIDTH * CAMERA_SCREEN_HEIGHT * 2,
      .data = NULL,
  };

  if (!allocate_frame_buffers())
    return false;

  if (!qr_decoder_init(DECODE_FRAME_SIZE, DECODE_FRAME_SIZE)) {
    ESP_LOGE(TAG, "Failed to initialize QR decoder");
  }

  // The PPA scales every frame twice: to the decode frame, then the preview.
  // A preview pass can still be pending when the next decode pass is queued.
  ppa_client_config_t ppa_cfg = {.oper_type = PPA_OPERATION_SRM,
                                 .max_pending_trans_num = 2};
  ppa_event_callbacks_t ppa_cbs = {.on_trans_done = preview_pass_done_cb};
  if (cam_ppa_client) {
    // Kept, with the buffers, by a shutdown that could not release it.
  } else if (ppa_register_client(&ppa_cfg, &cam_ppa_client) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to register PPA client for camera scaler");
    cam_ppa_client = NULL;
  } else if (ppa_client_register_event_callbacks(cam_ppa_client, &ppa_cbs) !=
             ESP_OK) {
    ESP_LOGE(TAG, "Failed to register PPA completion callback");
    ppa_unregister_client(cam_ppa_client);
    cam_ppa_client = NULL;
  }

  esp_err_t start_err = app_video_start(camera_video_frame_operation, 0);
  if (start_err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to start camera stream task: %s",
             esp_err_to_name(start_err));
    return false;
  }

  // Apply camera settings after stream starts (V4L2 controls register with the
  // sensor device only once streaming).
  if (has_ae_control) {
    app_video_set_ae_target(settings_get_ae_target());
  }
  if (has_focus_motor) {
    app_video_set_focus(settings_get_focus_position());
  }

  return true;
}

static bool camera_run(void) {
  if (!app_video_is_streaming())
    return camera_init();
  return true;
}

void qr_scanner_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  session_cleanup_register(qr_scanner_page_destroy);
  (void)parent;

#if CONFIG_KERN_SCAN_PROFILING
  scan_profile_start();
#endif

  return_callback = return_cb;
  closing = false;
  scan_completed = false;
  scan_failed = false;
  scan_failure_msg = NULL;
  is_fully_initialized = false;

  if (!app_video_is_ready()) {
    dialog_show_error_timeout("Camera not available", return_callback, 0);
    return;
  }

  // Probe sensor capabilities up front so we can gate the settings button
  // before camera_init() runs (which only happens later, inside camera_run()).
  has_focus_motor = app_video_has_focus_motor();
  has_ae_control = app_video_has_ae_control();

  qr_scanner_screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(qr_scanner_screen, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(qr_scanner_screen, bg_color(), 0);
  lv_obj_set_style_bg_opa(qr_scanner_screen, LV_OPA_COVER, 0);
  lv_obj_set_style_border_width(qr_scanner_screen, 0, 0);
  lv_obj_set_style_pad_all(qr_scanner_screen, 0, 0);
  lv_obj_set_style_radius(qr_scanner_screen, 0, 0);
  lv_obj_set_style_shadow_width(qr_scanner_screen, 0, 0);
  lv_obj_clear_flag(qr_scanner_screen, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(qr_scanner_screen, touch_event_cb, LV_EVENT_CLICKED,
                      NULL);

  lv_obj_t *frame_buffer = lv_obj_create(qr_scanner_screen);
  lv_obj_set_size(frame_buffer, CAMERA_SCREEN_WIDTH, CAMERA_SCREEN_HEIGHT);
  lv_obj_center(frame_buffer);
  lv_obj_set_style_bg_opa(frame_buffer, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(frame_buffer, 0, 0);
  lv_obj_set_style_pad_all(frame_buffer, 0, 0);
  lv_obj_set_style_radius(frame_buffer, 0, 0);
  lv_obj_clear_flag(frame_buffer, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_add_event_cb(frame_buffer, touch_event_cb, LV_EVENT_CLICKED, NULL);

  camera_img = lv_img_create(frame_buffer);
  lv_obj_set_size(camera_img, CAMERA_SCREEN_WIDTH, CAMERA_SCREEN_HEIGHT);
  lv_obj_center(camera_img);
  lv_obj_clear_flag(camera_img, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_style_bg_color(camera_img, bg_color(), 0);
  lv_obj_set_style_bg_opa(camera_img, LV_OPA_COVER, 0);

  lv_obj_t *title_label =
      theme_create_label(qr_scanner_screen, "QR Scanner", false);
  theme_apply_label(title_label, true);
  lv_obj_align(title_label, LV_ALIGN_TOP_MID, 0, 8);

  if (has_ae_control || has_focus_motor) {
    lv_obj_t *settings_btn =
        ui_create_settings_button(qr_scanner_screen, settings_btn_cb);
    lv_obj_set_style_bg_opa(settings_btn, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_color(settings_btn, bg_color(), 0);
  }

  if (!camera_run()) {
    ESP_LOGE(TAG, "Failed to initialize camera");
    return;
  }

  completion_timer =
      lv_timer_create(completion_timer_cb, UI_UPDATE_INTERVAL_MS, NULL);
  is_fully_initialized = true;
}

void qr_scanner_page_show(void) {
  if (is_fully_initialized && !closing && qr_scanner_screen) {
    lv_obj_clear_flag(qr_scanner_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void qr_scanner_page_hide(void) {
  if (is_fully_initialized && !closing && qr_scanner_screen) {
    lv_obj_add_flag(qr_scanner_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void qr_scanner_page_destroy(void) {
  session_cleanup_unregister(qr_scanner_page_destroy);
  destruction_in_progress = true;
  closing = true;
  is_fully_initialized = false;
  destroy_settings_overlay();
  has_focus_motor = false;
  has_ae_control = false;

  if (completion_timer) {
    lv_timer_del(completion_timer);
    completion_timer = NULL;
  }
  scan_completed = false;
  scan_failed = false;
  scan_failure_msg = NULL;

  if (camera_event_group) {
    xEventGroupClearBits(camera_event_group, CAMERA_EVENT_TASK_RUN);
    xEventGroupSetBits(camera_event_group, CAMERA_EVENT_DELETE);
  }

  int wait_count = 0;
  while (__atomic_load_n(&active_frame_operations, __ATOMIC_SEQ_CST) > 0 &&
         wait_count < 30) {
    vTaskDelay(pdMS_TO_TICKS(10));
    wait_count++;
  }

  int remaining_ops =
      __atomic_load_n(&active_frame_operations, __ATOMIC_SEQ_CST);
  if (remaining_ops > 0)
    ESP_LOGW(TAG, "Timeout waiting for frame operations (remaining: %d)",
             remaining_ops);

  esp_err_t stop_err = app_video_stop();
  if (stop_err != ESP_OK)
    ESP_LOGW(TAG, "Camera stop failed: %s", esp_err_to_name(stop_err));

  // The last preview pass may still be running, and a camera task that would
  // not stop may still be inside the decode pass. The PPA writes these buffers
  // by DMA, so they are freed only on confirmed completion, never on a timeout.
  for (int i = 0; i < 200 && !camera_pipeline_idle(); i++)
    vTaskDelay(pdMS_TO_TICKS(5));
  bool pipeline_idle = camera_pipeline_idle();

  qr_decoder_cleanup();

  bool display_locked = bsp_display_lock(1000);
  if (!display_locked)
    ESP_LOGW(TAG, "Failed to lock display for UI cleanup");

  camera_img = NULL;
  cleanup_progress_indicators();
  cleanup_ur_progress_bar();
  if (qr_scanner_screen) {
    lv_obj_del(qr_scanner_screen);
    qr_scanner_screen = NULL;
  }

  if (display_locked)
    bsp_display_unlock();

  if (pipeline_idle) {
    free_frame_buffers();
    if (cam_ppa_client && ppa_unregister_client(cam_ppa_client) == ESP_OK)
      cam_ppa_client = NULL;
  } else {
    // The driver refuses to unregister a client with a transaction outstanding
    // too. Both stay for the next scan, which takes them over once idle.
    ESP_LOGE(TAG, "PPA still owns camera frame buffers; keeping them");
  }

  if (camera_event_group) {
    vEventGroupDelete(camera_event_group);
    camera_event_group = NULL;
  }

  return_callback = NULL;
  destruction_in_progress = false;
  closing = false;
}

char *qr_scanner_get_completed_content(void) {
  return qr_scanner_get_completed_content_with_len(NULL);
}

char *qr_scanner_get_completed_content_with_len(size_t *content_len) {
  if (qr_parser && qr_parser_is_complete(qr_parser)) {
    size_t result_len;
    char *complete_result = qr_parser_result(qr_parser, &result_len);
    if (content_len) {
      *content_len = result_len;
    }
    return complete_result; // Caller must free this
  }
  if (content_len) {
    *content_len = 0;
  }
  return NULL;
}

bool qr_scanner_is_ready(void) { return is_fully_initialized && !closing; }

bool qr_scanner_has_completed_result(void) {
  return qr_parser && qr_parser_is_complete(qr_parser);
}

int qr_scanner_get_format(void) {
  if (qr_parser) {
    return qr_parser_get_format(qr_parser);
  }
  return -1;
}

char qr_scanner_get_bbqr_file_type(void) {
  return qr_parser_get_bbqr_file_type(qr_parser);
}

bool qr_scanner_get_ur_result(const char **ur_type_out,
                              const uint8_t **cbor_data_out,
                              size_t *cbor_len_out) {
  if (qr_parser) {
    return qr_parser_get_ur_result(qr_parser, ur_type_out, cbor_data_out,
                                   cbor_len_out);
  }
  return false;
}
