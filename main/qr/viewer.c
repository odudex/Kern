#include "viewer.h"
#include "../components/bbqr/src/bbqr.h"
#include "../components/cUR/src/types/psbt.h"
#include "../components/cUR/src/ur_encoder.h"
#include "../ui/theme.h"
#include "encoder.h"
#include "parser.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>

#define MAX_QR_CHARS_PER_FRAME 400
#define ANIMATION_INTERVAL_MS 250
#define PROGRESS_BAR_HEIGHT 20
#define PROGRESS_FRAME_PADD 2
#define PROGRESS_BLOC_PAD 1
#define MAX_QR_PARTS 100

#define UR_HEADER_OVERHEAD 30
#define UR_MAX_FRAGMENT_LEN ((MAX_QR_CHARS_PER_FRAME - UR_HEADER_OVERHEAD) / 2)

typedef struct {
  char *data;
  size_t len;
} QRViewerPart;

static lv_obj_t *qr_viewer_screen = NULL;
static lv_obj_t *qr_code_obj = NULL;
static lv_obj_t *progress_frame = NULL;
static lv_obj_t **progress_rectangles = NULL;
static int progress_rectangles_count = 0;

static void (*return_callback)(void) = NULL;
static char *qr_content_copy = NULL;
static lv_timer_t *message_timer = NULL;
static lv_timer_t *animation_timer = NULL;

static QRViewerPart *qr_parts = NULL;
static int qr_parts_count = 0;
static int current_part_index = 0;

static void back_button_cb(lv_event_t *e) {
  if (return_callback) {
    return_callback();
  }
}

static void hide_message_timer_cb(lv_timer_t *timer) {
  lv_obj_t *msgbox = (lv_obj_t *)lv_timer_get_user_data(timer);
  if (msgbox) {
    lv_obj_del(msgbox);
  }
  message_timer = NULL;
}

static void create_progress_indicators(int total_parts) {
  if (total_parts <= 1 || total_parts > MAX_QR_PARTS || !qr_viewer_screen) {
    return;
  }

  int progress_frame_width = lv_obj_get_width(qr_viewer_screen) * 80 / 100;
  int rect_width = progress_frame_width / total_parts;
  rect_width -= PROGRESS_BLOC_PAD;
  progress_frame_width = total_parts * rect_width + 1;
  progress_frame_width += 2 * PROGRESS_FRAME_PADD + 2;

  progress_frame = lv_obj_create(qr_viewer_screen);
  lv_obj_set_size(progress_frame, progress_frame_width, PROGRESS_BAR_HEIGHT);
  lv_obj_align(progress_frame, LV_ALIGN_BOTTOM_MID, 0, 0);
  theme_apply_frame(progress_frame);
  lv_obj_set_style_pad_all(progress_frame, 2, 0);

  progress_rectangles = malloc(total_parts * sizeof(lv_obj_t *));
  if (!progress_rectangles) {
    lv_obj_del(progress_frame);
    progress_frame = NULL;
    return;
  }
  progress_rectangles_count = total_parts;

  lv_obj_update_layout(progress_frame);

  for (int i = 0; i < total_parts; i++) {
    progress_rectangles[i] = lv_obj_create(progress_frame);
    lv_obj_set_size(progress_rectangles[i], rect_width - PROGRESS_BLOC_PAD, 12);
    lv_obj_set_pos(progress_rectangles[i], i * rect_width, 0);
    theme_apply_solid_rectangle(progress_rectangles[i]);
  }
}

static void update_progress_indicator(int part_index) {
  if (!progress_rectangles || part_index < 0 ||
      part_index >= progress_rectangles_count) {
    return;
  }

  for (int i = 0; i < progress_rectangles_count; i++) {
    lv_color_t color = (i == part_index) ? highlight_color() : main_color();
    lv_obj_set_style_bg_color(progress_rectangles[i], color, 0);
  }
}

static void cleanup_progress_indicators(void) {
  if (progress_rectangles) {
    free(progress_rectangles);
    progress_rectangles = NULL;
  }
  progress_rectangles_count = 0;
  progress_frame = NULL;
}

static void split_content_into_parts(const char *content) {
  size_t content_len = strlen(content);
  size_t max_chars = MAX_QR_CHARS_PER_FRAME;

  if (content_len <= max_chars) {
    qr_parts_count = 1;
    qr_parts = malloc(sizeof(QRViewerPart));
    if (!qr_parts)
      return;

    qr_parts[0].data = strdup(content);
    qr_parts[0].len = content_len;
    return;
  }

  qr_parts_count = (content_len + max_chars - 1) / max_chars;
  if (qr_parts_count > MAX_QR_PARTS) {
    qr_parts_count = MAX_QR_PARTS;
  }

  int prefix_len = (qr_parts_count > 9) ? 8 : 6;
  size_t chars_per_part = max_chars - prefix_len;
  qr_parts_count = (content_len + chars_per_part - 1) / chars_per_part;

  qr_parts = malloc(qr_parts_count * sizeof(QRViewerPart));
  if (!qr_parts) {
    qr_parts_count = 0;
    return;
  }

  for (int i = 0; i < qr_parts_count; i++) {
    size_t offset = i * chars_per_part;
    size_t remaining = content_len - offset;
    size_t chunk_size =
        (remaining > chars_per_part) ? chars_per_part : remaining;

    char header[16];
    snprintf(header, sizeof(header), "p%dof%d ", i + 1, qr_parts_count);
    size_t header_len = strlen(header);

    qr_parts[i].len = header_len + chunk_size;
    qr_parts[i].data = malloc(qr_parts[i].len + 1);
    if (!qr_parts[i].data) {
      for (int j = 0; j < i; j++) {
        free(qr_parts[j].data);
      }
      free(qr_parts);
      qr_parts = NULL;
      qr_parts_count = 0;
      return;
    }

    memcpy(qr_parts[i].data, header, header_len);
    memcpy(qr_parts[i].data + header_len, content + offset, chunk_size);
    qr_parts[i].data[qr_parts[i].len] = '\0';
  }
}

static void cleanup_qr_parts(void) {
  if (qr_parts) {
    for (int i = 0; i < qr_parts_count; i++) {
      if (qr_parts[i].data) {
        free(qr_parts[i].data);
      }
    }
    free(qr_parts);
    qr_parts = NULL;
  }
  qr_parts_count = 0;
  current_part_index = 0;
}

static void animation_timer_cb(lv_timer_t *timer) {
  if (!qr_code_obj || !qr_parts || qr_parts_count <= 1) {
    return;
  }
  current_part_index = (current_part_index + 1) % qr_parts_count;
  qr_update_optimal(qr_code_obj, qr_parts[current_part_index].data, NULL);
  update_progress_indicator(current_part_index);
}

static bool setup_qr_viewer_ui(lv_obj_t *parent, const char *title) {
  qr_viewer_screen = lv_obj_create(parent);
  lv_obj_set_size(qr_viewer_screen, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(qr_viewer_screen, lv_color_hex(0xFFFFFF), 0);
  lv_obj_set_style_bg_opa(qr_viewer_screen, LV_OPA_COVER, 0);
  lv_obj_set_style_pad_all(qr_viewer_screen, 10, 0);
  lv_obj_add_event_cb(qr_viewer_screen, back_button_cb, LV_EVENT_CLICKED, NULL);

  lv_obj_update_layout(qr_viewer_screen);
  int32_t w = lv_obj_get_content_width(qr_viewer_screen);
  int32_t h = lv_obj_get_content_height(qr_viewer_screen);
  if (qr_parts_count > 1) {
    h -= PROGRESS_BAR_HEIGHT + 20;
  }
  int32_t qr_size = (w < h) ? w : h;

  qr_code_obj = lv_qrcode_create(qr_viewer_screen);
  if (!qr_code_obj) {
    return false;
  }
  lv_qrcode_set_size(qr_code_obj, qr_size);
  qr_update_optimal(qr_code_obj, qr_parts[0].data, NULL);
  lv_obj_center(qr_code_obj);

  if (qr_parts_count > 1) {
    create_progress_indicators(qr_parts_count);
    update_progress_indicator(0);
    animation_timer =
        lv_timer_create(animation_timer_cb, ANIMATION_INTERVAL_MS, NULL);
  }

  if (title) {
    lv_obj_t *msgbox = lv_obj_create(qr_viewer_screen);
    lv_obj_set_size(msgbox, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
    lv_obj_set_style_bg_color(msgbox, lv_color_hex(0x000000), 0);
    lv_obj_set_style_bg_opa(msgbox, LV_OPA_80, 0);
    lv_obj_set_style_border_width(msgbox, 2, 0);
    lv_obj_set_style_border_color(msgbox, main_color(), 0);
    lv_obj_set_style_radius(msgbox, 10, 0);
    lv_obj_set_style_pad_all(msgbox, 20, 0);
    lv_obj_add_flag(msgbox, LV_OBJ_FLAG_FLOATING);
    lv_obj_center(msgbox);

    char message[128];
    snprintf(message, sizeof(message), "%s\nTap to return", title);
    lv_obj_t *msg_label = theme_create_label(msgbox, message, false);
    lv_obj_set_style_text_align(msg_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_color(msg_label, lv_color_hex(0xFFFFFF), 0);

    message_timer = lv_timer_create(hide_message_timer_cb, 2000, msgbox);
    if (message_timer) {
      lv_timer_set_repeat_count(message_timer, 1);
    }
  }
  return true;
}

void qr_viewer_page_create(lv_obj_t *parent, const char *qr_content,
                           const char *title, void (*return_cb)(void)) {
  if (!parent || !qr_content) {
    return;
  }

  return_callback = return_cb;
  message_timer = NULL;
  animation_timer = NULL;

  qr_content_copy = strdup(qr_content);
  if (!qr_content_copy) {
    return;
  }

  split_content_into_parts(qr_content_copy);
  if (!qr_parts || qr_parts_count == 0) {
    free(qr_content_copy);
    qr_content_copy = NULL;
    return;
  }

  setup_qr_viewer_ui(parent, title);
}

void qr_viewer_page_show(void) {
  if (qr_viewer_screen) {
    lv_obj_clear_flag(qr_viewer_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void qr_viewer_page_hide(void) {
  if (qr_viewer_screen) {
    lv_obj_add_flag(qr_viewer_screen, LV_OBJ_FLAG_HIDDEN);
  }
}

void qr_viewer_page_destroy(void) {
  if (animation_timer) {
    lv_timer_del(animation_timer);
    animation_timer = NULL;
  }

  if (message_timer) {
    lv_timer_del(message_timer);
    message_timer = NULL;
  }

  cleanup_qr_parts();
  cleanup_progress_indicators();

  if (qr_content_copy) {
    free(qr_content_copy);
    qr_content_copy = NULL;
  }

  if (qr_viewer_screen) {
    lv_obj_del(qr_viewer_screen);
    qr_viewer_screen = NULL;
  }

  qr_code_obj = NULL;
  return_callback = NULL;
}

bool qr_viewer_page_create_with_format(lv_obj_t *parent, int qr_format,
                                       const char *content, const char *title,
                                       void (*return_cb)(void)) {
  if (!parent || !content) {
    return false;
  }

  if (qr_format != FORMAT_UR && qr_format != FORMAT_BBQR) {
    qr_viewer_page_create(parent, content, title, return_cb);
    return true;
  }

  // Decode base64 content to binary PSBT
  size_t max_decoded_len = (strlen(content) * 3) / 4 + 1;
  uint8_t *psbt_bytes = (uint8_t *)malloc(max_decoded_len);
  if (!psbt_bytes) {
    return false;
  }

  size_t psbt_len = 0;
  int ret =
      wally_base64_to_bytes(content, 0, psbt_bytes, max_decoded_len, &psbt_len);
  if (ret != WALLY_OK) {
    free(psbt_bytes);
    return false;
  }

  if (qr_format == FORMAT_BBQR) {
    // Encode as BBQr
    BBQrParts *bbqr_parts = bbqr_encode(psbt_bytes, psbt_len, BBQR_TYPE_PSBT,
                                        MAX_QR_CHARS_PER_FRAME);
    free(psbt_bytes);

    if (!bbqr_parts) {
      return false;
    }

    return_callback = return_cb;
    message_timer = NULL;
    animation_timer = NULL;

    qr_parts_count = bbqr_parts->count;
    qr_parts = malloc(qr_parts_count * sizeof(QRViewerPart));
    if (!qr_parts) {
      bbqr_parts_free(bbqr_parts);
      return false;
    }

    for (int i = 0; i < qr_parts_count; i++) {
      qr_parts[i].len = strlen(bbqr_parts->parts[i]);
      qr_parts[i].data = strdup(bbqr_parts->parts[i]);
      if (!qr_parts[i].data) {
        for (int j = 0; j < i; j++) {
          free(qr_parts[j].data);
        }
        free(qr_parts);
        qr_parts = NULL;
        qr_parts_count = 0;
        bbqr_parts_free(bbqr_parts);
        return false;
      }
    }
    bbqr_parts_free(bbqr_parts);

    if (!setup_qr_viewer_ui(parent, title)) {
      cleanup_qr_parts();
      return false;
    }
    return true;
  }

  // FORMAT_UR path
  psbt_data_t *psbt_data = psbt_new(psbt_bytes, psbt_len);
  free(psbt_bytes);
  if (!psbt_data) {
    return false;
  }

  size_t cbor_len = 0;
  uint8_t *cbor_data = psbt_to_cbor(psbt_data, &cbor_len);
  psbt_free(psbt_data);
  if (!cbor_data) {
    return false;
  }

  size_t max_fragment_len = UR_MAX_FRAGMENT_LEN < 10 ? 10 : UR_MAX_FRAGMENT_LEN;
  ur_encoder_t *encoder = ur_encoder_new("crypto-psbt", cbor_data, cbor_len,
                                         max_fragment_len, 0, 10);
  free(cbor_data);
  if (!encoder) {
    return false;
  }

  bool is_single = ur_encoder_is_single_part(encoder);
  size_t seq_len = ur_encoder_seq_len(encoder);
  char **ur_parts_strings = NULL;
  size_t parts_count = is_single ? 1 : (seq_len * 2 > 100 ? 100 : seq_len * 2);

  ur_parts_strings = malloc(parts_count * sizeof(char *));
  if (!ur_parts_strings) {
    ur_encoder_free(encoder);
    return false;
  }

  for (size_t i = 0; i < parts_count; i++) {
    if (!ur_encoder_next_part(encoder, &ur_parts_strings[i])) {
      for (size_t j = 0; j < i; j++) {
        free(ur_parts_strings[j]);
      }
      free(ur_parts_strings);
      ur_encoder_free(encoder);
      return false;
    }
  }
  ur_encoder_free(encoder);

  return_callback = return_cb;
  message_timer = NULL;
  animation_timer = NULL;

  qr_parts_count = parts_count;
  qr_parts = malloc(qr_parts_count * sizeof(QRViewerPart));
  if (!qr_parts) {
    for (size_t i = 0; i < parts_count; i++) {
      free(ur_parts_strings[i]);
    }
    free(ur_parts_strings);
    return false;
  }

  for (int i = 0; i < qr_parts_count; i++) {
    qr_parts[i].len = strlen(ur_parts_strings[i]);
    qr_parts[i].data = ur_parts_strings[i];
  }
  free(ur_parts_strings);

  if (!setup_qr_viewer_ui(parent, title)) {
    cleanup_qr_parts();
    return false;
  }
  return true;
}
