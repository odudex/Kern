// Mnemonic QR Code Backup Page

#include "mnemonic_qr.h"
#include "../../../core/base43.h"
#include "../../../core/key.h"
#include "../../../qr/encoder.h"
#include "../../../ui/dialog.h"
#include "../../../ui/input_helpers.h"
#include "../../../ui/theme_widgets.h"
#include "../../shared/kef_encrypt_page.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>

#include "../../../utils/secure_mem.h"

#define GRID_INTERVAL_DEFAULT 5
#define GRID_INTERVAL_21 7
#define SHADE_OPACITY LV_OPA_70
#define PORTRAIT_CONTROL_WIDTH_PCT 70

static int get_grid_interval(int modules) {
  return (modules == 21) ? GRID_INTERVAL_21 : GRID_INTERVAL_DEFAULT;
}

// Region columns, which equals the number of rows: the grid is always square.
// False when there is no encoded QR to divide.
static bool get_grid_divisions(int modules, int *divisions) {
  if (modules <= 0)
    return false;

  int interval = get_grid_interval(modules);
  *divisions = (modules + interval - 1) / interval;
  return true;
}

typedef enum {
  QR_TYPE_PLAINTEXT = 0,
  QR_TYPE_SEEDQR = 1,
  QR_TYPE_COMPACT_SEEDQR = 2,
  QR_TYPE_ENCRYPTED = 3
} qr_type_t;

typedef enum {
  VIEW_STANDARD = 0,
  VIEW_REGIONS = 1,
  VIEW_ZOOMED = 2
} view_mode_t;

static lv_obj_t *mnemonic_qr_screen = NULL;
static lv_obj_t *back_button = NULL;
static lv_obj_t *qr_type_dropdown = NULL;
static lv_obj_t *view_dropdown = NULL;
static lv_obj_t *qr_code = NULL;
static lv_obj_t *qr_container = NULL;
static lv_obj_t *grid_overlay = NULL;
static lv_obj_t *content_area = NULL;
static lv_obj_t *shade_overlay = NULL;
static lv_obj_t **col_labels = NULL;
static lv_obj_t **row_labels = NULL;
static void (*return_callback)(void) = NULL;
static char *mnemonic_data = NULL;
static char *seedqr_data = NULL;
static unsigned char *compact_seedqr_data = NULL;
static size_t compact_seedqr_len = 0;
static qr_type_t current_qr_type = QR_TYPE_PLAINTEXT;
static view_mode_t view_mode = VIEW_STANDARD;
static bool shade_mode_active = false;
static int32_t qr_widget_size = 0;
static int32_t qr_box_size = 0;
static int32_t qr_pad_grid = 0;
static int32_t qr_pad_plain = 0;
static int32_t qr_pad_zoom = 0;
static int shade_region_index = 0; /* doubles as the zoomed-region cursor */
static int grid_divisions = 0;
static qr_encode_result_t last_qr_result = {0, 0};

/* Zoomed-view state: QR encoded once into zoom_qr_buf, regions drawn from it */
static uint8_t *zoom_qr_buf = NULL;
static int zoom_modules = 0;
static qr_type_t zoom_buf_type = (qr_type_t)-1;
static lv_obj_t *zoom_col_strip = NULL;
static lv_obj_t *zoom_row_strip = NULL;
static lv_obj_t *zoom_grid_clip = NULL;
static lv_obj_t *zoom_grid_lines = NULL;
/* Where the sliding sheet of gridlines sits when the region is centred */
static int32_t zoom_grid_origin = 0;
/* Grid viewport size once a drag opens it out to the whole cell */
static int32_t zoom_grid_open = 0;
/* Pixels the drawn region is currently slid by, 0 when it sits on centre */
static int32_t zoom_slide_x = 0;
static int32_t zoom_slide_y = 0;

/* Encrypted QR state */
static char *encrypted_qr_data = NULL;
static qr_type_t previous_qr_type = QR_TYPE_PLAINTEXT;

/* Forward declarations */
static void update_qr_code(void);
static void render_zoom(void);
static void draw_zoom_region(int32_t ofs_x, int32_t ofs_y);
static int32_t clamp_zoom_slide(int32_t ofs, bool horizontal);
static int ensure_zoom_encoded(void);
static void destroy_zoom_overlays(void);
static void slide_zoom_overlays(int32_t ofs_x, int32_t ofs_y);

static void back_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

static void destroy_grid_overlay(void) {
  if (grid_overlay) {
    lv_obj_del(grid_overlay);
    grid_overlay = NULL;
  }
  free(col_labels);
  col_labels = NULL;
  free(row_labels);
  row_labels = NULL;
  grid_divisions = 0;
}

static void update_grid_label_highlight(int highlight_row, int highlight_col) {
  if (!col_labels || !row_labels || grid_divisions == 0)
    return;

  lv_color_t normal_color = highlight_color();
  lv_color_t active_color = lv_color_hex(0xFFFFFF);

  for (int i = 0; i < grid_divisions; i++) {
    if (col_labels[i])
      lv_obj_set_style_text_color(
          col_labels[i], (i == highlight_col) ? active_color : normal_color, 0);
    if (row_labels[i])
      lv_obj_set_style_text_color(
          row_labels[i], (i == highlight_row) ? active_color : normal_color, 0);
  }
}

static void destroy_shade_overlay(void) {
  if (shade_overlay) {
    lv_obj_del(shade_overlay);
    shade_overlay = NULL;
  }
}

static void reset_shade_mode(void) {
  update_grid_label_highlight(-1, -1);
  destroy_shade_overlay();
  shade_mode_active = false;
  shade_region_index = 0;
}

static void add_shade_rect(int32_t x, int32_t y, int32_t w, int32_t h) {
  lv_obj_t *rect = lv_obj_create(shade_overlay);
  lv_obj_remove_style_all(rect);
  lv_obj_clear_flag(rect, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_set_pos(rect, x, y);
  lv_obj_set_size(rect, w, h);
  lv_obj_set_style_bg_color(rect, lv_color_hex(0x000000), 0);
  lv_obj_set_style_bg_opa(rect, SHADE_OPACITY, 0);
}

static void create_shade_overlay(void) {
  destroy_shade_overlay();

  int modules = last_qr_result.modules;
  int32_t scale = last_qr_result.scale;
  int divisions;
  if (scale == 0 || !get_grid_divisions(modules, &divisions))
    return;

  int row = shade_region_index / divisions;
  int col = shade_region_index % divisions;

  int32_t content_size = modules * scale;
  int32_t margin = (qr_widget_size - content_size) / 2;
  int32_t cell_px = scale * get_grid_interval(modules);

  lv_obj_update_layout(qr_code);
  lv_area_t qr_coords, container_coords, content_coords;
  lv_obj_get_coords(qr_code, &qr_coords);
  lv_obj_get_coords(qr_container, &container_coords);
  lv_obj_get_coords(content_area, &content_coords);

  int32_t qr_x = qr_coords.x1 - content_coords.x1 + margin;
  int32_t qr_y = qr_coords.y1 - content_coords.y1 + margin;
  int32_t cont_x = container_coords.x1 - content_coords.x1;
  int32_t cont_y = container_coords.y1 - content_coords.y1;
  int32_t cont_size = lv_obj_get_width(qr_container);

  int32_t win_x = qr_x + col * cell_px;
  int32_t win_y = qr_y + row * cell_px;
  int32_t win_w = cell_px;
  int32_t win_h = cell_px;

  if (win_x + win_w > qr_x + content_size)
    win_w = qr_x + content_size - win_x;
  if (win_y + win_h > qr_y + content_size)
    win_h = qr_y + content_size - win_y;

  shade_overlay = lv_obj_create(content_area);
  lv_obj_remove_style_all(shade_overlay);
  lv_obj_set_size(shade_overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_clear_flag(shade_overlay,
                    LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_flag(shade_overlay, LV_OBJ_FLAG_IGNORE_LAYOUT);

  if (grid_overlay)
    lv_obj_move_foreground(grid_overlay);

  if (win_y > cont_y)
    add_shade_rect(cont_x, cont_y, cont_size, win_y - cont_y);

  int32_t bottom_y = win_y + win_h;
  if (bottom_y < cont_y + cont_size)
    add_shade_rect(cont_x, bottom_y, cont_size, cont_y + cont_size - bottom_y);

  if (win_x > cont_x)
    add_shade_rect(cont_x, win_y, win_x - cont_x, win_h);

  int32_t right_x = win_x + win_w;
  if (right_x < cont_x + cont_size)
    add_shade_rect(right_x, win_y, cont_x + cont_size - right_x, win_h);

  shade_mode_active = true;
  update_grid_label_highlight(row, col);
}

/* Move the region cursor one step per axis. Each axis moves on its own, so the
 * other one never follows: a step past the last column stays on its row. */
static void step_region(int drow, int dcol) {
  /* Zoomed mode draws from its own encode, the other views from the widget's
   * last one. */
  int modules = (view_mode == VIEW_ZOOMED) ? ensure_zoom_encoded()
                                           : last_qr_result.modules;
  int divisions;
  if (!get_grid_divisions(modules, &divisions))
    return;

  /* The cursor outlives a QR type change, which can shrink the grid. */
  if (shade_region_index < 0 || shade_region_index >= divisions * divisions)
    shade_region_index = 0;

  int row = shade_region_index / divisions;
  int col = shade_region_index % divisions;
  if (view_mode == VIEW_ZOOMED) {
    /* The drag brings the neighbour in under the finger, and past the last row
     * or column there is none to bring, so the zoomed view stops at the edge
     * instead of wrapping to the far side. */
    row = LV_CLAMP(0, row + drow, divisions - 1);
    col = LV_CLAMP(0, col + dcol, divisions - 1);
  } else {
    row = (row + drow + divisions) % divisions;
    col = (col + dcol + divisions) % divisions;
  }
  shade_region_index = row * divisions + col;
}

static void qr_area_tap_cb(lv_event_t *e) {
  (void)e;

  if (view_mode == VIEW_REGIONS) {
    int divisions;
    if (!get_grid_divisions(last_qr_result.modules, &divisions))
      return;
    int total_regions = divisions * divisions;

    if (!shade_mode_active) {
      shade_region_index = 0;
      create_shade_overlay();
    } else {
      shade_region_index++;
      if (shade_region_index >= total_regions)
        reset_shade_mode();
      else
        create_shade_overlay();
    }
  } else if (view_mode == VIEW_ZOOMED) {
    shade_region_index++; /* render_zoom() wraps past the last region to 0 */
    render_zoom();
  }
}

/* Dragging moves the grid under the finger: left brings in the next column, up
 * the next row. The zoomed view follows the finger the whole way, the others
 * step once the touch ends. */
static void qr_area_drag_cb(int32_t dx, int32_t dy, bool released) {
  if (!released) {
    if (view_mode != VIEW_ZOOMED)
      return;

    bool horizontal = LV_ABS(dx) >= LV_ABS(dy);
    int32_t slide = clamp_zoom_slide(horizontal ? dx : dy, horizontal);
    int32_t slide_x = horizontal ? slide : 0;
    int32_t slide_y = horizontal ? 0 : slide;
    /* A held finger keeps reporting: only a moved one is worth redrawing. */
    if (slide_x == zoom_slide_x && slide_y == zoom_slide_y)
      return;
    /* Open the viewport to the whole cell so a neighbour can slide in: an edge
     * region rests on fewer modules than a cell holds. */
    if (zoom_slide_x == 0 && zoom_slide_y == 0 && zoom_grid_clip)
      lv_obj_set_size(zoom_grid_clip, zoom_grid_open, zoom_grid_open);
    zoom_slide_x = slide_x;
    zoom_slide_y = slide_y;

    slide_zoom_overlays(slide_x, slide_y);
    draw_zoom_region(slide_x, slide_y);
    return;
  }

  int drow = 0, dcol = 0;
  lv_dir_t dir;
  if (ui_drag_is_swipe(dx, dy, &dir)) {
    switch (dir) {
    case LV_DIR_LEFT:
      dcol = 1;
      break;
    case LV_DIR_RIGHT:
      dcol = -1;
      break;
    case LV_DIR_TOP:
      drow = 1;
      break;
    default:
      drow = -1;
      break;
    }
  }

  if (view_mode == VIEW_ZOOMED) {
    /* Both steps are no-ops for a drag that fell short, and the render lands
     * the region back on centre either way. */
    step_region(drow, dcol);
    render_zoom();
  } else if (view_mode == VIEW_REGIONS && (drow || dcol)) {
    /* First swipe opens the shade on region A1, like the first tap does. */
    if (shade_mode_active)
      step_region(drow, dcol);
    else
      shade_region_index = 0;
    create_shade_overlay();
  }
}

static void create_grid_overlay(void) {
  destroy_grid_overlay();

  int modules = last_qr_result.modules;
  int32_t scale = last_qr_result.scale;
  int divisions;
  if (scale == 0 || !get_grid_divisions(modules, &divisions))
    return;

  int32_t content_size = modules * scale;
  int32_t margin = (qr_widget_size - content_size) / 2;

  lv_obj_update_layout(qr_code);
  lv_area_t qr_coords, content_coords;
  lv_obj_get_coords(qr_code, &qr_coords);
  lv_obj_get_coords(content_area, &content_coords);

  int32_t qr_x = qr_coords.x1 - content_coords.x1 + margin;
  int32_t qr_y = qr_coords.y1 - content_coords.y1 + margin;

  grid_overlay = lv_obj_create(content_area);
  lv_obj_remove_style_all(grid_overlay);
  lv_obj_set_size(grid_overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_clear_flag(grid_overlay,
                    LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_flag(grid_overlay, LV_OBJ_FLAG_IGNORE_LAYOUT);

  lv_color_t color = highlight_color();
  int grid_interval = get_grid_interval(modules);
  int32_t cell_px = scale * grid_interval;
  int32_t label_pad = LV_MAX(theme_small_padding(), 2);

  grid_divisions = divisions;
  col_labels = calloc(divisions, sizeof(lv_obj_t *));
  row_labels = calloc(divisions, sizeof(lv_obj_t *));

  for (int c = 0; c <= divisions; c++) {
    int32_t mod = (c * grid_interval > modules) ? modules : c * grid_interval;
    int32_t x = qr_x + mod * scale;

    lv_obj_t *line = lv_obj_create(grid_overlay);
    lv_obj_remove_style_all(line);
    lv_obj_set_size(line, 2, content_size);
    lv_obj_set_pos(line, x - 1, qr_y);
    lv_obj_set_style_bg_color(line, color, 0);
    lv_obj_set_style_bg_opa(line, LV_OPA_COVER, 0);

    if (c < divisions) {
      char txt[12];
      snprintf(txt, sizeof(txt), "%d", c + 1);
      lv_obj_t *lbl = lv_label_create(grid_overlay);
      lv_label_set_text(lbl, txt);
      lv_obj_set_style_text_color(lbl, color, 0);
      lv_obj_set_style_text_font(lbl, theme_font_small(), 0);
      lv_obj_update_layout(lbl);
      lv_obj_set_pos(lbl, x + (cell_px - lv_obj_get_width(lbl)) / 2,
                     qr_y - label_pad - lv_obj_get_height(lbl));
      if (col_labels)
        col_labels[c] = lbl;
    }
  }

  for (int r = 0; r <= divisions; r++) {
    int32_t mod = (r * grid_interval > modules) ? modules : r * grid_interval;
    int32_t y = qr_y + mod * scale;

    lv_obj_t *line = lv_obj_create(grid_overlay);
    lv_obj_remove_style_all(line);
    lv_obj_set_size(line, content_size, 2);
    lv_obj_set_pos(line, qr_x, y - 1);
    lv_obj_set_style_bg_color(line, color, 0);
    lv_obj_set_style_bg_opa(line, LV_OPA_COVER, 0);

    if (r < divisions) {
      char txt[2] = {(char)('A' + r), '\0'};
      lv_obj_t *lbl = lv_label_create(grid_overlay);
      lv_label_set_text(lbl, txt);
      lv_obj_set_style_text_color(lbl, color, 0);
      lv_obj_set_style_text_font(lbl, theme_font_small(), 0);
      lv_obj_update_layout(lbl);
      lv_obj_set_pos(lbl, qr_x - label_pad - lv_obj_get_width(lbl),
                     y + (cell_px - lv_obj_get_height(lbl)) / 2);
      if (row_labels)
        row_labels[r] = lbl;
    }
  }
}

static void apply_qr_sizing(void) {
  if (!qr_container || !qr_code)
    return;
  int32_t pad = (view_mode == VIEW_REGIONS)  ? qr_pad_grid
                : (view_mode == VIEW_ZOOMED) ? qr_pad_zoom
                                             : qr_pad_plain;
  int32_t size = qr_box_size - 2 * pad;
  if (size <= 0 || size == qr_widget_size)
    return;
  lv_obj_set_style_pad_all(qr_container, pad, 0);
  qr_resize(qr_code, size);
  qr_widget_size = size;
}

static void view_mode_cb(lv_event_t *e) {
  view_mode_t new_mode =
      (view_mode_t)lv_dropdown_get_selected(lv_event_get_target(e));
  if (new_mode == view_mode)
    return;

  reset_shade_mode();
  destroy_grid_overlay();
  destroy_zoom_overlays();
  shade_region_index = 0; /* fresh region cursor for grid/zoom */

  view_mode = new_mode;
  apply_qr_sizing();
  update_qr_code();
}

/* ---------- Encrypted QR flow (via kef_encrypt_page) ---------- */

static void encrypt_return_cb(void) {
  kef_encrypt_page_destroy();
  current_qr_type = previous_qr_type;
  lv_dropdown_set_selected(qr_type_dropdown, (uint32_t)current_qr_type);
}

static void encrypt_success_cb(const char *id, const uint8_t *envelope,
                               size_t len) {
  (void)id;
  char *b43 = NULL;
  size_t b43_len = 0;
  if (!base43_encode(envelope, len, &b43, &b43_len)) {
    kef_encrypt_page_destroy();
    dialog_show_error_timeout("Encoding failed", NULL, 0);
    current_qr_type = previous_qr_type;
    lv_dropdown_set_selected(qr_type_dropdown, (uint32_t)current_qr_type);
    return;
  }

  kef_encrypt_page_destroy();
  SECURE_FREE_STRING(encrypted_qr_data);
  encrypted_qr_data = b43;

  current_qr_type = QR_TYPE_ENCRYPTED;
  lv_dropdown_set_selected(qr_type_dropdown, 3);
  /* Same type but fresh data (new GCM IV): force the zoom cache to re-encode.
   */
  zoom_buf_type = (qr_type_t)-1;
  shade_region_index = 0;
  update_qr_code();
}

static void start_encrypted_flow(void) {
  previous_qr_type = current_qr_type;

  if (!compact_seedqr_data || compact_seedqr_len == 0) {
    dialog_show_error_timeout("No data to encrypt", NULL, 0);
    return;
  }

  kef_encrypt_page_create(lv_screen_active(), encrypt_return_cb,
                          encrypt_success_cb, compact_seedqr_data,
                          compact_seedqr_len, NULL);
}

static void destroy_zoom_overlays(void) {
  if (zoom_grid_clip) {
    lv_obj_del(zoom_grid_clip);
    zoom_grid_clip = NULL;
    zoom_grid_lines = NULL;
  }
  if (zoom_col_strip) {
    lv_obj_del(zoom_col_strip);
    zoom_col_strip = NULL;
  }
  if (zoom_row_strip) {
    lv_obj_del(zoom_row_strip);
    zoom_row_strip = NULL;
  }
}

/* Encode the current QR into zoom_qr_buf, cached by type. Returns module count.
 */
static int ensure_zoom_encoded(void) {
  if (!zoom_qr_buf)
    return 0;
  if (zoom_modules > 0 && zoom_buf_type == current_qr_type)
    return zoom_modules;

  int modules = 0;
  if (current_qr_type == QR_TYPE_COMPACT_SEEDQR) {
    if (compact_seedqr_data && compact_seedqr_len > 0)
      modules = qr_encode_binary(compact_seedqr_data, compact_seedqr_len,
                                 zoom_qr_buf);
  } else if (current_qr_type == QR_TYPE_ENCRYPTED) {
    if (encrypted_qr_data)
      modules = qr_encode_optimal(encrypted_qr_data, zoom_qr_buf);
  } else {
    const char *data = (current_qr_type == QR_TYPE_PLAINTEXT) ? mnemonic_data
                       : (current_qr_type == QR_TYPE_SEEDQR)  ? seedqr_data
                                                              : NULL;
    if (data)
      modules = qr_encode_optimal(data, zoom_qr_buf);
  }

  zoom_modules = modules;
  zoom_buf_type = (modules > 0) ? current_qr_type : (qr_type_t)-1;
  return modules;
}

/* A strip holds one label per region: the current one and the neighbours,
 * parked a span away on each side. It clips whatever hangs outside the QR, so
 * sliding the labels brings the next one in as the current one leaves. */
static lv_obj_t *create_zoom_strip(int32_t x, int32_t y, int32_t w, int32_t h) {
  lv_obj_t *strip = lv_obj_create(content_area);
  lv_obj_remove_style_all(strip);
  lv_obj_set_pos(strip, x, y);
  lv_obj_set_size(strip, w, h);
  lv_obj_clear_flag(strip, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_flag(strip, LV_OBJ_FLAG_IGNORE_LAYOUT);
  return strip;
}

static lv_obj_t *add_zoom_strip_label(lv_obj_t *strip, const char *txt) {
  lv_obj_t *lbl = lv_label_create(strip);
  lv_label_set_text(lbl, txt);
  lv_obj_set_style_text_color(lbl, highlight_color(), 0);
  lv_obj_set_style_text_font(lbl, theme_font_medium(), 0);
  lv_obj_update_layout(lbl);
  return lbl;
}

static void add_zoom_gridline(lv_obj_t *parent, int32_t x, int32_t y, int32_t w,
                              int32_t h) {
  lv_obj_t *line = lv_obj_create(parent);
  lv_obj_remove_style_all(line);
  lv_obj_set_pos(line, x, y);
  lv_obj_set_size(line, w, h);
  lv_obj_set_style_bg_color(line, highlight_color(), 0);
  lv_obj_set_style_bg_opa(line, LV_OPA_COVER, 0);
}

/* Three regions of gridlines sit inside a clipped viewport that never moves.
 * At rest it ends with the current region's last module; dragging opens it out
 * to the whole cell, which is all the blit will draw into anyway. */
static void create_zoom_grid(int interval, int32_t scale, int32_t line_w,
                             int32_t margin, int32_t qr_x, int32_t qr_y,
                             int32_t span_w, int32_t span_h) {
  int32_t sheet = 3 * interval * scale;
  int32_t span = interval * scale;
  int32_t line_head = line_w / 2;
  /* The border lines straddle the cell's edges, so the viewport carries half a
   * line on the near side and the other half on the far one. */
  int32_t line_tail = (line_w + 1) / 2;

  zoom_grid_open = span + line_head + line_tail;
  zoom_grid_clip = create_zoom_strip(
      qr_x + margin - line_head, qr_y + margin - line_head,
      span_w + line_head + line_tail, span_h + line_head + line_tail);

  zoom_grid_lines = lv_obj_create(zoom_grid_clip);
  lv_obj_remove_style_all(zoom_grid_lines);
  lv_obj_set_size(zoom_grid_lines, sheet, sheet);
  lv_obj_clear_flag(zoom_grid_lines,
                    LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);

  /* Its middle region covers the drawn one. */
  zoom_grid_origin = line_head - span;
  lv_obj_set_pos(zoom_grid_lines, zoom_grid_origin, zoom_grid_origin);

  for (int i = 0; i <= 3 * interval; i++) {
    add_zoom_gridline(zoom_grid_lines, i * scale - line_head, 0, line_w, sheet);
    add_zoom_gridline(zoom_grid_lines, 0, i * scale - line_head, sheet, line_w);
  }
}

/* Each strip is sized from the labels it ends up holding, so it is built at the
 * QR's own extent first and moved into its margin once they are measured. */
static void create_zoom_labels(int row, int col, int divisions, int32_t qr_x,
                               int32_t qr_y, int32_t qr_w, int32_t qr_h,
                               int32_t span, int32_t label_pad) {
  zoom_col_strip = create_zoom_strip(qr_x, qr_y, qr_w, 0);
  int32_t strip_h = 0;
  for (int k = -1; k <= 1; k++) {
    if (col + k < 0 || col + k >= divisions)
      continue;
    char txt[12];
    snprintf(txt, sizeof(txt), "%d", col + k + 1);
    lv_obj_t *lbl = add_zoom_strip_label(zoom_col_strip, txt);
    lv_obj_set_pos(lbl, k * span + (qr_w - lv_obj_get_width(lbl)) / 2, 0);
    strip_h = LV_MAX(strip_h, lv_obj_get_height(lbl));
  }
  lv_obj_set_pos(zoom_col_strip, qr_x, qr_y - label_pad - strip_h);
  lv_obj_set_height(zoom_col_strip, strip_h);

  zoom_row_strip = create_zoom_strip(qr_x, qr_y, qr_w, qr_h);
  int32_t strip_w = 0;
  for (int k = -1; k <= 1; k++) {
    if (row + k < 0 || row + k >= divisions)
      continue;
    char txt[2] = {(char)('A' + row + k), '\0'};
    lv_obj_t *lbl = add_zoom_strip_label(zoom_row_strip, txt);
    lv_obj_set_y(lbl, k * span + (qr_h - lv_obj_get_height(lbl)) / 2);
    strip_w = LV_MAX(strip_w, lv_obj_get_width(lbl));
  }
  /* Right-aligned against the QR, as the numbers are centred on it. */
  uint32_t letters = lv_obj_get_child_count(zoom_row_strip);
  for (uint32_t i = 0; i < letters; i++) {
    lv_obj_t *lbl = lv_obj_get_child(zoom_row_strip, i);
    lv_obj_set_x(lbl, strip_w - lv_obj_get_width(lbl));
  }
  lv_obj_set_pos(zoom_row_strip, qr_x - label_pad - strip_w, qr_y);
  lv_obj_set_width(zoom_row_strip, strip_w);
}

/* Only the axis being dragged moves: sliding sideways leaves the row letter
 * where it is, and the other way round. The grid follows both. */
static void slide_zoom_overlays(int32_t ofs_x, int32_t ofs_y) {
  if (zoom_grid_lines)
    lv_obj_set_pos(zoom_grid_lines, zoom_grid_origin + ofs_x,
                   zoom_grid_origin + ofs_y);

  if (zoom_col_strip) {
    uint32_t n = lv_obj_get_child_count(zoom_col_strip);
    for (uint32_t i = 0; i < n; i++)
      lv_obj_set_style_translate_x(lv_obj_get_child(zoom_col_strip, i), ofs_x,
                                   0);
  }
  if (zoom_row_strip) {
    uint32_t n = lv_obj_get_child_count(zoom_row_strip);
    for (uint32_t i = 0; i < n; i++)
      lv_obj_set_style_translate_y(lv_obj_get_child(zoom_row_strip, i), ofs_y,
                                   0);
  }
}

/* Draw the region cursor's cell, slid by (ofs_x, ofs_y) px. The blit gets one
 * region of margin on every side, so a slide brings the neighbours in and the
 * rest is clipped. */
static void draw_zoom_region(int32_t ofs_x, int32_t ofs_y) {
  int modules = ensure_zoom_encoded();
  int divisions;
  if (!get_grid_divisions(modules, &divisions))
    return;

  int interval = get_grid_interval(modules);
  if (shade_region_index < 0 || shade_region_index >= divisions * divisions)
    shade_region_index = 0;

  int x0 = (shade_region_index % divisions) * interval;
  int y0 = (shade_region_index / divisions) * interval;
  /* From the canvas, not the widget: a resize reaches the canvas first, and
   * this runs before the layout that would catch the widget up. */
  int32_t scale = qr_module_scale(qr_code, interval);

  /* cell == interval keeps a constant module size; edge regions leave blanks.
   * The neighbours ride along for a slide to bring in and are clipped to the
   * cell until one does. */
  qr_draw_region(qr_code, zoom_qr_buf, x0 - interval, y0 - interval,
                 3 * interval, 3 * interval, interval, ofs_x - interval * scale,
                 ofs_y - interval * scale);
}

/* How far the region may slide towards its neighbour: one region at most, and
 * nowhere at all at the edge, where there is no neighbour to bring in. */
static int32_t clamp_zoom_slide(int32_t ofs, bool horizontal) {
  int modules = ensure_zoom_encoded();
  int divisions;
  if (!get_grid_divisions(modules, &divisions))
    return 0;

  int interval = get_grid_interval(modules);
  int32_t span = qr_module_scale(qr_code, interval) * interval;
  int pos = horizontal ? shade_region_index % divisions
                       : shade_region_index / divisions;

  /* Sliding the content towards negative brings in the region after it. */
  if (ofs < 0)
    return (pos + 1 < divisions) ? LV_MAX(ofs, -span) : 0;
  return (pos > 0) ? LV_MIN(ofs, span) : 0;
}

static void render_zoom(void) {
  int modules = ensure_zoom_encoded();
  int divisions;
  if (!get_grid_divisions(modules, &divisions))
    return;

  int interval = get_grid_interval(modules);
  int total = divisions * divisions;
  if (shade_region_index < 0 || shade_region_index >= total)
    shade_region_index = 0;

  int row = shade_region_index / divisions;
  int col = shade_region_index % divisions;
  int x0 = col * interval;
  int y0 = row * interval;
  int w = LV_MIN(interval, modules - x0);
  int h = LV_MIN(interval, modules - y0);

  zoom_slide_x = 0;
  zoom_slide_y = 0;
  draw_zoom_region(0, 0);

  destroy_zoom_overlays();
  lv_obj_update_layout(qr_code);
  lv_area_t qr_coords, content_coords;
  lv_obj_get_coords(qr_code, &qr_coords);
  lv_obj_get_coords(content_area, &content_coords);
  int32_t qr_x = qr_coords.x1 - content_coords.x1;
  int32_t qr_y = qr_coords.y1 - content_coords.y1;
  int32_t qr_w = lv_obj_get_width(qr_code);
  int32_t qr_h = lv_obj_get_height(qr_code);
  int32_t label_pad = LV_MAX(theme_small_padding(), 2);

  /* Inter-cell grid; same scale/centering as qr_draw_region so lines land on
   * the module boundaries. */
  int32_t scale = qr_module_scale(qr_code, interval);
  int32_t margin = (qr_w - interval * scale) / 2;
  int32_t span_w = w * scale;
  int32_t span_h = h * scale;
  /* Two pixels minimum: a hairline reads as an artefact next to the modules on
   * boards whose zoomed cells land under 80 px. */
  int32_t line_w = LV_MAX(2, scale / 40);
  create_zoom_grid(interval, scale, line_w, margin, qr_x, qr_y, span_w, span_h);
  create_zoom_labels(row, col, divisions, qr_x, qr_y, qr_w, qr_h,
                     interval * scale, label_pad);
}

static void update_qr_code(void) {
  if (!qr_code)
    return;

  if (view_mode == VIEW_ZOOMED) {
    reset_shade_mode();
    render_zoom();
    return;
  }

  destroy_zoom_overlays();
  if (current_qr_type == QR_TYPE_COMPACT_SEEDQR) {
    if (compact_seedqr_data && compact_seedqr_len > 0)
      qr_update_binary(qr_code, compact_seedqr_data, compact_seedqr_len,
                       &last_qr_result);
  } else if (current_qr_type == QR_TYPE_ENCRYPTED) {
    if (encrypted_qr_data)
      qr_update_optimal(qr_code, encrypted_qr_data, &last_qr_result);
  } else {
    const char *data = (current_qr_type == QR_TYPE_PLAINTEXT) ? mnemonic_data
                       : (current_qr_type == QR_TYPE_SEEDQR)  ? seedqr_data
                                                              : NULL;
    if (data)
      qr_update_optimal(qr_code, data, &last_qr_result);
  }

  reset_shade_mode();
  if (view_mode == VIEW_REGIONS)
    create_grid_overlay();
}

static void dropdown_cb(lv_event_t *e) {
  uint32_t sel = lv_dropdown_get_selected(lv_event_get_target(e));
  if (sel == 3) {
    /* Encrypted: always trigger fresh flow (new GCM IV each time) */
    start_encrypted_flow();
    return;
  }
  qr_type_t new_type = (sel == 0)   ? QR_TYPE_PLAINTEXT
                       : (sel == 1) ? QR_TYPE_SEEDQR
                                    : QR_TYPE_COMPACT_SEEDQR;
  if (new_type != current_qr_type) {
    current_qr_type = new_type;
    shade_region_index = 0; /* region cursor invalid for the new QR */
    update_qr_code();
  }
}

void mnemonic_qr_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  if (!parent || !key_is_loaded())
    return;

  return_callback = return_cb;

  if (!key_get_mnemonic(&mnemonic_data) || !mnemonic_data)
    return;

  seedqr_data = mnemonic_to_seedqr(mnemonic_data);
  compact_seedqr_data =
      mnemonic_to_compact_seedqr(mnemonic_data, &compact_seedqr_len);
  if (!seedqr_data || !compact_seedqr_data) {
    secure_memzero(mnemonic_data, strlen(mnemonic_data));
    wally_free_string(mnemonic_data);
    mnemonic_data = NULL;
    SECURE_FREE_STRING(seedqr_data);
    SECURE_FREE_BUFFER(compact_seedqr_data, compact_seedqr_len);
    compact_seedqr_len = 0;
    return;
  }

  current_qr_type = QR_TYPE_PLAINTEXT;
  view_mode = VIEW_STANDARD;
  shade_region_index = 0;
  zoom_qr_buf = malloc(QR_CODE_BUF_LEN);
  zoom_modules = 0;
  zoom_buf_type = (qr_type_t)-1;

  mnemonic_qr_screen = lv_obj_create(parent);
  lv_obj_set_size(mnemonic_qr_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(mnemonic_qr_screen);
  lv_obj_clear_flag(mnemonic_qr_screen, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(mnemonic_qr_screen, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(mnemonic_qr_screen, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(mnemonic_qr_screen, theme_default_padding(), 0);
  lv_obj_set_style_pad_gap(mnemonic_qr_screen, theme_default_padding(), 0);

  bool portrait = theme_screen_height() > theme_screen_width();
  int32_t top_pad = theme_small_padding();
  if (portrait && theme_safe_area_inset())
    top_pad += theme_safe_area_inset() + theme_corner_button_height() +
               theme_small_padding();
  lv_obj_set_style_pad_top(mnemonic_qr_screen, top_pad, 0);

  int32_t ctrl_h = theme_min_touch_size();
  int32_t ctrl_gap = theme_small_padding();
  int32_t ctrl_w_pct = portrait ? PORTRAIT_CONTROL_WIDTH_PCT : 40;

  lv_obj_t *top_bar = lv_obj_create(mnemonic_qr_screen);
  lv_obj_set_size(top_bar, LV_PCT(100),
                  portrait ? (ctrl_h * 2 + ctrl_gap) : ctrl_h);
  theme_apply_transparent_container(top_bar);
  lv_obj_set_flex_flow(top_bar,
                       portrait ? LV_FLEX_FLOW_COLUMN : LV_FLEX_FLOW_ROW);
  // Landscape lays the dropdowns in a row; right-align them so they clear the
  // back button overlaid at the top-left rather than centering under it.
  lv_obj_set_flex_align(top_bar,
                        portrait ? LV_FLEX_ALIGN_CENTER : LV_FLEX_ALIGN_END,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(top_bar, ctrl_gap, 0);
  lv_obj_clear_flag(top_bar, LV_OBJ_FLAG_SCROLLABLE);

  back_button = ui_create_back_button(parent, back_cb);

  qr_type_dropdown = theme_create_dropdown(
      top_bar, "Plaintext\nSeedQR\nCompact SeedQR\nEncrypted");
  lv_obj_set_size(qr_type_dropdown, LV_PCT(ctrl_w_pct), ctrl_h);
  lv_obj_add_event_cb(qr_type_dropdown, dropdown_cb, LV_EVENT_VALUE_CHANGED,
                      NULL);

  view_dropdown = theme_create_dropdown(top_bar, "Standard\nRegions\nZoomed");
  lv_obj_set_size(view_dropdown, LV_PCT(ctrl_w_pct), ctrl_h);
  lv_obj_add_event_cb(view_dropdown, view_mode_cb, LV_EVENT_VALUE_CHANGED,
                      NULL);

  content_area = lv_obj_create(mnemonic_qr_screen);
  lv_obj_set_size(content_area, LV_PCT(100), LV_PCT(100));
  theme_apply_transparent_container(content_area);
  lv_obj_set_flex_grow(content_area, 1);
  lv_obj_clear_flag(content_area, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(content_area, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content_area, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  lv_obj_update_layout(mnemonic_qr_screen);
  int32_t avail_w = lv_obj_get_content_width(content_area);
  int32_t avail_h = lv_obj_get_content_height(content_area);
  int32_t container_size = LV_MIN(avail_w, avail_h);
  int32_t legend = LV_MAX(24, lv_font_get_line_height(theme_font_small()) +
                                  2 * LV_MAX(ctrl_gap, 2));

  // Grid mode reserves `legend` padding for the row/column labels; with the
  // grid hidden only a scanner quiet zone is needed, so the QR grows to fill
  // the reclaimed space and is easier to scan.
  qr_box_size = container_size;
  qr_pad_grid = legend;
  qr_pad_plain = LV_MIN(legend, theme_default_padding());
  // Zoomed view labels the region with the larger medium font; reserve enough
  // top/left padding for it to sit above/left of the magnified region.
  qr_pad_zoom = LV_MAX(legend, lv_font_get_line_height(theme_font_medium()) +
                                   2 * LV_MAX(ctrl_gap, 2));

  qr_container =
      theme_create_qr_container(content_area, container_size, qr_pad_plain);

  lv_obj_update_layout(qr_container);
  qr_widget_size = lv_obj_get_content_width(qr_container);

  qr_code = qr_create_optimal(qr_container, qr_widget_size, NULL);

  ui_enable_tap_drag(qr_container, qr_area_tap_cb, qr_area_drag_cb);

  update_qr_code();
}

void mnemonic_qr_page_show(void) {
  if (mnemonic_qr_screen)
    lv_obj_clear_flag(mnemonic_qr_screen, LV_OBJ_FLAG_HIDDEN);
}

void mnemonic_qr_page_hide(void) {
  if (mnemonic_qr_screen)
    lv_obj_add_flag(mnemonic_qr_screen, LV_OBJ_FLAG_HIDDEN);
}

void mnemonic_qr_page_destroy(void) {
  kef_encrypt_page_destroy();

  reset_shade_mode();
  destroy_grid_overlay();
  destroy_zoom_overlays();

  if (zoom_qr_buf) {
    secure_memzero(zoom_qr_buf, QR_CODE_BUF_LEN);
    free(zoom_qr_buf);
    zoom_qr_buf = NULL;
  }

  if (mnemonic_data) {
    secure_memzero(mnemonic_data, strlen(mnemonic_data));
    wally_free_string(mnemonic_data);
    mnemonic_data = NULL;
  }

  SECURE_FREE_STRING(seedqr_data);
  SECURE_FREE_BUFFER(compact_seedqr_data, compact_seedqr_len);
  compact_seedqr_len = 0;
  SECURE_FREE_STRING(encrypted_qr_data);

  if (back_button) {
    lv_obj_del(back_button);
    back_button = NULL;
  }

  if (mnemonic_qr_screen) {
    lv_obj_del(mnemonic_qr_screen);
    mnemonic_qr_screen = NULL;
  }

  qr_type_dropdown = NULL;
  view_dropdown = NULL;
  zoom_col_strip = NULL;
  zoom_row_strip = NULL;
  zoom_grid_clip = NULL;
  zoom_grid_lines = NULL;
  qr_code = NULL;
  qr_container = NULL;
  content_area = NULL;
  return_callback = NULL;
  current_qr_type = QR_TYPE_PLAINTEXT;
  view_mode = VIEW_STANDARD;
  zoom_modules = 0;
  zoom_buf_type = (qr_type_t)-1;
  zoom_slide_x = 0;
  zoom_slide_y = 0;
  zoom_grid_open = 0;
  shade_region_index = 0;
  qr_widget_size = 0;
  qr_box_size = 0;
  qr_pad_grid = 0;
  qr_pad_plain = 0;
  qr_pad_zoom = 0;
  last_qr_result = (qr_encode_result_t){0, 0};
}
