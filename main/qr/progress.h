#ifndef QR_PROGRESS_H
#define QR_PROGRESS_H

#include "parser.h"

// Copied by value between the decoder and UI. Each snapshot contains all
// received frames, so replacing a queued snapshot cannot lose progress.
typedef struct {
  int total;
  int received;
  int latest;
  uint8_t bits[(QR_PARSER_MAX_MULTIPART_PARTS + 7) / 8];
} qr_part_progress_t;

static inline bool qr_part_progress_has(const qr_part_progress_t *progress,
                                        int index) {
  return index >= 0 && index < progress->total &&
         index < QR_PARSER_MAX_MULTIPART_PARTS &&
         (progress->bits[index / 8] & (1U << (index % 8))) != 0;
}

static inline void qr_part_progress_record(qr_part_progress_t *progress,
                                           int index) {
  if (index < 0 || index >= progress->total ||
      index >= QR_PARSER_MAX_MULTIPART_PARTS)
    return;
  if (!qr_part_progress_has(progress, index)) {
    progress->bits[index / 8] |= 1U << (index % 8);
    progress->received++;
  }
  progress->latest = index;
}

// One cell per frame, left-to-right then top-to-bottom. Keep at least five
// pixels of cell width and a one-pixel gap, wrapping instead of hiding cells.
#define QR_PROGRESS_CELL_MIN_WIDTH 5
#define QR_PROGRESS_CELL_GAP 1

// LVGL queues a draw task per rect before clipping, so grid draw callbacks
// skip cells outside the invalidated area themselves.
static inline bool qr_progress_spans_overlap(int a1, int a2, int b1, int b2) {
  return a1 <= b2 && b1 <= a2;
}

typedef struct {
  int columns;
  int rows;
  int cell_width;
  int cell_height;
  int width;
  int height;
} qr_progress_grid_t;

static inline qr_progress_grid_t qr_progress_grid_layout(int total, int width) {
  qr_progress_grid_t grid = {0};
  // BBQr exports can use the full two-digit base36 range (1295 parts).
  if (total <= 0 || total > 1295 || width < QR_PROGRESS_CELL_MIN_WIDTH)
    return grid;
  grid.columns = (width + QR_PROGRESS_CELL_GAP) /
                 (QR_PROGRESS_CELL_MIN_WIDTH + QR_PROGRESS_CELL_GAP);
  if (grid.columns > total)
    grid.columns = total;
  grid.rows = (total + grid.columns - 1) / grid.columns;
  grid.cell_width =
      (width + QR_PROGRESS_CELL_GAP) / grid.columns - QR_PROGRESS_CELL_GAP;
  grid.cell_height = grid.rows == 1 ? 12 : 4;
  grid.width = grid.columns * (grid.cell_width + QR_PROGRESS_CELL_GAP) -
               QR_PROGRESS_CELL_GAP;
  grid.height = grid.rows * (grid.cell_height + QR_PROGRESS_CELL_GAP) -
                QR_PROGRESS_CELL_GAP;
  return grid;
}

// RGB565 pixels of a grid the UI blits as a single image. The scanner's grid
// sits over the camera preview, so it is redrawn on every camera frame: cells
// are painted here once, when they change, instead of on each redraw.
typedef struct {
  uint16_t *pixels;
  int stride; // pixels per row
  uint16_t gap;
  uint16_t missing;
  uint16_t missing_border;
  uint16_t received;
  uint16_t latest;
} qr_progress_canvas_t;

static inline void qr_progress_fill(const qr_progress_canvas_t *canvas, int x,
                                    int y, int width, int height,
                                    uint16_t color) {
  for (int row = y; row < y + height; row++) {
    uint16_t *pixels = canvas->pixels + (size_t)row * canvas->stride + x;
    for (int i = 0; i < width; i++)
      pixels[i] = color;
  }
}

static inline void qr_progress_paint_cell(const qr_progress_canvas_t *canvas,
                                          const qr_progress_grid_t *grid,
                                          const qr_part_progress_t *progress,
                                          int index) {
  if (index < 0 || index >= progress->total)
    return;
  int x = (index % grid->columns) * (grid->cell_width + QR_PROGRESS_CELL_GAP);
  int y = (index / grid->columns) * (grid->cell_height + QR_PROGRESS_CELL_GAP);
  if (qr_part_progress_has(progress, index)) {
    qr_progress_fill(canvas, x, y, grid->cell_width, grid->cell_height,
                     index == progress->latest ? canvas->latest
                                               : canvas->received);
    return;
  }
  qr_progress_fill(canvas, x, y, grid->cell_width, grid->cell_height,
                   canvas->missing_border);
  qr_progress_fill(canvas, x + 1, y + 1, grid->cell_width - 2,
                   grid->cell_height - 2, canvas->missing);
}

// Paints the cells whose state differs between two snapshots, or the whole
// grid when there is no previous one. Returns the number of cells painted.
static inline int qr_progress_paint(const qr_progress_canvas_t *canvas,
                                    const qr_progress_grid_t *grid,
                                    const qr_part_progress_t *previous,
                                    const qr_part_progress_t *current) {
  int painted = 0;
  if (!previous) {
    qr_progress_fill(canvas, 0, 0, grid->width, grid->height, canvas->gap);
    for (int i = 0; i < current->total; i++, painted++)
      qr_progress_paint_cell(canvas, grid, current, i);
    return painted;
  }

  for (int byte = 0; byte < (int)sizeof(current->bits); byte++) {
    uint8_t changed = previous->bits[byte] ^ current->bits[byte];
    for (int bit = 0; changed; bit++, changed >>= 1) {
      if (changed & 1) {
        qr_progress_paint_cell(canvas, grid, current, byte * 8 + bit);
        painted++;
      }
    }
  }
  if (previous->latest != current->latest) {
    qr_progress_paint_cell(canvas, grid, current, previous->latest);
    qr_progress_paint_cell(canvas, grid, current, current->latest);
    painted += 2;
  }
  return painted;
}

#endif
