#include "../progress.h"
#include "freertos/queue.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_coalesced_snapshots(void) {
  QueueHandle_t queue = xQueueCreate(1, sizeof(qr_part_progress_t));
  assert(queue);
  qr_part_progress_t decoder = {.total = 1024};
  qr_part_progress_t ui = {0};
  const int indices[] = {1023, 7, 8, 0, 100, 7};
  for (size_t i = 0; i < sizeof(indices) / sizeof(indices[0]); i++) {
    qr_part_progress_record(&decoder, indices[i]);
    assert(xQueueOverwrite(queue, &decoder) == pdPASS);
  }
  // The UI missed every intermediate update, but must know all five parts.
  assert(xQueueReceive(queue, &ui, 0) == pdPASS);
  assert(ui.received == 5 && ui.latest == 7);
  for (int i = 0; i < 1024; i++) {
    bool expected = i == 0 || i == 7 || i == 8 || i == 100 || i == 1023;
    assert(qr_part_progress_has(&ui, i) == expected);
  }
  assert(xQueueReceive(queue, &ui, 0) == pdFAIL);

  // Snapshots have independent storage, and an empty queue accepts updates.
  qr_part_progress_record(&decoder, 9);
  assert(!qr_part_progress_has(&ui, 9));
  assert(xQueueOverwrite(queue, &decoder) == pdPASS);
  assert(xQueueReceive(queue, &ui, 0) == pdPASS);
  assert(ui.received == 6 && qr_part_progress_has(&ui, 9));

  qr_part_progress_record(&decoder, -1);
  qr_part_progress_record(&decoder, 1024);
  assert(decoder.received == 6 && decoder.latest == 9);
  for (int i = 0; i < 1024; i++)
    qr_part_progress_record(&decoder, i);
  assert(decoder.received == 1024);
  vQueueDelete(queue);
}

static void test_grid_fits_all_boards(void) {
  const int screen_widths[] = {320, 480, 720, 1024};
  for (size_t w = 0; w < sizeof(screen_widths) / sizeof(screen_widths[0]);
       w++) {
    int available = screen_widths[w] * 80 / 100 - 12;
    // Includes the old zero-width range (86-100) and the 100/101 boundary.
    for (int total = 2; total <= 1024; total++) {
      qr_progress_grid_t grid = qr_progress_grid_layout(total, available);
      assert(grid.columns > 0 && grid.columns <= total);
      assert(grid.rows * grid.columns >= total);
      assert((grid.rows - 1) * grid.columns < total);
      assert(grid.cell_width >= 5 && grid.cell_height >= 4);
      assert(grid.width <= available && grid.height <= 130);
      for (int i = 0; i < total; i++) {
        int x = (i % grid.columns) * (grid.cell_width + QR_PROGRESS_CELL_GAP);
        int y = (i / grid.columns) * (grid.cell_height + QR_PROGRESS_CELL_GAP);
        assert(x >= 0 && x + grid.cell_width <= grid.width);
        assert(y >= 0 && y + grid.cell_height <= grid.height);
      }
    }
  }
  assert(qr_progress_grid_layout(0, 244).columns == 0);
  assert(qr_progress_grid_layout(1295, 244).columns > 0);
  assert(qr_progress_grid_layout(1296, 244).columns == 0);
  assert(qr_progress_grid_layout(100, 0).columns == 0);

  assert(qr_progress_spans_overlap(0, 4, 4, 9));
  assert(qr_progress_spans_overlap(4, 9, 0, 4));
  assert(qr_progress_spans_overlap(2, 3, 0, 9));
  assert(!qr_progress_spans_overlap(0, 4, 5, 9));
  assert(!qr_progress_spans_overlap(5, 9, 0, 4));
}

#define CANARY 0xDEAD
#define GUARD_ROWS 2
#define STRIDE_PADDING 3

typedef struct {
  qr_progress_canvas_t canvas;
  uint16_t *allocation;
  int rows;
} test_canvas_t;

static test_canvas_t test_canvas_create(const qr_progress_grid_t *grid) {
  test_canvas_t t = {.rows = grid->height + 2 * GUARD_ROWS};
  int stride = grid->width + STRIDE_PADDING;
  t.allocation = malloc((size_t)t.rows * stride * sizeof(uint16_t));
  assert(t.allocation);
  for (int i = 0; i < t.rows * stride; i++)
    t.allocation[i] = CANARY;
  t.canvas = (qr_progress_canvas_t){
      .pixels = t.allocation + GUARD_ROWS * stride,
      .stride = stride,
      .gap = 1,
      .missing = 2,
      .missing_border = 3,
      .received = 4,
      .latest = 5,
  };
  return t;
}

// Guard rows and stride padding must survive; everything else must be painted.
static void test_canvas_check_bounds(const test_canvas_t *t,
                                     const qr_progress_grid_t *grid) {
  for (int row = 0; row < t->rows; row++) {
    bool guard = row < GUARD_ROWS || row >= GUARD_ROWS + grid->height;
    for (int x = 0; x < t->canvas.stride; x++) {
      uint16_t pixel = t->allocation[row * t->canvas.stride + x];
      assert((pixel == CANARY) == (guard || x >= grid->width));
    }
  }
}

static uint16_t test_canvas_pixel(const test_canvas_t *t, int x, int y) {
  return t->canvas.pixels[y * t->canvas.stride + x];
}

static void test_cell_appearance(void) {
  qr_progress_grid_t grid = qr_progress_grid_layout(2, 244);
  assert(grid.columns == 2 && grid.rows == 1);
  test_canvas_t t = test_canvas_create(&grid);
  qr_part_progress_t progress = {.total = 2};
  qr_part_progress_record(&progress, 1);
  assert(qr_progress_paint(&t.canvas, &grid, NULL, &progress) == 2);
  test_canvas_check_bounds(&t, &grid);

  // Missing cell 0: outlined. Then the gap column. Then received cell 1.
  int last_x = grid.cell_width - 1, last_y = grid.cell_height - 1;
  assert(test_canvas_pixel(&t, 0, 0) == 3);
  assert(test_canvas_pixel(&t, last_x, last_y) == 3);
  assert(test_canvas_pixel(&t, 1, 1) == 2);
  assert(test_canvas_pixel(&t, last_x - 1, last_y - 1) == 2);
  assert(test_canvas_pixel(&t, grid.cell_width, 0) == 1);
  assert(test_canvas_pixel(&t, grid.cell_width + 1, 0) == 5);
  assert(test_canvas_pixel(&t, grid.width - 1, last_y) == 5);

  // Receiving cell 0 moves the highlight there and demotes cell 1.
  qr_part_progress_t next = progress;
  qr_part_progress_record(&next, 0);
  assert(qr_progress_paint(&t.canvas, &grid, &progress, &next) == 3);
  assert(test_canvas_pixel(&t, 1, 1) == 5);
  assert(test_canvas_pixel(&t, grid.cell_width + 1, 0) == 4);
  assert(qr_progress_paint(&t.canvas, &grid, &next, &next) == 0);
  free(t.allocation);
}

static void test_incremental_paint_matches_full_repaint(void) {
  const int screen_widths[] = {320, 480, 720, 1024};
  const int totals[] = {2, 5, 40, 41, 100, 101, 409, 1024};
  uint32_t seed = 1;
  for (size_t w = 0; w < sizeof(screen_widths) / sizeof(screen_widths[0]);
       w++) {
    for (size_t n = 0; n < sizeof(totals) / sizeof(totals[0]); n++) {
      int total = totals[n];
      qr_progress_grid_t grid =
          qr_progress_grid_layout(total, screen_widths[w] * 80 / 100 - 12);
      test_canvas_t incremental = test_canvas_create(&grid);
      test_canvas_t reference = test_canvas_create(&grid);
      size_t bytes = (size_t)incremental.rows * incremental.canvas.stride *
                     sizeof(uint16_t);

      qr_part_progress_t decoder = {.total = total};
      qr_part_progress_t displayed = {0};
      bool created = false;
      int pending = 0;
      // Rescans dominate once most parts are in, as they do on a real scan.
      for (int step = 0; step < total * 4; step++) {
        seed = seed * 1664525u + 1013904223u;
        qr_part_progress_record(&decoder, (int)((seed >> 8) % total));
        pending++;
        // The UI timer coalesces: it only ever sees some of the snapshots.
        if ((seed >> 28) % 3 != 0 && step != total * 4 - 1)
          continue;

        int painted = qr_progress_paint(&incremental.canvas, &grid,
                                        created ? &displayed : NULL, &decoder);
        assert(painted <= (created ? pending + 2 : total));
        created = true;
        pending = 0;
        displayed = decoder;

        assert(qr_progress_paint(&reference.canvas, &grid, NULL, &decoder) ==
               total);
        assert(memcmp(incremental.allocation, reference.allocation, bytes) ==
               0);
        test_canvas_check_bounds(&incremental, &grid);
      }
      free(incremental.allocation);
      free(reference.allocation);
    }
  }
}

int main(void) {
  test_coalesced_snapshots();
  test_grid_fits_all_boards();
  test_cell_appearance();
  test_incremental_paint_matches_full_repaint();
  puts("All QR progress tests passed.");
  return 0;
}
