#include "../yuv420.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CANARY 0xA5

// Luma is a function of position; chroma bytes are values no luma takes, so a
// misaddressed sample cannot pass for a correct one.
static uint8_t luma_at(uint32_t x, uint32_t y) {
  return (uint8_t)((x * 7 + y * 13) % 200);
}

static uint8_t *pack_frame(uint32_t width, uint32_t height) {
  uint8_t *frame = malloc(YUV420_FRAME_BYTES(width, height));
  assert(frame);
  uint8_t *out = frame;
  for (uint32_t y = 0; y < height; y++) {
    for (uint32_t x = 0; x < width; x += 2) {
      *out++ = (y % 2) ? 0xFE : 0xFD; // V on odd lines, U on even ones
      *out++ = luma_at(x, y);
      *out++ = luma_at(x + 1, y);
    }
  }
  assert((size_t)(out - frame) == YUV420_FRAME_BYTES(width, height));
  return frame;
}

static void check_region(const uint8_t *frame, uint32_t frame_width, uint32_t x,
                         uint32_t y, uint32_t width, uint32_t height) {
  size_t pixels = (size_t)width * height;
  uint8_t *gray = malloc(pixels + 2);
  assert(gray);
  gray[0] = CANARY;
  gray[pixels + 1] = CANARY;

  yuv420_extract_luma(frame, frame_width, x, y, width, height, gray + 1);

  assert(gray[0] == CANARY && gray[pixels + 1] == CANARY);
  for (uint32_t row = 0; row < height; row++)
    for (uint32_t col = 0; col < width; col++)
      assert(gray[1 + (size_t)row * width + col] == luma_at(x + col, y + row));
  free(gray);
}

static void test_extracts_full_frames_and_regions(void) {
  // The decode frame sizes in use, plus a small one for odd-row coverage.
  const uint32_t sizes[] = {8, 600, 640};
  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
    uint32_t size = sizes[i];
    uint8_t *frame = pack_frame(size, size);
    check_region(frame, size, 0, 0, size, size);
    check_region(frame, size, 0, 0, 2, 1);
    check_region(frame, size, size - 2, size - 1, 2, 1);
    check_region(frame, size, 2, 3, size - 4, size - 5);
    if (size >= 600) {
      check_region(frame, size, 96, 71, 416, 416); // a typical ROI
      check_region(frame, size, size - 64, size - 64, 64, 64);
    }
    free(frame);
  }
}

static void test_rectangular_frame(void) {
  uint8_t *frame = pack_frame(16, 6);
  check_region(frame, 16, 0, 0, 16, 6);
  check_region(frame, 16, 4, 1, 8, 4);
  free(frame);
}

int main(void) {
  test_extracts_full_frames_and_regions();
  test_rectangular_frame();
  puts("All YUV420 tests passed.");
  return 0;
}
