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

static void check_frame(uint32_t width, uint32_t height) {
  uint8_t *frame = pack_frame(width, height);
  size_t pixels = (size_t)width * height;
  uint8_t *gray = malloc(pixels + 2);
  assert(gray);
  gray[0] = CANARY;
  gray[pixels + 1] = CANARY;

  yuv420_extract_luma(frame, width, height, gray + 1);

  assert(gray[0] == CANARY && gray[pixels + 1] == CANARY);
  for (uint32_t y = 0; y < height; y++)
    for (uint32_t x = 0; x < width; x++)
      assert(gray[1 + (size_t)y * width + x] == luma_at(x, y));
  free(gray);
  free(frame);
}

static void test_extracts_frames(void) {
  // The decode frame sizes in use, plus small ones for odd-row coverage.
  check_frame(600, 600);
  check_frame(640, 640);
  check_frame(8, 8);
  check_frame(2, 1);
  check_frame(16, 7);
}

int main(void) {
  test_extracts_frames();
  puts("All YUV420 tests passed.");
  return 0;
}
