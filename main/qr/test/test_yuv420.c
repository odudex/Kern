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

static void check_frame_with_offsets(uint32_t width, uint32_t height,
                                     size_t src_ofs, size_t dst_ofs) {
  size_t src_bytes = YUV420_FRAME_BYTES(width, height);
  uint8_t *packed = pack_frame(width, height);
  uint8_t *src_buf = malloc(src_bytes + src_ofs);
  assert(src_buf);
  memcpy(src_buf + src_ofs, packed, src_bytes);
  free(packed);

  size_t pixels = (size_t)width * height;
  uint8_t *gray = malloc(pixels + dst_ofs + 2);
  assert(gray);
  gray[dst_ofs] = CANARY;
  gray[dst_ofs + pixels + 1] = CANARY;

  yuv420_extract_luma(src_buf + src_ofs, width, height, gray + dst_ofs + 1);

  assert(gray[dst_ofs] == CANARY && gray[dst_ofs + pixels + 1] == CANARY);
  for (uint32_t y = 0; y < height; y++)
    for (uint32_t x = 0; x < width; x++)
      assert(gray[dst_ofs + 1 + (size_t)y * width + x] == luma_at(x, y));
  free(gray);
  free(src_buf);
}

static void check_frame(uint32_t width, uint32_t height) {
  // Cover aligned and unaligned source/destination pointers for the 32-bit
  // word-packed loop and scalar tail.
  check_frame_with_offsets(width, height, 0, 0);
  check_frame_with_offsets(width, height, 1, 3);
}

static void test_extracts_frames(void) {
  // The decode frame sizes in use, plus small ones covering every remainder
  // modulo 8 pixels (0, 2, 4, 6) and odd row counts.
  check_frame(600, 600);
  check_frame(640, 640);
  check_frame(8, 8);
  check_frame(2, 1);
  check_frame(4, 1);
  check_frame(6, 1);
  check_frame(8, 1);
  check_frame(10, 1);
  check_frame(14, 3);
  check_frame(16, 7);
}

int main(void) {
  test_extracts_frames();
  puts("All YUV420 tests passed.");
  return 0;
}
