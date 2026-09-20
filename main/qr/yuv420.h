#ifndef QR_YUV420_H
#define QR_YUV420_H

#include <stddef.h>
#include <stdint.h>

// Espressif's packed YUV420 ("OUYY_EVYY"), as the ESP32-P4 PPA writes it. Each
// pixel pair is three bytes: one chroma sample, U on the first line of every
// two and V on the second, then the pair's two luma samples.
//
//   line 0: U Y Y  U Y Y ...
//   line 1: V Y Y  V Y Y ...
#define YUV420_FRAME_BYTES(width, height)                                      \
  ((size_t)(width) * (size_t)(height) * 3 / 2)

// Copies the luma of a region into a tightly packed grayscale image. Samples
// are addressed by pixel pair, so x and width must be even.
static inline void yuv420_extract_luma(const uint8_t *frame,
                                       uint32_t frame_width, uint32_t x,
                                       uint32_t y, uint32_t width,
                                       uint32_t height, uint8_t *gray) {
  size_t stride = (size_t)frame_width * 3 / 2;
  for (uint32_t row = 0; row < height; row++) {
    const uint8_t *pair = frame + (y + row) * stride + (size_t)(x / 2) * 3;
    uint8_t *out = gray + (size_t)row * width;
    for (uint32_t i = 0; i < width; i += 2, pair += 3) {
      out[i] = pair[1];
      out[i + 1] = pair[2];
    }
  }
}

#endif
