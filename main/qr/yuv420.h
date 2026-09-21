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

// Copies a frame's luma into a tightly packed grayscale image. Samples are
// addressed by pixel pair, so the width must be even.
static inline void yuv420_extract_luma(const uint8_t *frame, uint32_t width,
                                       uint32_t height, uint8_t *gray) {
  const uint8_t *pair = frame;
  for (size_t i = 0; i < (size_t)width * height; i += 2, pair += 3) {
    gray[i] = pair[1];
    gray[i + 1] = pair[2];
  }
}

#endif
