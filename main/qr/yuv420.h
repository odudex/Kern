#ifndef QR_YUV420_H
#define QR_YUV420_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
static inline void yuv420_extract_luma(const uint8_t *restrict frame,
                                       uint32_t width, uint32_t height,
                                       uint8_t *restrict gray) {
  size_t total = (size_t)width * (size_t)height;
  const uint8_t *pair = frame;
  size_t i = 0;

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  // Unpack 4 pixel pairs (12 bytes -> 8 luma bytes) per iteration using three
  // 32-bit loads and two 32-bit stores instead of 16 byte memory ops:
  //   w0 = [C0, Y0, Y1, C1]
  //   w1 = [Y2, Y3, C2, Y4]
  //   w2 = [Y5, C3, Y6, Y7]
  // Fixed-size memcpy compiles to single word loads/stores while remaining
  // safe for unaligned buffers and strict aliasing.
  size_t vec_end = total & ~(size_t)7;
  for (; i < vec_end; i += 8, pair += 12) {
    uint32_t w0, w1, w2;
    memcpy(&w0, pair, 4);
    memcpy(&w1, pair + 4, 4);
    memcpy(&w2, pair + 8, 4);

    uint32_t out0 = ((w0 >> 8) & 0x0000FFFFu) | ((w1 & 0x0000FFFFu) << 16);
    uint32_t out1 = (w1 >> 24) | ((w2 & 0x000000FFu) << 8) | (w2 & 0xFFFF0000u);

    memcpy(gray + i, &out0, 4);
    memcpy(gray + i + 4, &out1, 4);
  }
#endif

  for (; i < total; i += 2, pair += 3) {
    gray[i] = pair[1];
    gray[i + 1] = pair[2];
  }
}

#endif
