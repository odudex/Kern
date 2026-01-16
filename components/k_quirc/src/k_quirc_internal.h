/*
 * K-Quirc Internal Header
 * Internal types, macros, and shared structures
 */

#ifndef K_QUIRC_INTERNAL_H
#define K_QUIRC_INTERNAL_H

#include "k_quirc.h"
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include <esp_heap_caps.h>
#define K_MALLOC(size)                                                         \
  heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT |                 \
                             MALLOC_CAP_CACHE_ALIGNED)
#define K_MALLOC_FAST(size)                                                    \
  heap_caps_malloc(size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)
#define K_FREE(ptr) heap_caps_free(ptr)
#else
#define K_MALLOC(size) malloc(size)
#define K_MALLOC_FAST(size) malloc(size)
#define K_FREE(ptr) free(ptr)
#endif

/* Compiler optimization hints */
#ifndef __GNUC__
#define __attribute__(x)
#endif

#define HOT_FUNC __attribute__((hot))
#define ALWAYS_INLINE __attribute__((always_inline)) static inline
#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

/* Quirc internal definitions */
#define QUIRC_PIXEL_WHITE 0
#define QUIRC_PIXEL_BLACK 1
#define QUIRC_PIXEL_REGION 2

#ifndef QUIRC_MAX_REGIONS
#define QUIRC_MAX_REGIONS 254
#endif

#define QUIRC_MAX_CAPSTONES 32
#define QUIRC_MAX_GRIDS 8
#define QUIRC_PERSPECTIVE_PARAMS 8
#define QUIRC_MAX_VERSION 24
#define QUIRC_MAX_ALIGNMENT 7

#if QUIRC_MAX_REGIONS < UINT8_MAX
typedef uint8_t quirc_pixel_t;
#elif QUIRC_MAX_REGIONS < UINT16_MAX
typedef uint16_t quirc_pixel_t;
#else
#error "QUIRC_MAX_REGIONS > 65534 is not supported"
#endif

/*
 * Internal structures
 */
struct quirc_point {
  int x;
  int y;
};

struct quirc_region {
  struct quirc_point seed;
  int count;
  int capstone;
};

struct quirc_capstone {
  int ring;
  int stone;
  struct quirc_point corners[4];
  struct quirc_point center;
  float c[QUIRC_PERSPECTIVE_PARAMS];
  int qr_grid;
};

struct quirc_grid {
  int caps[3];
  int align_region;
  struct quirc_point align;
  struct quirc_point tpep[3];
  int hscan;
  int vscan;
  int grid_size;
  float c[QUIRC_PERSPECTIVE_PARAMS];
  int timing_bias;
};

struct quirc_code {
  struct quirc_point corners[4];
  int size;
  uint8_t cell_bitmap[K_QUIRC_MAX_BITMAP];
};

struct quirc_data {
  int version;
  int ecc_level;
  int mask;
  int data_type;
  uint8_t payload[K_QUIRC_MAX_PAYLOAD];
  int payload_len;
  uint32_t eci;
};

struct k_quirc {
  uint8_t *image;
  quirc_pixel_t *pixels;
  int w;
  int h;
  int num_regions;
  struct quirc_region regions[QUIRC_MAX_REGIONS];
  int num_capstones;
  struct quirc_capstone capstones[QUIRC_MAX_CAPSTONES];
  int num_grids;
  struct quirc_grid grids[QUIRC_MAX_GRIDS];
};

/*
 * Version info structure
 */
struct quirc_rs_params {
  uint8_t bs;
  uint8_t dw;
  uint8_t ns;
};

struct quirc_version_info {
  uint16_t data_bytes;
  uint8_t apat[QUIRC_MAX_ALIGNMENT];
  struct quirc_rs_params ecc[4];
};

/* Version database - defined in k_quirc_version.c */
extern const struct quirc_version_info quirc_version_db[QUIRC_MAX_VERSION + 1];

/*
 * Helper functions
 */
ALWAYS_INLINE int fast_roundf(float x) { return (int)(x + 0.5f); }

ALWAYS_INLINE void perspective_map(const float *c, float u, float v,
                                   struct quirc_point *ret) {
  float den = c[6] * u + c[7] * v + 1.0f;
  float inv_den = 1.0f / den;
  float x = (c[0] * u + c[1] * v + c[2]) * inv_den;
  float y = (c[3] * u + c[4] * v + c[5]) * inv_den;

  ret->x = fast_roundf(x);
  ret->y = fast_roundf(y);
}

/*
 * Identification module functions (k_quirc_identify.c)
 */
void k_quirc_identify(struct k_quirc *q, bool find_inverted);
int k_quirc_get_threshold_offset(void);

/*
 * Decode module functions (k_quirc_decode.c)
 */
void quirc_extract_internal(const struct k_quirc *q, int index,
                            struct quirc_code *code);
k_quirc_error_t quirc_decode_internal(const struct quirc_code *code,
                                      struct quirc_data *data);

#endif /* K_QUIRC_INTERNAL_H */
