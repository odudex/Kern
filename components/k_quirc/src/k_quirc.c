/*
 * K-Quirc - Standalone QR Code Recognition Library
 * Public API implementation
 *
 * Original Copyright (C) 2010-2012 Daniel Beer <dlbeer@gmail.com>
 * OpenMV modifications Copyright (c) 2013-2021 Ibrahim Abdelkader
 * <iabdalkader@openmv.io> OpenMV modifications Copyright (c) 2013-2021 Kwabena
 * W. Agyeman <kwagyeman@openmv.io>
 *
 * This work is licensed under the MIT license, see the file LICENSE for
 * details.
 */

#include "k_quirc_internal.h"

k_quirc_t *k_quirc_new(void) {
  k_quirc_t *q = K_MALLOC(sizeof(*q));
  if (q)
    memset(q, 0, sizeof(*q));
  return q;
}

void k_quirc_destroy(k_quirc_t *q) {
  if (q) {
    if (q->image)
      K_FREE(q->image);
    if (sizeof(*q->image) != sizeof(*q->pixels) && q->pixels)
      K_FREE(q->pixels);
    K_FREE(q);
  }
}

int k_quirc_resize(k_quirc_t *q, int w, int h) {
  if (q->image)
    K_FREE(q->image);

  uint8_t *new_image = K_MALLOC(w * h);
  if (!new_image)
    return -1;

  if (sizeof(*q->image) != sizeof(*q->pixels)) {
    size_t new_size = w * h * sizeof(quirc_pixel_t);
    if (q->pixels)
      K_FREE(q->pixels);
    quirc_pixel_t *new_pixels = K_MALLOC(new_size);
    if (!new_pixels) {
      K_FREE(new_image);
      return -1;
    }
    q->pixels = new_pixels;
  }

  q->image = new_image;
  q->w = w;
  q->h = h;

  return 0;
}

uint8_t *k_quirc_begin(k_quirc_t *q, int *w, int *h) {
  q->num_regions = QUIRC_PIXEL_REGION;
  q->num_capstones = 0;
  q->num_grids = 0;

  if (w)
    *w = q->w;
  if (h)
    *h = q->h;

  return q->image;
}

void k_quirc_end(k_quirc_t *q, bool find_inverted) {
  k_quirc_identify(q, find_inverted);
}

int k_quirc_count(const k_quirc_t *q) { return q->num_grids; }

k_quirc_error_t k_quirc_decode(k_quirc_t *q, int index,
                               k_quirc_result_t *result) {
  struct quirc_code *code = K_MALLOC_FAST(sizeof(struct quirc_code));
  if (!code)
    code = K_MALLOC(sizeof(struct quirc_code));
  struct quirc_data *data = K_MALLOC_FAST(sizeof(struct quirc_data));
  if (!data)
    data = K_MALLOC(sizeof(struct quirc_data));

  if (!code || !data) {
    if (code)
      K_FREE(code);
    if (data)
      K_FREE(data);
    return K_QUIRC_ERROR_ALLOC_FAILED;
  }

  memset(result, 0, sizeof(*result));
  result->valid = false;

  if (index < 0 || index >= q->num_grids) {
    K_FREE(code);
    K_FREE(data);
    return K_QUIRC_ERROR_INVALID_GRID_SIZE;
  }

  quirc_extract_internal(q, index, code);

  k_quirc_error_t err = quirc_decode_internal(code, data);
  if (err == K_QUIRC_SUCCESS) {
    result->valid = true;
    for (int i = 0; i < 4; i++) {
      result->corners[i].x = code->corners[i].x;
      result->corners[i].y = code->corners[i].y;
    }
    result->data.version = data->version;
    result->data.ecc_level = data->ecc_level;
    result->data.mask = data->mask;
    result->data.data_type = data->data_type;
    result->data.payload_len = data->payload_len;
    result->data.eci = data->eci;
    memcpy(result->data.payload, data->payload, data->payload_len + 1);
  }

  K_FREE(code);
  K_FREE(data);

  return err;
}

const char *k_quirc_strerror(k_quirc_error_t err) {
  static const char *error_table[] = {
      [K_QUIRC_SUCCESS] = "Success",
      [K_QUIRC_ERROR_INVALID_GRID_SIZE] = "Invalid grid size",
      [K_QUIRC_ERROR_INVALID_VERSION] = "Invalid version",
      [K_QUIRC_ERROR_FORMAT_ECC] = "Format data ECC failure",
      [K_QUIRC_ERROR_DATA_ECC] = "ECC failure",
      [K_QUIRC_ERROR_UNKNOWN_DATA_TYPE] = "Unknown data type",
      [K_QUIRC_ERROR_DATA_OVERFLOW] = "Data overflow",
      [K_QUIRC_ERROR_DATA_UNDERFLOW] = "Data underflow",
      [K_QUIRC_ERROR_ALLOC_FAILED] = "Memory allocation failed"};

  if (err >= 0 && err < sizeof(error_table) / sizeof(error_table[0]))
    return error_table[err];

  return "Unknown error";
}

int k_quirc_decode_grayscale(const uint8_t *grayscale_data, int width,
                             int height, k_quirc_result_t *results,
                             int max_results, bool find_inverted) {
  k_quirc_t *q = k_quirc_new();
  if (!q)
    return 0;

  if (k_quirc_resize(q, width, height) < 0) {
    k_quirc_destroy(q);
    return 0;
  }

  uint8_t *buf = k_quirc_begin(q, NULL, NULL);
  memcpy(buf, grayscale_data, width * height);

  k_quirc_end(q, find_inverted);

  int count = k_quirc_count(q);
  int decoded = 0;

  for (int i = 0; i < count && decoded < max_results; i++) {
    k_quirc_error_t err = k_quirc_decode(q, i, &results[decoded]);
    if (err == K_QUIRC_SUCCESS) {
      decoded++;
    }
  }

  k_quirc_destroy(q);
  return decoded;
}

#ifdef K_QUIRC_DEBUG_VIS

static k_quirc_debug_info_t debug_info;

const k_quirc_debug_info_t *k_quirc_get_debug_info(const k_quirc_t *q) {
  if (!q)
    return NULL;

  debug_info.pixels = q->pixels;
  debug_info.w = q->w;
  debug_info.h = q->h;
  debug_info.num_grids = q->num_grids;

  for (int i = 0; i < q->num_grids && i < K_QUIRC_DEBUG_MAX_GRIDS; i++) {
    memcpy(debug_info.grids[i].c, q->grids[i].c, sizeof(float) * 8);
    debug_info.grids[i].grid_size = q->grids[i].grid_size;
    debug_info.grids[i].timing_bias = q->grids[i].timing_bias;
  }

  debug_info.num_capstones = q->num_capstones;
  for (int i = 0; i < q->num_capstones && i < K_QUIRC_DEBUG_MAX_CAPSTONES; i++) {
    debug_info.capstones[i].x = q->capstones[i].center.x;
    debug_info.capstones[i].y = q->capstones[i].center.y;
  }

  debug_info.threshold_offset = k_quirc_get_threshold_offset();

  return &debug_info;
}

#endif /* K_QUIRC_DEBUG_VIS */
