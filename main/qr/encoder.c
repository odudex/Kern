#include "encoder.h"
#ifdef SIMULATOR
#include <libs/qrcode/qrcodegen.h>
#else
#include "../managed_components/lvgl__lvgl/src/libs/qrcode/qrcodegen.h"
#endif
#include <ctype.h>
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip39.h>
#include <wally_core.h>

static bool is_all_digits(const char *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (!isdigit((unsigned char)data[i])) {
      return false;
    }
  }
  return true;
}

static bool looks_like_plaintext(const char *data, size_t len) {
  bool has_space = false;
  bool has_letter = false;

  for (size_t i = 0; i < len; i++) {
    char c = data[i];
    if (c == ' ') {
      has_space = true;
    } else if (isalpha((unsigned char)c)) {
      has_letter = true;
    } else if (!isprint((unsigned char)c)) {
      return false;
    }
  }
  return has_space && has_letter;
}

static bool has_non_printable(const char *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (!isprint((unsigned char)data[i]) && !isspace((unsigned char)data[i])) {
      return true;
    }
  }
  return false;
}

mnemonic_qr_format_t mnemonic_qr_detect_format(const char *data, size_t len) {
  if (!data || len == 0) {
    return MNEMONIC_QR_UNKNOWN;
  }

  // Compact SeedQR: exactly 16 or 32 bytes with non-printable characters
  if ((len == COMPACT_SEEDQR_12_WORDS_LEN ||
       len == COMPACT_SEEDQR_24_WORDS_LEN) &&
      has_non_printable(data, len)) {
    return MNEMONIC_QR_COMPACT;
  }

  // SeedQR: exactly 48 or 96 decimal digits
  if ((len == SEEDQR_12_WORDS_LEN || len == SEEDQR_24_WORDS_LEN) &&
      is_all_digits(data, len)) {
    return MNEMONIC_QR_SEEDQR;
  }

  // Plaintext: contains spaces and letters
  if (looks_like_plaintext(data, len)) {
    return MNEMONIC_QR_PLAINTEXT;
  }

  // 16/32 bytes of printable data - try as Compact SeedQR anyway
  if (len == COMPACT_SEEDQR_12_WORDS_LEN ||
      len == COMPACT_SEEDQR_24_WORDS_LEN) {
    return MNEMONIC_QR_COMPACT;
  }

  return MNEMONIC_QR_UNKNOWN;
}

char *mnemonic_qr_compact_to_mnemonic(const unsigned char *data, size_t len) {
  if (!data || (len != COMPACT_SEEDQR_12_WORDS_LEN &&
                len != COMPACT_SEEDQR_24_WORDS_LEN)) {
    return NULL;
  }

  char *wally_mnemonic = NULL;
  if (bip39_mnemonic_from_bytes(NULL, data, len, &wally_mnemonic) != WALLY_OK ||
      !wally_mnemonic) {
    return NULL;
  }

  if (bip39_mnemonic_validate(NULL, wally_mnemonic) != WALLY_OK) {
    wally_free_string(wally_mnemonic);
    return NULL;
  }

  char *mnemonic = strdup(wally_mnemonic);
  wally_free_string(wally_mnemonic);
  return mnemonic;
}

char *mnemonic_qr_seedqr_to_mnemonic(const char *data, size_t len) {
  if (!data || (len != SEEDQR_12_WORDS_LEN && len != SEEDQR_24_WORDS_LEN) ||
      !is_all_digits(data, len)) {
    return NULL;
  }

  int word_count = (len == SEEDQR_12_WORDS_LEN) ? 12 : 24;

  struct words *wordlist = NULL;
  if (bip39_get_wordlist(NULL, &wordlist) != WALLY_OK || !wordlist) {
    return NULL;
  }

  size_t max_len = word_count * 12;
  char *mnemonic = malloc(max_len);
  if (!mnemonic) {
    return NULL;
  }

  size_t offset = 0;
  for (int i = 0; i < word_count; i++) {
    char index_str[5] = {data[i * 4], data[i * 4 + 1], data[i * 4 + 2],
                         data[i * 4 + 3], '\0'};
    int word_index = atoi(index_str);

    if (word_index < 0 || word_index > 2047) {
      free(mnemonic);
      return NULL;
    }

    const char *word = bip39_get_word_by_index(wordlist, (size_t)word_index);
    if (!word) {
      free(mnemonic);
      return NULL;
    }

    if (i > 0) {
      mnemonic[offset++] = ' ';
    }

    size_t word_len = strlen(word);
    if (offset + word_len >= max_len) {
      free(mnemonic);
      return NULL;
    }

    memcpy(mnemonic + offset, word, word_len);
    offset += word_len;
  }
  mnemonic[offset] = '\0';

  if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    free(mnemonic);
    return NULL;
  }

  return mnemonic;
}

char *mnemonic_qr_to_mnemonic(const char *data, size_t len,
                              mnemonic_qr_format_t *format_out) {
  if (!data || len == 0) {
    if (format_out) {
      *format_out = MNEMONIC_QR_UNKNOWN;
    }
    return NULL;
  }

  mnemonic_qr_format_t format = mnemonic_qr_detect_format(data, len);
  if (format_out) {
    *format_out = format;
  }

  switch (format) {
  case MNEMONIC_QR_COMPACT:
    return mnemonic_qr_compact_to_mnemonic((const unsigned char *)data, len);

  case MNEMONIC_QR_SEEDQR:
    return mnemonic_qr_seedqr_to_mnemonic(data, len);

  case MNEMONIC_QR_PLAINTEXT: {
    char *mnemonic = strndup(data, len);
    if (mnemonic && bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
      free(mnemonic);
      return NULL;
    }
    return mnemonic;
  }

  default:
    return NULL;
  }
}

const char *mnemonic_qr_format_name(mnemonic_qr_format_t format) {
  switch (format) {
  case MNEMONIC_QR_PLAINTEXT:
    return "Plaintext";
  case MNEMONIC_QR_COMPACT:
    return "Compact SeedQR";
  case MNEMONIC_QR_SEEDQR:
    return "SeedQR";
  default:
    return "Unknown";
  }
}

char *mnemonic_to_seedqr(const char *mnemonic) {
  if (!mnemonic) {
    return NULL;
  }

  // Validate mnemonic first
  if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    return NULL;
  }

  // Get the BIP39 wordlist
  struct words *wordlist = NULL;
  if (bip39_get_wordlist(NULL, &wordlist) != WALLY_OK || !wordlist) {
    return NULL;
  }

  // Count words to determine output size
  int word_count = 0;
  const char *p = mnemonic;
  while (*p) {
    while (*p == ' ')
      p++;
    if (*p) {
      word_count++;
      while (*p && *p != ' ')
        p++;
    }
  }

  if (word_count != 12 && word_count != 24) {
    return NULL;
  }

  // Allocate output buffer (4 digits per word + null terminator)
  size_t output_len = (size_t)word_count * 4 + 1;
  char *seedqr = malloc(output_len);
  if (!seedqr) {
    return NULL;
  }

  // Process each word
  size_t offset = 0;
  p = mnemonic;
  while (*p) {
    // Skip leading spaces
    while (*p == ' ')
      p++;
    if (!*p)
      break;

    // Find word end
    const char *word_start = p;
    while (*p && *p != ' ')
      p++;
    size_t word_len = (size_t)(p - word_start);

    // Create null-terminated word for lookup
    char word[16];
    if (word_len >= sizeof(word)) {
      free(seedqr);
      return NULL;
    }
    memcpy(word, word_start, word_len);
    word[word_len] = '\0';

    // Find word index in wordlist
    size_t word_index;
    bool found = false;
    for (size_t i = 0; i < 2048; i++) {
      const char *list_word = bip39_get_word_by_index(wordlist, i);
      if (list_word && strcmp(word, list_word) == 0) {
        word_index = i;
        found = true;
        break;
      }
    }

    if (!found) {
      free(seedqr);
      return NULL;
    }

    // Write 4-digit zero-padded index
    snprintf(seedqr + offset, 5, "%04zu", word_index);
    offset += 4;
  }

  seedqr[offset] = '\0';
  return seedqr;
}

unsigned char *mnemonic_to_compact_seedqr(const char *mnemonic,
                                          size_t *out_len) {
  if (!mnemonic || !out_len) {
    return NULL;
  }

  if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    return NULL;
  }

  unsigned char entropy[32];
  size_t entropy_len = 0;
  if (bip39_mnemonic_to_bytes(NULL, mnemonic, entropy, sizeof(entropy),
                              &entropy_len) != WALLY_OK) {
    return NULL;
  }

  if (entropy_len != COMPACT_SEEDQR_12_WORDS_LEN &&
      entropy_len != COMPACT_SEEDQR_24_WORDS_LEN) {
    return NULL;
  }

  unsigned char *result = malloc(entropy_len);
  if (!result) {
    return NULL;
  }

  memcpy(result, entropy, entropy_len);
  *out_len = entropy_len;
  return result;
}

lv_result_t qr_update_binary(lv_obj_t *qr_obj, const unsigned char *data,
                             size_t len, qr_encode_result_t *result) {
  if (!qr_obj || !data || len == 0 || len > qrcodegen_BUFFER_LEN_MAX) {
    return LV_RESULT_INVALID;
  }

  lv_draw_buf_t *draw_buf = lv_canvas_get_draw_buf(qr_obj);
  if (!draw_buf) {
    return LV_RESULT_INVALID;
  }

  int32_t canvas_size = draw_buf->header.w;
  uint8_t *qr_code = malloc(qrcodegen_BUFFER_LEN_MAX);
  uint8_t *data_buf = malloc(qrcodegen_BUFFER_LEN_MAX);
  if (!qr_code || !data_buf) {
    free(qr_code);
    free(data_buf);
    return LV_RESULT_INVALID;
  }

  memcpy(data_buf, data, len);
  bool ok = qrcodegen_encodeBinary(data_buf, len, qr_code, qrcodegen_Ecc_LOW,
                                   qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                                   qrcodegen_Mask_AUTO, true);
  free(data_buf);
  if (!ok) {
    free(qr_code);
    return LV_RESULT_INVALID;
  }

  int32_t qr_size = qrcodegen_getSize(qr_code);
  int32_t scale = canvas_size / qr_size;
  int32_t margin = (canvas_size - (qr_size * scale)) / 2;

  if (result) {
    result->modules = qr_size;
    result->scale = scale;
  }

  lv_draw_buf_clear(draw_buf, NULL);
  lv_canvas_set_palette(qr_obj, 0,
                        lv_color_to_32(lv_color_white(), LV_OPA_COVER));
  lv_canvas_set_palette(qr_obj, 1,
                        lv_color_to_32(lv_color_black(), LV_OPA_COVER));

  uint8_t *buf = (uint8_t *)draw_buf->data + 8;
  uint32_t stride = draw_buf->header.stride;

  for (int32_t qy = 0; qy < qr_size; qy++) {
    int32_t py = margin + qy * scale;
    for (int32_t qx = 0; qx < qr_size; qx++) {
      if (qrcodegen_getModule(qr_code, qx, qy)) {
        int32_t px = margin + qx * scale;
        for (int32_t dx = 0; dx < scale; dx++) {
          int32_t x = px + dx;
          buf[py * stride + (x >> 3)] |= (0x80 >> (x & 7));
        }
      }
    }
    uint8_t *src_row = buf + py * stride;
    for (int32_t dy = 1; dy < scale; dy++) {
      memcpy(buf + (py + dy) * stride, src_row, stride);
    }
  }

  free(qr_code);
  lv_image_cache_drop(draw_buf);
  lv_obj_invalidate(qr_obj);
  return LV_RESULT_OK;
}

lv_result_t qr_update_optimal(lv_obj_t *qr_obj, const char *text,
                              qr_encode_result_t *result) {
  if (!qr_obj || !text || strlen(text) == 0 ||
      strlen(text) > qrcodegen_BUFFER_LEN_MAX) {
    return LV_RESULT_INVALID;
  }

  lv_draw_buf_t *draw_buf = lv_canvas_get_draw_buf(qr_obj);
  if (!draw_buf) {
    return LV_RESULT_INVALID;
  }

  int32_t canvas_size = draw_buf->header.w;
  uint8_t *qr_code = malloc(qrcodegen_BUFFER_LEN_MAX);
  uint8_t *temp_buf = malloc(qrcodegen_BUFFER_LEN_MAX);
  if (!qr_code || !temp_buf) {
    free(qr_code);
    free(temp_buf);
    return LV_RESULT_INVALID;
  }

  // Use LOW ECC with boost for optimal density while maximizing error
  // correction within the chosen version. encodeText auto-selects
  // numeric/alphanumeric/byte mode.
  bool ok = qrcodegen_encodeText(text, temp_buf, qr_code, qrcodegen_Ecc_LOW,
                                 qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                                 qrcodegen_Mask_AUTO, true);
  free(temp_buf);
  if (!ok) {
    free(qr_code);
    return LV_RESULT_INVALID;
  }

  int32_t qr_size = qrcodegen_getSize(qr_code);
  int32_t scale = canvas_size / qr_size;
  int32_t margin = (canvas_size - (qr_size * scale)) / 2;

  // Populate result if requested
  if (result) {
    result->modules = qr_size;
    result->scale = scale;
  }

  lv_draw_buf_clear(draw_buf, NULL);
  lv_canvas_set_palette(qr_obj, 0,
                        lv_color_to_32(lv_color_white(), LV_OPA_COVER));
  lv_canvas_set_palette(qr_obj, 1,
                        lv_color_to_32(lv_color_black(), LV_OPA_COVER));

  uint8_t *buf = (uint8_t *)draw_buf->data + 8; // Skip palette
  uint32_t stride = draw_buf->header.stride;

  for (int32_t qy = 0; qy < qr_size; qy++) {
    int32_t py = margin + qy * scale;
    for (int32_t qx = 0; qx < qr_size; qx++) {
      if (qrcodegen_getModule(qr_code, qx, qy)) {
        int32_t px = margin + qx * scale;
        for (int32_t dx = 0; dx < scale; dx++) {
          int32_t x = px + dx;
          buf[py * stride + (x >> 3)] |= (0x80 >> (x & 7));
        }
      }
    }
    uint8_t *src_row = buf + py * stride;
    for (int32_t dy = 1; dy < scale; dy++) {
      memcpy(buf + (py + dy) * stride, src_row, stride);
    }
  }

  free(qr_code);
  lv_image_cache_drop(draw_buf);
  lv_obj_invalidate(qr_obj);
  return LV_RESULT_OK;
}
