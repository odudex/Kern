#include "deflate_codec.h"

#include <limits.h>
#include <stdlib.h>
#include <zlib.h>

#define DEFLATE_CODEC_MEM_LEVEL 4
#define DEFLATE_CODEC_INITIAL_OUTPUT 1024U

#ifdef ESP_PLATFORM
#include <esp_heap_caps.h>

// zlib's internal state is several KB per stream; keep it out of the scarce
// internal DRAM that the camera/ISP pipeline already pressures.
static voidpf codec_zalloc(voidpf opaque, uInt items, uInt size) {
  (void)opaque;
  return heap_caps_malloc_prefer((size_t)items * size, 2,
                                 MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                 MALLOC_CAP_8BIT);
}

static void codec_zfree(voidpf opaque, voidpf address) {
  (void)opaque;
  heap_caps_free(address);
}
#endif

static void stream_set_allocator(z_stream *stream) {
#ifdef ESP_PLATFORM
  stream->zalloc = codec_zalloc;
  stream->zfree = codec_zfree;
#else
  (void)stream;
#endif
}

uint8_t *deflate_compress_raw_alloc(const uint8_t *source, size_t source_len,
                                    size_t *dest_len, int window_bits) {
  if ((!source && source_len != 0) || !dest_len || window_bits < 8 ||
      window_bits > MAX_WBITS || source_len > UINT_MAX ||
      source_len > ULONG_MAX) {
    return NULL;
  }

  z_stream stream = {0};
  stream_set_allocator(&stream);
  if (deflateInit2(&stream, Z_BEST_COMPRESSION, Z_DEFLATED, -window_bits,
                   DEFLATE_CODEC_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK) {
    return NULL;
  }

  uLong bound = deflateBound(&stream, (uLong)source_len);
  if (bound == 0 || bound > SIZE_MAX || bound > UINT_MAX) {
    deflateEnd(&stream);
    return NULL;
  }

  uint8_t *dest = (uint8_t *)malloc((size_t)bound);
  if (!dest) {
    deflateEnd(&stream);
    return NULL;
  }

  stream.next_in = (Bytef *)source;
  stream.avail_in = (uInt)source_len;
  stream.next_out = dest;
  stream.avail_out = (uInt)bound;

  int status = deflate(&stream, Z_FINISH);
  if (status != Z_STREAM_END) {
    deflateEnd(&stream);
    free(dest);
    return NULL;
  }

  size_t actual_len = (size_t)stream.total_out;
  deflateEnd(&stream);

  uint8_t *shrunk = (uint8_t *)realloc(dest, actual_len);
  if (shrunk) {
    dest = shrunk;
  }
  *dest_len = actual_len;
  return dest;
}

static uint8_t *inflate_alloc(const uint8_t *source, size_t source_len,
                              size_t *dest_len, int window_bits,
                              size_t max_output) {
  if (!source || source_len == 0 || !dest_len || max_output == 0 ||
      source_len > UINT_MAX) {
    return NULL;
  }

  z_stream stream = {0};
  stream_set_allocator(&stream);
  if (inflateInit2(&stream, window_bits) != Z_OK) {
    return NULL;
  }

  size_t capacity = source_len > max_output / 4 ? max_output : source_len * 4;
  if (capacity < DEFLATE_CODEC_INITIAL_OUTPUT) {
    capacity = max_output < DEFLATE_CODEC_INITIAL_OUTPUT
                   ? max_output
                   : DEFLATE_CODEC_INITIAL_OUTPUT;
  }

  uint8_t *dest = (uint8_t *)malloc(capacity);
  if (!dest) {
    inflateEnd(&stream);
    return NULL;
  }

  stream.next_in = (Bytef *)source;
  stream.avail_in = (uInt)source_len;
  stream.next_out = dest;
  stream.avail_out = (uInt)capacity;

  for (;;) {
    int status = inflate(&stream, Z_NO_FLUSH);
    if (status == Z_STREAM_END) {
      break;
    }
    if (status != Z_OK) {
      inflateEnd(&stream);
      free(dest);
      return NULL;
    }

    if (stream.avail_out != 0) {
      if (stream.avail_in == 0) {
        inflateEnd(&stream);
        free(dest);
        return NULL;
      }
      continue;
    }

    if (capacity >= max_output) {
      inflateEnd(&stream);
      free(dest);
      return NULL;
    }

    size_t used = (size_t)stream.total_out;
    size_t new_capacity = capacity > max_output / 2 ? max_output : capacity * 2;
    uint8_t *grown = (uint8_t *)realloc(dest, new_capacity);
    if (!grown) {
      inflateEnd(&stream);
      free(dest);
      return NULL;
    }

    dest = grown;
    capacity = new_capacity;
    stream.next_out = dest + used;
    stream.avail_out = (uInt)(capacity - used);
  }

  size_t actual_len = (size_t)stream.total_out;
  inflateEnd(&stream);

  if (actual_len > 0) {
    uint8_t *shrunk = (uint8_t *)realloc(dest, actual_len);
    if (shrunk) {
      dest = shrunk;
    }
  }
  *dest_len = actual_len;
  return dest;
}

uint8_t *deflate_decompress_raw_alloc(const uint8_t *source, size_t source_len,
                                      size_t *dest_len, int window_bits,
                                      size_t max_output) {
  if (window_bits < 8 || window_bits > MAX_WBITS) {
    return NULL;
  }
  return inflate_alloc(source, source_len, dest_len, -window_bits, max_output);
}

uint8_t *deflate_decompress_zlib_alloc(const uint8_t *source, size_t source_len,
                                       size_t *dest_len, size_t max_output) {
  return inflate_alloc(source, source_len, dest_len, MAX_WBITS, max_output);
}
