#include "bbqr.h"
#include "base32.h"
#include "deflate_codec.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

// Base36 alphabet (0-9, A-Z)
static const char BASE36_ALPHABET[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// BBQr spec: raw deflate with a 1KB window (wbits = -10)
#define BBQR_COMPRESS_WBITS 10
// Decode liberally: raw inflate at 15 accepts any window, including spec's 10
#define BBQR_DECODE_WBITS 15
#define BBQR_MAX_DECOMPRESSED (512U * 1024U)

typedef struct {
  BBQrParts *parts;
  int part_index;
  size_t payload_offset;
  size_t payload_per_part;
  size_t encoded_len;
  size_t total_written;
} bbqr_parts_writer_t;

static size_t part_payload_len(size_t encoded_len, size_t payload_per_part,
                               int index) {
  size_t start = (size_t)index * payload_per_part;
  size_t remaining = encoded_len - start;
  return remaining < payload_per_part ? remaining : payload_per_part;
}

static bool write_to_parts(void *context, const char *data, size_t len) {
  bbqr_parts_writer_t *writer = (bbqr_parts_writer_t *)context;

  while (len > 0) {
    if (writer->part_index >= writer->parts->count) {
      return false;
    }

    size_t part_len = part_payload_len(
        writer->encoded_len, writer->payload_per_part, writer->part_index);
    size_t available = part_len - writer->payload_offset;
    size_t chunk_len = len < available ? len : available;
    memcpy(writer->parts->parts[writer->part_index] + BBQR_HEADER_LEN +
               writer->payload_offset,
           data, chunk_len);
    writer->payload_offset += chunk_len;
    writer->total_written += chunk_len;
    data += chunk_len;
    len -= chunk_len;

    if (writer->payload_offset == part_len) {
      writer->part_index++;
      writer->payload_offset = 0;
    }
  }

  return true;
}

bool bbqr_is_valid_encoding(char c) {
  return c == BBQR_ENCODING_HEX || c == BBQR_ENCODING_BASE32 ||
         c == BBQR_ENCODING_ZLIB;
}

bool bbqr_is_valid_file_type(char c) {
  return c == BBQR_TYPE_PSBT || c == BBQR_TYPE_TRANSACTION ||
         c == BBQR_TYPE_JSON || c == BBQR_TYPE_UNICODE;
}

int bbqr_base36_decode(char c1, char c2) {
  int v1 = -1, v2 = -1;

  c1 = toupper((unsigned char)c1);
  c2 = toupper((unsigned char)c2);

  if (c1 >= '0' && c1 <= '9') {
    v1 = c1 - '0';
  } else if (c1 >= 'A' && c1 <= 'Z') {
    v1 = c1 - 'A' + 10;
  }

  if (c2 >= '0' && c2 <= '9') {
    v2 = c2 - '0';
  } else if (c2 >= 'A' && c2 <= 'Z') {
    v2 = c2 - 'A' + 10;
  }

  if (v1 < 0 || v2 < 0) {
    return -1;
  }

  return v1 * 36 + v2;
}

bool bbqr_base36_encode(int value, char *c1, char *c2) {
  if (value < 0 || value > 1295 || !c1 || !c2) {
    return false;
  }

  *c1 = BASE36_ALPHABET[value / 36];
  *c2 = BASE36_ALPHABET[value % 36];
  return true;
}

bool bbqr_parse_part(const char *data, size_t data_len, BBQrPart *part) {
  if (!data || !part || data_len < BBQR_HEADER_LEN) {
    return false;
  }

  // Check magic "B$"
  if (data[0] != 'B' || data[1] != '$') {
    return false;
  }

  // Extract and validate encoding
  char encoding = toupper((unsigned char)data[2]);
  if (!bbqr_is_valid_encoding(encoding)) {
    return false;
  }

  // Extract and validate file type
  char file_type = toupper((unsigned char)data[3]);
  if (!bbqr_is_valid_file_type(file_type)) {
    return false;
  }

  // Decode total parts (base36)
  int total = bbqr_base36_decode(data[4], data[5]);
  if (total < 1 || total > 1295) {
    return false;
  }

  // Decode part index (base36)
  int index = bbqr_base36_decode(data[6], data[7]);
  if (index < 0 || index >= total) {
    return false;
  }

  part->encoding = encoding;
  part->file_type = file_type;
  part->total = total;
  part->index = index;
  part->payload = data + BBQR_HEADER_LEN;
  part->payload_len = data_len - BBQR_HEADER_LEN;

  return true;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

// Helper: decode hex string to binary
static uint8_t *decode_hex(const char *hex, size_t hex_len, size_t *out_len) {
  if (hex_len % 2 != 0) {
    return NULL;
  }

  size_t bin_len = hex_len / 2;
  uint8_t *output = (uint8_t *)malloc(bin_len);
  if (!output) {
    return NULL;
  }

  for (size_t i = 0; i < bin_len; i++) {
    int v1 = hex_nibble(hex[i * 2]);
    int v2 = hex_nibble(hex[i * 2 + 1]);
    if (v1 < 0 || v2 < 0) {
      free(output);
      return NULL;
    }
    output[i] = (uint8_t)((v1 << 4) | v2);
  }

  *out_len = bin_len;
  return output;
}

uint8_t *bbqr_decode_payload(char encoding, const char *data, size_t data_len,
                             size_t *out_len) {
  if (!data || !out_len || data_len == 0) {
    return NULL;
  }

  encoding = toupper((unsigned char)encoding);

  if (encoding == BBQR_ENCODING_HEX) {
    // Hex decode
    return decode_hex(data, data_len, out_len);
  } else if (encoding == BBQR_ENCODING_BASE32) {
    // Base32 decode only
    size_t max_decoded = base32_decoded_len(data_len);
    uint8_t *decoded = (uint8_t *)malloc(max_decoded);
    if (!decoded) {
      return NULL;
    }

    if (!base32_decode(data, data_len, decoded, max_decoded, out_len)) {
      free(decoded);
      return NULL;
    }

    return decoded;
  } else if (encoding == BBQR_ENCODING_ZLIB) {
    // Base32 decode, then zlib decompress
    size_t max_decoded = base32_decoded_len(data_len);
    uint8_t *compressed = (uint8_t *)malloc(max_decoded);
    if (!compressed) {
      return NULL;
    }

    size_t compressed_len;
    if (!base32_decode(data, data_len, compressed, max_decoded,
                       &compressed_len)) {
      free(compressed);
      return NULL;
    }

    // Try to detect format: zlib-wrapped starts with 0x78 (CMF for deflate)
    // Raw deflate typically starts with block header bits
    size_t decompressed_len = 0;
    uint8_t *decompressed = NULL;

    if (compressed_len >= 2 && (compressed[0] & 0x0F) == 0x08) {
      // Looks like zlib header (CMF method = 8 = deflate)
      // Verify header checksum: (CMF*256 + FLG) % 31 == 0
      if ((compressed[0] * 256 + compressed[1]) % 31 == 0) {
        // Try zlib-wrapped decompression first
        decompressed = deflate_decompress_zlib_alloc(compressed, compressed_len,
                                                     &decompressed_len,
                                                     BBQR_MAX_DECOMPRESSED);
      }
    }

    if (!decompressed) {
      // Fall back to raw deflate (BBQr spec says raw deflate)
      decompressed = deflate_decompress_raw_alloc(
          compressed, compressed_len, &decompressed_len, BBQR_DECODE_WBITS,
          BBQR_MAX_DECOMPRESSED);
    }

    free(compressed);

    if (!decompressed) {
      return NULL;
    }

    *out_len = decompressed_len;
    return decompressed;
  }

  return NULL;
}

BBQrParts *bbqr_encode(const uint8_t *data, size_t data_len, char file_type,
                       int max_chars_per_qr) {
  if (!data || data_len == 0 || !bbqr_is_valid_file_type(file_type)) {
    return NULL;
  }

  // Minimum practical size
  if (max_chars_per_qr < BBQR_HEADER_LEN + 8) {
    return NULL;
  }

  int max_payload_per_part = max_chars_per_qr - BBQR_HEADER_LEN;

  // Use compression (raw deflate) only when it actually shrinks the data
  size_t compressed_len = 0;
  uint8_t *compressed = deflate_compress_raw_alloc(
      data, data_len, &compressed_len, BBQR_COMPRESS_WBITS);

  const uint8_t *to_encode = data;
  size_t to_encode_len = data_len;
  char encoding = BBQR_ENCODING_BASE32;
  if (compressed && compressed_len < data_len) {
    to_encode = compressed;
    to_encode_len = compressed_len;
    encoding = BBQR_ENCODING_ZLIB;
  }

  size_t encoded_len = base32_encoded_len(to_encode_len);
  if (encoded_len == 0) {
    free(compressed);
    return NULL;
  }

  // Calculate number of parts needed
  // Make payload size a multiple of 8 for base32 alignment
  int payload_per_part = (max_payload_per_part / 8) * 8;
  if (payload_per_part <= 0) {
    payload_per_part = 8;
  }

  size_t parts_needed = encoded_len / (size_t)payload_per_part +
                        (encoded_len % (size_t)payload_per_part != 0);
  if (parts_needed > 1295) {
    free(compressed);
    return NULL;
  }
  int num_parts = (int)parts_needed;

  // Recalculate payload per part to distribute evenly
  payload_per_part = (encoded_len + num_parts - 1) / num_parts;
  payload_per_part =
      ((payload_per_part + 7) / 8) * 8; // Round up to multiple of 8

  // Allocate parts structure
  BBQrParts *parts = (BBQrParts *)calloc(1, sizeof(BBQrParts));
  if (!parts) {
    free(compressed);
    return NULL;
  }

  parts->parts = (char **)calloc(num_parts, sizeof(char *));
  if (!parts->parts) {
    free(parts);
    free(compressed);
    return NULL;
  }

  parts->count = num_parts;
  parts->encoding = encoding;
  parts->file_type = file_type;

  if (encoded_len > SIZE_MAX - (size_t)num_parts * (BBQR_HEADER_LEN + 1)) {
    free(parts->parts);
    free(parts);
    free(compressed);
    return NULL;
  }
  size_t storage_len = encoded_len + (size_t)num_parts * (BBQR_HEADER_LEN + 1);
  parts->storage = (char *)malloc(storage_len);
  if (!parts->storage) {
    free(parts->parts);
    free(parts);
    free(compressed);
    return NULL;
  }

  // Generate headers and lay out all part strings in one allocation.
  size_t storage_offset = 0;
  char total_c1, total_c2;
  bbqr_base36_encode(num_parts, &total_c1, &total_c2);
  for (int i = 0; i < num_parts; i++) {
    size_t this_payload_len =
        part_payload_len(encoded_len, (size_t)payload_per_part, i);

    // Build header: B$ + encoding + file_type + total(2) + index(2)
    char index_c1, index_c2;
    bbqr_base36_encode(i, &index_c1, &index_c2);

    char *part = parts->storage + storage_offset;
    parts->parts[i] = part;
    part[0] = 'B';
    part[1] = '$';
    part[2] = encoding;
    part[3] = file_type;
    part[4] = total_c1;
    part[5] = total_c2;
    part[6] = index_c1;
    part[7] = index_c2;
    part[BBQR_HEADER_LEN + this_payload_len] = '\0';

    storage_offset += BBQR_HEADER_LEN + this_payload_len + 1;
  }

  bbqr_parts_writer_t writer = {
      .parts = parts,
      .part_index = 0,
      .payload_offset = 0,
      .payload_per_part = (size_t)payload_per_part,
      .encoded_len = encoded_len,
      .total_written = 0,
  };
  bool encoded =
      base32_encode_write(to_encode, to_encode_len, write_to_parts, &writer);
  free(compressed);
  if (!encoded || writer.total_written != encoded_len) {
    bbqr_parts_free(parts);
    return NULL;
  }

  return parts;
}

void bbqr_parts_free(BBQrParts *parts) {
  if (!parts) {
    return;
  }

  if (parts->parts) {
    free(parts->parts);
  }

  free(parts->storage);
  free(parts);
}
