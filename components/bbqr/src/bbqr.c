#include "bbqr.h"
#include "base32.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

// Include miniz for zlib compression
#include "miniz.h"

// Base36 alphabet (0-9, A-Z)
static const char BASE36_ALPHABET[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

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
    char h[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};

    // Convert hex pair to byte
    char c1 = h[0];
    char c2 = h[1];
    int v1 = -1, v2 = -1;

    if (c1 >= '0' && c1 <= '9')
      v1 = c1 - '0';
    else if (c1 >= 'A' && c1 <= 'F')
      v1 = c1 - 'A' + 10;
    else if (c1 >= 'a' && c1 <= 'f')
      v1 = c1 - 'a' + 10;

    if (c2 >= '0' && c2 <= '9')
      v2 = c2 - '0';
    else if (c2 >= 'A' && c2 <= 'F')
      v2 = c2 - 'A' + 10;
    else if (c2 >= 'a' && c2 <= 'f')
      v2 = c2 - 'a' + 10;

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
        decompressed =
            mz_uncompress_alloc(compressed, compressed_len, &decompressed_len);
      }
    }

    if (!decompressed) {
      // Fall back to raw deflate (BBQr spec says raw deflate)
      decompressed =
          mz_inflate_raw_alloc(compressed, compressed_len, &decompressed_len);
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

  // Try compression first (use raw deflate for BBQr)
  uint8_t *compressed = NULL;
  size_t compressed_len = 0;
  char *encoded_data = NULL;
  size_t encoded_len = 0;
  char encoding = BBQR_ENCODING_BASE32;

  compressed = mz_deflate_raw_alloc(data, data_len, &compressed_len);

  if (compressed && compressed_len < data_len) {
    // Compression helped - use Z encoding
    size_t max_encoded = base32_encoded_len(compressed_len);
    encoded_data = (char *)malloc(max_encoded + 1);
    if (encoded_data) {
      encoded_len = base32_encode(compressed, compressed_len, encoded_data,
                                  max_encoded + 1);
      if (encoded_len > 0) {
        encoding = BBQR_ENCODING_ZLIB;
      } else {
        free(encoded_data);
        encoded_data = NULL;
      }
    }
    free(compressed);
  } else {
    if (compressed) {
      free(compressed);
    }
  }

  // If compression didn't help or failed, use uncompressed base32
  if (!encoded_data) {
    size_t max_encoded = base32_encoded_len(data_len);
    encoded_data = (char *)malloc(max_encoded + 1);
    if (!encoded_data) {
      return NULL;
    }

    encoded_len = base32_encode(data, data_len, encoded_data, max_encoded + 1);
    if (encoded_len == 0) {
      free(encoded_data);
      return NULL;
    }
    encoding = BBQR_ENCODING_BASE32;
  }

  // Calculate number of parts needed
  // Make payload size a multiple of 8 for base32 alignment
  int payload_per_part = (max_payload_per_part / 8) * 8;
  if (payload_per_part <= 0) {
    payload_per_part = 8;
  }

  int num_parts = (encoded_len + payload_per_part - 1) / payload_per_part;
  if (num_parts > 1295) {
    free(encoded_data);
    return NULL;
  }
  if (num_parts < 1) {
    num_parts = 1;
  }

  // Recalculate payload per part to distribute evenly
  payload_per_part = (encoded_len + num_parts - 1) / num_parts;
  payload_per_part =
      ((payload_per_part + 7) / 8) * 8; // Round up to multiple of 8

  // Allocate parts structure
  BBQrParts *parts = (BBQrParts *)calloc(1, sizeof(BBQrParts));
  if (!parts) {
    free(encoded_data);
    return NULL;
  }

  parts->parts = (char **)calloc(num_parts, sizeof(char *));
  if (!parts->parts) {
    free(parts);
    free(encoded_data);
    return NULL;
  }

  parts->count = num_parts;
  parts->encoding = encoding;
  parts->file_type = file_type;

  // Generate each part
  size_t offset = 0;
  for (int i = 0; i < num_parts; i++) {
    size_t remaining = encoded_len - offset;
    size_t this_payload_len = (remaining > (size_t)payload_per_part)
                                  ? (size_t)payload_per_part
                                  : remaining;

    // Allocate part string (header + payload + null terminator)
    parts->parts[i] = (char *)malloc(BBQR_HEADER_LEN + this_payload_len + 1);
    if (!parts->parts[i]) {
      // Cleanup on failure
      for (int j = 0; j < i; j++) {
        free(parts->parts[j]);
      }
      free(parts->parts);
      free(parts);
      free(encoded_data);
      return NULL;
    }

    // Build header: B$ + encoding + file_type + total(2) + index(2)
    char total_c1, total_c2, index_c1, index_c2;
    bbqr_base36_encode(num_parts, &total_c1, &total_c2);
    bbqr_base36_encode(i, &index_c1, &index_c2);

    parts->parts[i][0] = 'B';
    parts->parts[i][1] = '$';
    parts->parts[i][2] = encoding;
    parts->parts[i][3] = file_type;
    parts->parts[i][4] = total_c1;
    parts->parts[i][5] = total_c2;
    parts->parts[i][6] = index_c1;
    parts->parts[i][7] = index_c2;

    // Copy payload
    memcpy(parts->parts[i] + BBQR_HEADER_LEN, encoded_data + offset,
           this_payload_len);
    parts->parts[i][BBQR_HEADER_LEN + this_payload_len] = '\0';

    offset += this_payload_len;
  }

  free(encoded_data);
  return parts;
}

void bbqr_parts_free(BBQrParts *parts) {
  if (!parts) {
    return;
  }

  if (parts->parts) {
    for (int i = 0; i < parts->count; i++) {
      if (parts->parts[i]) {
        free(parts->parts[i]);
      }
    }
    free(parts->parts);
  }

  free(parts);
}
