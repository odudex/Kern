#include "base32.h"
#include <ctype.h>
#include <string.h>

// RFC 4648 Base32 alphabet
static const char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// Lookup table for decoding (maps ASCII to 5-bit values, -1 for invalid)
static const int8_t BASE32_DECODE_TABLE[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-15
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-31
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, // 32-47
    -1, -1, 26, 27, 28, 29, 30, 31,
    -1, -1, -1, -1, -1, -1, -1, -1, // 48-63  ('2'-'7')
    -1, 0,  1,  2,  3,  4,  5,  6,
    7,  8,  9,  10, 11, 12, 13, 14, // 64-79  ('A'-'O')
    15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, -1, -1, -1, -1, -1, // 80-95  ('P'-'Z')
    -1, 0,  1,  2,  3,  4,  5,  6,
    7,  8,  9,  10, 11, 12, 13, 14, // 96-111 ('a'-'o')
    15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, -1, -1, -1, -1, -1 // 112-127('p'-'z')
};

size_t base32_encoded_len(size_t input_len) {
  // BBQr omits RFC 4648 padding, so partial groups use 2, 4, 5, or 7 chars.
  static const uint8_t chars_per_remainder[] = {0, 2, 4, 5, 7};
  size_t full_groups = input_len / 5;
  size_t remainder_chars = chars_per_remainder[input_len % 5];
  if (full_groups > (SIZE_MAX - remainder_chars) / 8) {
    return 0;
  }
  return full_groups * 8 + remainder_chars;
}

size_t base32_decoded_len(size_t input_len) {
  // Each 8 characters becomes 5 bytes (maximum)
  return (input_len * 5) / 8;
}

bool base32_encode_write(const uint8_t *input, size_t input_len,
                         base32_write_fn write, void *context) {
  if (!input || !write || input_len == 0) {
    return false;
  }

  size_t in_idx = 0;

  // Process input in groups of 5 bytes -> 8 chars
  while (in_idx < input_len) {
    // Load up to 5 bytes into a 40-bit buffer (left-aligned)
    uint64_t buffer = 0;
    int bytes_in_group = 0;

    for (int i = 0; i < 5 && in_idx < input_len; i++) {
      buffer |= ((uint64_t)input[in_idx++]) << (32 - i * 8);
      bytes_in_group++;
    }

    // 1 byte (8 bits) -> 2 chars
    // 2 bytes (16 bits) -> 4 chars
    // 3 bytes (24 bits) -> 5 chars
    // 4 bytes (32 bits) -> 7 chars
    // 5 bytes (40 bits) -> 8 chars
    static const int chars_per_bytes[] = {0, 2, 4, 5, 7, 8};
    int num_chars = chars_per_bytes[bytes_in_group];
    char encoded[8];

    for (int i = 0; i < num_chars; i++) {
      int idx = (buffer >> (35 - i * 5)) & 0x1F;
      encoded[i] = BASE32_ALPHABET[idx];
    }

    if (!write(context, encoded, (size_t)num_chars)) {
      return false;
    }
  }

  return true;
}

typedef struct {
  char *output;
  size_t output_size;
  size_t output_len;
} base32_buffer_writer_t;

static bool write_to_buffer(void *context, const char *data, size_t len) {
  base32_buffer_writer_t *writer = (base32_buffer_writer_t *)context;
  if (len > writer->output_size - writer->output_len - 1) {
    return false;
  }

  memcpy(writer->output + writer->output_len, data, len);
  writer->output_len += len;
  return true;
}

size_t base32_encode(const uint8_t *input, size_t input_len, char *output,
                     size_t output_size) {
  if (!input || !output || input_len == 0) {
    return 0;
  }

  size_t encoded_len = base32_encoded_len(input_len);
  if (output_size < encoded_len + 1) {
    return 0;
  }

  base32_buffer_writer_t writer = {
      .output = output,
      .output_size = output_size,
      .output_len = 0,
  };
  if (!base32_encode_write(input, input_len, write_to_buffer, &writer)) {
    return 0;
  }

  output[writer.output_len] = '\0';
  return writer.output_len;
}

bool base32_decode(const char *input, size_t input_len, uint8_t *output,
                   size_t output_size, size_t *out_len) {
  if (!input || !output || !out_len || input_len == 0) {
    return false;
  }

  // Skip padding characters at the end
  while (input_len > 0 && input[input_len - 1] == '=') {
    input_len--;
  }

  if (input_len == 0) {
    *out_len = 0;
    return true;
  }

  // Calculate expected output length based on input chars (upper bound).
  // Note: if input contains whitespace, actual output will be smaller
  // since whitespace chars are skipped but counted in input_len.
  size_t total_bits = input_len * 5;
  size_t expected_bytes = total_bits / 8;

  if (output_size < expected_bytes) {
    return false;
  }

  size_t out_idx = 0;
  uint32_t buffer = 0;
  int bits_in_buffer = 0;

  for (size_t i = 0; i < input_len; i++) {
    unsigned char c = (unsigned char)input[i];

    // Skip whitespace
    if (isspace(c)) {
      continue;
    }

    // Validate character
    if (c >= 128 || BASE32_DECODE_TABLE[c] < 0) {
      return false;
    }

    // Add 5 bits to buffer
    buffer = (buffer << 5) | (uint32_t)BASE32_DECODE_TABLE[c];
    bits_in_buffer += 5;

    // Extract bytes when we have 8 or more bits
    while (bits_in_buffer >= 8) {
      bits_in_buffer -= 8;
      output[out_idx++] = (uint8_t)(buffer >> bits_in_buffer);
      buffer &= (1u << bits_in_buffer) - 1;
    }
  }

  // Don't output partial bytes from leftover bits
  *out_len = out_idx;
  return true;
}
