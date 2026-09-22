#include "parser.h"
#include "../../components/bbqr/src/bbqr.h"
#include "../../components/cUR/src/ur_decoder.h"
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Helper function prototypes
static int detect_format(const char *data, size_t data_len, BBQrCode **bbqr);
static bool parse_pmofn_qr_part(const char *data, size_t data_len,
                                const char **part, size_t *part_len, int *index,
                                int *total);
static bool starts_with_case_insensitive(const char *str, const char *prefix);
static bool add_part(QRPartParser *parser, int index, const char *data,
                     size_t data_len);
static int compare_parts(const void *a, const void *b);

static int fail_parser(QRPartParser *parser) {
  parser->failed = true;
  return -1;
}

// Allocation failures are terminal like any other: a scan that silently drops
// frames under memory pressure would hide the exhaustion instead of showing it.
static bool fail_alloc(QRPartParser *parser) {
  parser->alloc_failed = true;
  parser->failed = true;
  return false;
}

static bool fail_too_large(QRPartParser *parser) {
  parser->too_large = true;
  parser->failed = true;
  return false;
}

// BBQr parts have equal lengths except for the shorter last part. This is a
// lower bound even if the last part arrives first; PMOFN has no such guarantee.
static bool sequence_exceeds_budget(int total, size_t part_len) {
  return total > 1 &&
         part_len > QR_PARSER_MAX_STORED_BYTES / (size_t)(total - 1);
}

QRPartParser *qr_parser_create(void) {
  QRPartParser *parser = (QRPartParser *)calloc(1, sizeof(QRPartParser));
  if (!parser)
    return NULL;

  parser->parts_capacity = 10;
  parser->parts = (QRPart **)calloc(parser->parts_capacity, sizeof(QRPart *));
  if (!parser->parts) {
    free(parser);
    return NULL;
  }

  parser->total = -1;
  parser->format = -1;
  return parser;
}

void qr_parser_destroy(QRPartParser *parser) {
  if (!parser)
    return;

  if (parser->parts) {
    for (int i = 0; i < parser->parts_count; i++) {
      if (parser->parts[i]) {
        free(parser->parts[i]->data);
        free(parser->parts[i]);
      }
    }
    free(parser->parts);
  }

  if (parser->bbqr) {
    free(parser->bbqr);
  }

  if (parser->ur_decoder) {
    ur_decoder_free((ur_decoder_t *)parser->ur_decoder);
    parser->ur_decoder = NULL;
  }

  free(parser);
}

int qr_parser_parsed_count(QRPartParser *parser) {
  if (parser->format == FORMAT_UR && parser->ur_decoder) {
    ur_decoder_t *decoder = (ur_decoder_t *)parser->ur_decoder;
    return (int)ur_decoder_processed_parts_count(decoder);
  }
  return parser->parts_count;
}

int qr_parser_processed_parts_count(QRPartParser *parser) {
  if (parser->format == FORMAT_UR && parser->ur_decoder) {
    ur_decoder_t *decoder = (ur_decoder_t *)parser->ur_decoder;
    return (int)ur_decoder_processed_parts_count(decoder);
  }
  return parser->parts_count;
}

int qr_parser_total_count(QRPartParser *parser) {
  if (parser->format == FORMAT_UR && parser->ur_decoder) {
    ur_decoder_t *decoder = (ur_decoder_t *)parser->ur_decoder;
    size_t expected = ur_decoder_expected_part_count(decoder);
    return expected > 0 ? (int)expected : 1;
  }
  return parser->total;
}

static bool add_part(QRPartParser *parser, int index, const char *data,
                     size_t data_len) {
  // Check if part already exists
  for (int i = 0; i < parser->parts_count; i++) {
    if (parser->parts[i]->index == index) {
      if (parser->parts[i]->data_len == data_len &&
          memcmp(parser->parts[i]->data, data, data_len) == 0) {
        return true;
      }
      // Update existing part
      size_t retained_bytes = parser->stored_bytes - parser->parts[i]->data_len;
      if (data_len > QR_PARSER_MAX_STORED_BYTES - retained_bytes) {
        return fail_too_large(parser);
      }
      char *replacement = (char *)malloc(data_len + 1);
      if (!replacement) {
        return fail_alloc(parser);
      }
      memcpy(replacement, data, data_len);
      replacement[data_len] = '\0';
      free(parser->parts[i]->data);
      parser->parts[i]->data = replacement;
      parser->parts[i]->data_len = data_len;
      parser->stored_bytes = retained_bytes + data_len;
      return true;
    }
  }

  if (parser->parts_count >= QR_PARSER_MAX_MULTIPART_PARTS ||
      data_len > QR_PARSER_MAX_STORED_BYTES - parser->stored_bytes) {
    return fail_too_large(parser);
  }

  // Resize if needed
  if (parser->parts_count >= parser->parts_capacity) {
    int new_capacity = parser->parts_capacity * 2;
    if (new_capacity > QR_PARSER_MAX_MULTIPART_PARTS) {
      new_capacity = QR_PARSER_MAX_MULTIPART_PARTS;
    }
    QRPart **new_parts =
        (QRPart **)realloc(parser->parts, new_capacity * sizeof(QRPart *));
    if (!new_parts) {
      return fail_alloc(parser);
    }
    parser->parts = new_parts;
    parser->parts_capacity = new_capacity;
  }

  // Add new part
  QRPart *part = (QRPart *)calloc(1, sizeof(QRPart));
  if (!part) {
    return fail_alloc(parser);
  }

  part->index = index;
  part->data = (char *)malloc(data_len + 1);
  if (!part->data) {
    free(part);
    return fail_alloc(parser);
  }
  memcpy(part->data, data, data_len);
  part->data[data_len] = '\0';
  part->data_len = data_len;

  parser->parts[parser->parts_count++] = part;
  parser->stored_bytes += data_len;
  return true;
}

int qr_parser_parse(QRPartParser *parser, const char *data) {
  return qr_parser_parse_with_len(parser, data, strlen(data));
}

int qr_parser_parse_with_len(QRPartParser *parser, const char *data,
                             size_t data_len) {
  if (!parser || !data || parser->failed) {
    return -1;
  }

  if (parser->format == -1) {
    parser->format = detect_format(data, data_len, &parser->bbqr);
  }

  if (parser->format == FORMAT_NONE) {
    if (!add_part(parser, 1, data, data_len)) {
      return -1;
    }
    parser->total = 1;
  } else if (parser->format == FORMAT_PMOFN) {
    const char *part = NULL;
    size_t part_len = 0;
    int index, total;
    if (!parse_pmofn_qr_part(data, data_len, &part, &part_len, &index,
                             &total)) {
      return fail_parser(parser);
    }
    if (parser->total != -1 && parser->total != total) {
      return fail_parser(parser);
    }
    if (total > QR_PARSER_MAX_MULTIPART_PARTS) {
      fail_too_large(parser);
      return -1;
    }
    if (!add_part(parser, index, part, part_len)) {
      return -1;
    }
    parser->total = total;
    return index - 1;
  } else if (parser->format == FORMAT_UR) {
    // Create UR decoder if not exists
    if (!parser->ur_decoder) {
      parser->ur_decoder = ur_decoder_new();
      if (!parser->ur_decoder) {
        return -1;
      }
    }

    ur_decoder_t *decoder = (ur_decoder_t *)parser->ur_decoder;
    ur_decoder_state_t state = ur_decoder_receive_part(decoder, data);
    if (state == UR_DECODER_OK) {
      return 0; // Single-part UR, complete immediately
    }
    if (state == UR_DECODER_PROCESSING) {
      size_t processed = ur_decoder_processed_parts_count(decoder);
      return (int)processed - 1;
    }
  } else if (parser->format == FORMAT_BBQR) {
    BBQrPart part;
    if (!parser->bbqr || !bbqr_parse_part(data, data_len, &part)) {
      return fail_parser(parser);
    }
    if ((parser->total != -1 && parser->total != part.total) ||
        parser->bbqr->encoding != part.encoding ||
        parser->bbqr->file_type != part.file_type) {
      return fail_parser(parser);
    }
    if (part.total > QR_PARSER_MAX_MULTIPART_PARTS ||
        sequence_exceeds_budget(part.total, part.payload_len)) {
      fail_too_large(parser);
      return -1;
    }
    // Store payload (payload_len may differ from strlen if binary)
    if (!add_part(parser, part.index, part.payload, part.payload_len)) {
      return -1;
    }
    parser->total = part.total;
    return part.index;
  }

  return -1;
}

bool qr_parser_is_failed(QRPartParser *parser) {
  if (!parser) {
    return false;
  }
  if (parser->failed) {
    return true;
  }
  if (parser->format == FORMAT_UR && parser->ur_decoder) {
    ur_decoder_state_t state =
        ur_decoder_get_state((ur_decoder_t *)parser->ur_decoder);
    return ur_decoder_state_is_terminal(state) && state != UR_DECODER_OK;
  }
  return false;
}

bool qr_parser_is_complete(QRPartParser *parser) {
  if (!parser || parser->failed) {
    return false;
  }
  if (parser->format == FORMAT_UR && parser->ur_decoder) {
    ur_decoder_t *decoder = (ur_decoder_t *)parser->ur_decoder;
    return ur_decoder_get_state(decoder) == UR_DECODER_OK;
  }

  if (parser->total == -1)
    return false;
  if (parser->parts_count != parser->total)
    return false;

  // Check if we have all expected indices
  int start_index =
      (parser->format == FORMAT_PMOFN || parser->format == FORMAT_NONE) ? 1 : 0;
  int expected_sum = 0;
  for (int i = start_index; i < start_index + parser->total; i++) {
    expected_sum += i;
  }

  int actual_sum = 0;
  for (int i = 0; i < parser->parts_count; i++) {
    actual_sum += parser->parts[i]->index;
  }

  return actual_sum == expected_sum;
}

static int compare_parts(const void *a, const void *b) {
  QRPart *part_a = *(QRPart **)a;
  QRPart *part_b = *(QRPart **)b;
  return part_a->index - part_b->index;
}

char *qr_parser_result(QRPartParser *parser, size_t *result_len) {
  if (result_len)
    *result_len = 0;
  if (!parser || parser->failed) {
    return NULL;
  }
  if (parser->format == FORMAT_UR && parser->ur_decoder) {
    // For UR format, return a special marker string that indicates
    // the result needs to be extracted using qr_parser_get_ur_result()
    // This is because UR results are binary CBOR data, not text strings
    const char *marker = "UR_RESULT";
    char *result = strdup(marker);
    if (!result) {
      fail_alloc(parser);
      return NULL;
    }
    if (result_len) {
      *result_len = strlen(marker);
    }
    return result;
  }

  // add_part maintains stored_bytes, including replacements and duplicates.
  qsort(parser->parts, parser->parts_count, sizeof(QRPart *), compare_parts);
  char *result = malloc(parser->stored_bytes + 1);
  if (!result) {
    fail_alloc(parser);
    return NULL;
  }

  size_t len = 0;
  for (int i = 0; i < parser->parts_count; i++) {
    memcpy(result + len, parser->parts[i]->data, parser->parts[i]->data_len);
    len += parser->parts[i]->data_len;
  }
  result[len] = '\0';

  if (parser->format == FORMAT_BBQR) {
    size_t decoded_len = 0;
    uint8_t *decoded =
        bbqr_decode_payload(parser->bbqr->encoding, result, len, &decoded_len);
    free(result);
    if (!decoded)
      return NULL;

    // The decoder reserves a terminator. Transfer its allocation directly:
    // growing it here can copy the entire result under the secure allocator.
    result = (char *)decoded;
    len = decoded_len;
  }

  if (result_len)
    *result_len = len;
  return result;
}

static bool starts_with_case_insensitive(const char *str, const char *prefix) {
  while (*prefix) {
    if (tolower((unsigned char)*str) != tolower((unsigned char)*prefix))
      return false;
    str++;
    prefix++;
  }
  return true;
}

static int detect_format(const char *data, size_t data_len, BBQrCode **bbqr) {
  if (data_len > 1 && data[0] == 'p') {
    // Recognize a prospective pMofN header even when an integer is malformed,
    // so it is rejected rather than silently treated as plain text.
    size_t offset = 1;
    if (offset < data_len && (data[offset] == '+' || data[offset] == '-')) {
      offset++;
    }
    size_t digits_start = offset;
    while (offset < data_len && isdigit((unsigned char)data[offset])) {
      offset++;
    }
    if (offset > digits_start && offset + 1 < data_len && data[offset] == 'o' &&
        data[offset + 1] == 'f' &&
        memchr(data + offset + 2, ' ', data_len - offset - 2) != NULL) {
      return FORMAT_PMOFN;
    }
  } else if (data_len >= 3 && starts_with_case_insensitive(data, "ur:")) {
    return FORMAT_UR;
  } else if (data_len >= BBQR_HEADER_LEN && data[0] == 'B' && data[1] == '$') {
    // Validate BBQr header (convert to uppercase for validation)
    char encoding = toupper((unsigned char)data[2]);
    char file_type = toupper((unsigned char)data[3]);
    if (bbqr_is_valid_encoding(encoding) &&
        bbqr_is_valid_file_type(file_type)) {
      // Create BBQrCode structure
      *bbqr = (BBQrCode *)calloc(1, sizeof(BBQrCode));
      if (*bbqr) {
        (*bbqr)->encoding = encoding;
        (*bbqr)->file_type = file_type;
      }
      return FORMAT_BBQR;
    }
  }

  return FORMAT_NONE;
}

static bool parse_positive_decimal(const char **cursor, const char *end,
                                   int *value) {
  const char *p = *cursor;
  if (p == end || !isdigit((unsigned char)*p)) {
    return false;
  }

  int parsed = 0;
  do {
    int digit = *p - '0';
    if (parsed > (INT_MAX - digit) / 10) {
      return false;
    }
    parsed = parsed * 10 + digit;
    p++;
  } while (p < end && isdigit((unsigned char)*p));

  if (parsed == 0) {
    return false;
  }
  *cursor = p;
  *value = parsed;
  return true;
}

static bool parse_pmofn_qr_part(const char *data, size_t data_len,
                                const char **part, size_t *part_len, int *index,
                                int *total) {
  const char *cursor = data;
  const char *end = data + data_len;
  if (cursor == end || *cursor++ != 'p' ||
      !parse_positive_decimal(&cursor, end, index) || end - cursor < 2 ||
      cursor[0] != 'o' || cursor[1] != 'f') {
    return false;
  }
  cursor += 2;
  if (!parse_positive_decimal(&cursor, end, total) || cursor == end ||
      *cursor++ != ' ' || *index > *total) {
    return false;
  }

  *part = cursor;
  *part_len = (size_t)(end - cursor);
  return true;
}

bool qr_parser_get_ur_result(QRPartParser *parser, const char **ur_type_out,
                             const uint8_t **cbor_data_out,
                             size_t *cbor_len_out) {
  if (!parser || parser->format != FORMAT_UR || !parser->ur_decoder) {
    return false;
  }

  ur_decoder_t *decoder = (ur_decoder_t *)parser->ur_decoder;
  if (ur_decoder_get_state(decoder) != UR_DECODER_OK) {
    return false;
  }

  ur_result_t *result = ur_decoder_get_result(decoder);
  if (!result) {
    return false;
  }

  if (ur_type_out) {
    *ur_type_out = result->type;
  }
  if (cbor_data_out) {
    *cbor_data_out = result->cbor_data;
  }
  if (cbor_len_out) {
    *cbor_len_out = result->cbor_len;
  }

  return true;
}

int qr_parser_get_format(QRPartParser *parser) {
  if (!parser) {
    return FORMAT_NONE;
  }
  return parser->format;
}

char qr_parser_get_bbqr_file_type(QRPartParser *parser) {
  if (parser && parser->format == FORMAT_BBQR && parser->bbqr) {
    return parser->bbqr->file_type;
  }
  return 0;
}

int get_qr_size(const char *qr_code) {
  int len = strlen(qr_code);
  int size = (int)sqrt(len * 8);
  return size;
}
