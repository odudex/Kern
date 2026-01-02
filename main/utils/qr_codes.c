#include "qr_codes.h"
#include "../../components/cUR/src/ur_decoder.h"
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// QR capacity arrays (limited to version 20)
static const int QR_CAPACITY_BYTE[] = {17,  32,  53,  78,  106, 134, 154,
                                       192, 230, 271, 321, 367, 425, 458,
                                       520, 586, 644, 718, 792, 858};

static const int QR_CAPACITY_ALPHANUMERIC[] = {
    25,  47,  77,  114, 154, 195, 224, 279,  335,  395,
    468, 535, 619, 667, 758, 854, 938, 1046, 1153, 1249};

#define QR_CAPACITY_SIZE 20

// Helper function prototypes
static int detect_format(const char *data, BBQrCode **bbqr);
static bool parse_pmofn_qr_part(const char *data, char **part, int *index,
                                int *total);
static bool starts_with_case_insensitive(const char *str, const char *prefix);
static int max_qr_bytes(int max_width, const char *encoding);
static void find_min_num_parts(const char *data, size_t data_len, int max_width,
                               int qr_format, int *num_parts, int *part_size);
static bool add_part(QRPartParser *parser, int index, const char *data,
                     size_t data_len);
static int compare_parts(const void *a, const void *b);

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
    free(parser->bbqr->payload);
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
  // Resize if needed
  if (parser->parts_count >= parser->parts_capacity) {
    int new_capacity = parser->parts_capacity * 2;
    QRPart **new_parts =
        (QRPart **)realloc(parser->parts, new_capacity * sizeof(QRPart *));
    if (!new_parts)
      return false;
    parser->parts = new_parts;
    parser->parts_capacity = new_capacity;
  }

  // Check if part already exists
  for (int i = 0; i < parser->parts_count; i++) {
    if (parser->parts[i]->index == index) {
      // Update existing part
      free(parser->parts[i]->data);
      parser->parts[i]->data = (char *)malloc(data_len + 1);
      if (!parser->parts[i]->data)
        return false;
      memcpy(parser->parts[i]->data, data, data_len);
      parser->parts[i]->data[data_len] = '\0';
      parser->parts[i]->data_len = data_len;
      return true;
    }
  }

  // Add new part
  QRPart *part = (QRPart *)calloc(1, sizeof(QRPart));
  if (!part)
    return false;

  part->index = index;
  part->data = (char *)malloc(data_len + 1);
  if (!part->data) {
    free(part);
    return false;
  }
  memcpy(part->data, data, data_len);
  part->data[data_len] = '\0';
  part->data_len = data_len;

  parser->parts[parser->parts_count++] = part;
  return true;
}

int qr_parser_parse(QRPartParser *parser, const char *data) {
  return qr_parser_parse_with_len(parser, data, strlen(data));
}

int qr_parser_parse_with_len(QRPartParser *parser, const char *data,
                             size_t data_len) {
  if (parser->format == -1) {
    parser->format = detect_format(data, &parser->bbqr);
  }

  if (parser->format == FORMAT_NONE) {
    add_part(parser, 1, data, data_len);
    parser->total = 1;
  } else if (parser->format == FORMAT_PMOFN) {
    char *part = NULL;
    int index, total;
    if (parse_pmofn_qr_part(data, &part, &index, &total)) {
      add_part(parser, index, part, strlen(part));
      parser->total = total;
      free(part);
      return index - 1;
    }
  } else if (parser->format == FORMAT_UR) {
    // Create UR decoder if not exists
    if (!parser->ur_decoder) {
      parser->ur_decoder = ur_decoder_new();
      if (!parser->ur_decoder) {
        return -1;
      }
    }

    ur_decoder_t *decoder = (ur_decoder_t *)parser->ur_decoder;
    if (ur_decoder_receive_part(decoder, data)) {
      size_t processed = ur_decoder_processed_parts_count(decoder);
      return (int)processed - 1;
    }
  } else if (parser->format == FORMAT_BBQR) {
    // TODO: Implement BBQR format parsing
    // Would need to parse BBQR header and extract part data
    /*
    char *part;
    int index, total;
    if (parse_bbqr(data, &part, &index, &total)) {
        add_part(parser, index, part, strlen(part));
        parser->total = total;
        free(part);
        return index;
    }
    */
  }

  return -1;
}

bool qr_parser_is_complete(QRPartParser *parser) {
  if (parser->format == FORMAT_UR && parser->ur_decoder) {
    ur_decoder_t *decoder = (ur_decoder_t *)parser->ur_decoder;
    return ur_decoder_is_complete(decoder) && ur_decoder_is_success(decoder);
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
  if (parser->format == FORMAT_UR && parser->ur_decoder) {
    // For UR format, return a special marker string that indicates
    // the result needs to be extracted using qr_parser_get_ur_result()
    // This is because UR results are binary CBOR data, not text strings
    const char *marker = "UR_RESULT";
    char *result = strdup(marker);
    if (result_len) {
      *result_len = strlen(marker);
    }
    return result;
  }

  if (parser->format == FORMAT_BBQR) {
    // TODO: Decode BBQR and return result
    return NULL;
  }

  // Sort parts by index
  qsort(parser->parts, parser->parts_count, sizeof(QRPart *), compare_parts);

  // Calculate total length
  size_t total_len = 0;
  for (int i = 0; i < parser->parts_count; i++) {
    total_len += parser->parts[i]->data_len;
  }

  // Combine parts
  char *result = (char *)malloc(total_len + 1);
  if (!result)
    return NULL;

  size_t offset = 0;
  for (int i = 0; i < parser->parts_count; i++) {
    memcpy(result + offset, parser->parts[i]->data, parser->parts[i]->data_len);
    offset += parser->parts[i]->data_len;
  }
  result[total_len] = '\0';

  if (result_len)
    *result_len = total_len;
  return result;
}

static bool starts_with_case_insensitive(const char *str, const char *prefix) {
  while (*prefix) {
    if (tolower(*str) != tolower(*prefix))
      return false;
    str++;
    prefix++;
  }
  return true;
}

static int detect_format(const char *data, BBQrCode **bbqr) {
  if (data[0] == 'p') {
    // Check for "pXofY " format
    const char *space = strchr(data, ' ');
    if (space) {
      char header[32];
      size_t header_len = space - data;
      if (header_len < sizeof(header)) {
        strncpy(header, data, header_len);
        header[header_len] = '\0';

        const char *of_pos = strstr(header, "of");
        if (of_pos && of_pos > header + 1) {
          // Check if number before "of"
          bool is_digit = true;
          for (const char *p = header + 1; p < of_pos; p++) {
            if (!isdigit((unsigned char)*p)) {
              is_digit = false;
              break;
            }
          }
          if (is_digit)
            return FORMAT_PMOFN;
        }
      }
    }
  } else if (starts_with_case_insensitive(data, "ur:")) {
    return FORMAT_UR;
  } else if (strncmp(data, "B$", 2) == 0) {
    // TODO: Implement BBQR format detection
    // Would need to check known encodings and file types
    /*
    if (is_known_filetype(data[3]) && is_known_encoding(data[2])) {
        *bbqr = create_bbqr(NULL, data[2], data[3]);
        return FORMAT_BBQR;
    }
    */
  }

  return FORMAT_NONE;
}

static bool parse_pmofn_qr_part(const char *data, char **part, int *index,
                                int *total) {
  const char *of_pos = strstr(data, "of");
  const char *space_pos = strchr(data, ' ');

  if (!of_pos || !space_pos || of_pos >= space_pos)
    return false;

  // Parse index (skip 'p')
  *index = atoi(data + 1);

  // Parse total
  *total = atoi(of_pos + 2);

  // Extract part data (after space)
  size_t part_len = strlen(space_pos + 1);
  *part = (char *)malloc(part_len + 1);
  if (!*part)
    return false;
  strcpy(*part, space_pos + 1);

  return true;
}

static int max_qr_bytes(int max_width, const char *encoding) {
  max_width -= 2; // Subtract frame width
  int qr_version = (max_width - 17) / 4;

  if (qr_version < 1)
    qr_version = 1;
  if (qr_version > QR_CAPACITY_SIZE)
    qr_version = QR_CAPACITY_SIZE;

  const int *capacity_list = (strcmp(encoding, "alphanumeric") == 0)
                                 ? QR_CAPACITY_ALPHANUMERIC
                                 : QR_CAPACITY_BYTE;

  return capacity_list[qr_version - 1];
}

static void find_min_num_parts(const char *data, size_t data_len, int max_width,
                               int qr_format, int *num_parts, int *part_size) {
  const char *encoding = (qr_format == FORMAT_BBQR) ? "alphanumeric" : "byte";
  int qr_capacity = max_qr_bytes(max_width, encoding);

  if (qr_format == FORMAT_PMOFN) {
    int ps = qr_capacity - PMOFN_PREFIX_LENGTH_1D;
    *num_parts = (data_len + ps - 1) / ps;

    if (*num_parts > 9) {
      ps = qr_capacity - PMOFN_PREFIX_LENGTH_2D;
      *num_parts = (data_len + ps - 1) / ps;
    }

    *part_size = (data_len + *num_parts - 1) / *num_parts;
  } else if (qr_format == FORMAT_UR) {
    // TODO: Implement UR format calculation
    // Similar to Python version but adapted for C
    qr_capacity -= UR_GENERIC_PREFIX_LENGTH;
    qr_capacity -= (UR_CBOR_PREFIX_LEN + UR_BYTEWORDS_CRC_LEN) * 2;
    qr_capacity = (qr_capacity > UR_MIN_FRAGMENT_LENGTH)
                      ? qr_capacity
                      : UR_MIN_FRAGMENT_LENGTH;

    size_t adjusted_len = data_len * 2; // Bytewords encoding doubles length
    *num_parts = (adjusted_len + qr_capacity - 1) / qr_capacity;
    *part_size = data_len / *num_parts;
    *part_size = (*part_size > UR_MIN_FRAGMENT_LENGTH) ? *part_size
                                                       : UR_MIN_FRAGMENT_LENGTH;
  } else if (qr_format == FORMAT_BBQR) {
    // TODO: Implement BBQR format calculation
    int max_part_size = qr_capacity - BBQR_PREFIX_LENGTH;
    if ((int)data_len < max_part_size) {
      *num_parts = 1;
      *part_size = data_len;
      return;
    }

    max_part_size = (max_part_size / 8) * 8;
    *num_parts = (data_len + max_part_size - 1) / max_part_size;
    *part_size = data_len / *num_parts;
    *part_size = ((*part_size + 7) / 8) * 8;

    if (*part_size > max_part_size) {
      (*num_parts)++;
      *part_size = data_len / *num_parts;
      *part_size = ((*part_size + 7) / 8) * 8;
    }
  }
}

bool qr_parser_get_ur_result(QRPartParser *parser, const char **ur_type_out,
                             const uint8_t **cbor_data_out,
                             size_t *cbor_len_out) {
  if (!parser || parser->format != FORMAT_UR || !parser->ur_decoder) {
    return false;
  }

  ur_decoder_t *decoder = (ur_decoder_t *)parser->ur_decoder;
  if (!ur_decoder_is_complete(decoder) || !ur_decoder_is_success(decoder)) {
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

int get_qr_size(const char *qr_code) {
  int len = strlen(qr_code);
  int size = (int)sqrt(len * 8);
  return size;
}
