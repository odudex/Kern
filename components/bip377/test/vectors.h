/* Loads the BIP-377 test vector files: a JSON object holding one `vectors`
 * array of flat objects. Only what those files use is parsed. */

#ifndef BIP377_TEST_VECTORS_H
#define BIP377_TEST_VECTORS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VECTOR_NAME_MAX 96

typedef struct {
  char name[VECTOR_NAME_MAX];
  bool is_request;
  bool decode_only;
  bool decode_error;
  uint8_t *bytes; /* exactly `len` bytes, so a sanitizer sees an overread */
  size_t len;
} vector_t;

static const char *const VECTOR_FILES[] = {
    "get_info",
    "get_keys",
    "register_descriptor",
    "unregister_descriptor",
    "address_verification",
    "signing",
    "errors",
    "versioning",
    "invalid",
};
#define VECTOR_FILE_COUNT (sizeof(VECTOR_FILES) / sizeof(VECTOR_FILES[0]))

typedef struct {
  const char *p;
  const char *end;
  bool failed;
} json_t;

static void json_skip_space(json_t *j) {
  while (j->p < j->end && strchr(" \t\r\n", *j->p))
    j->p++;
}

static bool json_take(json_t *j, char c) {
  json_skip_space(j);
  if (j->p < j->end && *j->p == c) {
    j->p++;
    return true;
  }
  return false;
}

/* Copies a string value to `out` (optional), escapes left as they are */
static void json_string(json_t *j, char *out, size_t out_size) {
  size_t n = 0;
  if (!json_take(j, '"')) {
    j->failed = true;
    return;
  }
  while (j->p < j->end && *j->p != '"') {
    if (*j->p == '\\' && j->p + 1 < j->end) {
      j->p++;
    }
    if (out && n + 1 < out_size)
      out[n++] = *j->p;
    j->p++;
  }
  if (out && out_size)
    out[n] = '\0';
  if (j->p >= j->end)
    j->failed = true;
  else
    j->p++;
}

static bool json_literal(json_t *j, const char *word) {
  size_t len = strlen(word);
  json_skip_space(j);
  if ((size_t)(j->end - j->p) >= len && memcmp(j->p, word, len) == 0) {
    j->p += len;
    return true;
  }
  return false;
}

static int hex_digit(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

static uint8_t *hex_decode(const char *hex, size_t *len_out) {
  size_t hex_len = strlen(hex);
  if (hex_len % 2)
    return NULL;
  uint8_t *bytes = malloc(hex_len / 2 ? hex_len / 2 : 1);
  if (!bytes)
    return NULL;
  for (size_t i = 0; i < hex_len / 2; i++) {
    int hi = hex_digit(hex[2 * i]);
    int lo = hex_digit(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      free(bytes);
      return NULL;
    }
    bytes[i] = (uint8_t)(hi << 4 | lo);
  }
  *len_out = hex_len / 2;
  return bytes;
}

static void json_vector(json_t *j, char *text, size_t text_size, vector_t *v) {
  bool has_name = false, has_direction = false, has_hex = false;
  bool has_decode_only = false;
  memset(v, 0, sizeof(*v));
  if (!json_take(j, '{')) {
    j->failed = true;
    return;
  }
  do {
    char key[32];
    json_string(j, key, sizeof(key));
    if (j->failed || !json_take(j, ':')) {
      j->failed = true;
      return;
    }
    if (strcmp(key, "name") == 0) {
      json_string(j, v->name, sizeof(v->name));
      has_name = true;
    } else if (strcmp(key, "description") == 0) {
      json_string(j, NULL, 0);
    } else if (strcmp(key, "direction") == 0) {
      json_string(j, text, text_size);
      v->is_request = strcmp(text, "request") == 0;
      has_direction = v->is_request || strcmp(text, "response") == 0;
    } else if (strcmp(key, "hex") == 0) {
      json_string(j, text, text_size);
      v->bytes = j->failed ? NULL : hex_decode(text, &v->len);
      has_hex = v->bytes != NULL;
    } else if (strcmp(key, "decode_only") == 0 ||
               strcmp(key, "decode_error") == 0) {
      bool value = json_literal(j, "true");
      if (!value && !json_literal(j, "false"))
        j->failed = true;
      if (key[7] == 'o') {
        v->decode_only = value;
        has_decode_only = true;
      } else {
        v->decode_error = value;
      }
    } else {
      j->failed = true;
    }
  } while (!j->failed && json_take(j, ','));
  if (!json_take(j, '}') || !has_name || !has_direction || !has_hex ||
      !has_decode_only)
    j->failed = true;
}

/* Loads test/vectors/<file>.json. Returns the number of vectors, or -1. */
static int vectors_load(const char *dir, const char *file, vector_t *out,
                        size_t max) {
  char path[512];
  snprintf(path, sizeof(path), "%s/%s.json", dir, file);
  FILE *f = fopen(path, "rb");
  if (!f) {
    fprintf(stderr, "cannot open %s\n", path);
    return -1;
  }
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  rewind(f);
  char *data = malloc((size_t)size + 1);
  char *text = malloc((size_t)size + 1);
  if (!data || !text || fread(data, 1, (size_t)size, f) != (size_t)size) {
    fclose(f);
    free(data);
    free(text);
    return -1;
  }
  fclose(f);

  json_t j = {data, data + size, false};
  char key[32];
  size_t count = 0;
  if (!json_take(&j, '{'))
    j.failed = true;
  json_string(&j, key, sizeof(key));
  if (strcmp(key, "vectors") != 0 || !json_take(&j, ':') || !json_take(&j, '['))
    j.failed = true;
  while (!j.failed && count < max) {
    json_vector(&j, text, (size_t)size + 1, &out[count]);
    if (j.failed)
      break;
    count++;
    if (!json_take(&j, ','))
      break;
  }
  if (!json_take(&j, ']') || !json_take(&j, '}'))
    j.failed = true;
  free(data);
  free(text);
  if (j.failed) {
    fprintf(stderr, "cannot parse %s\n", path);
    return -1;
  }
  return (int)count;
}

static void vectors_free(vector_t *vectors, int count) {
  for (int i = 0; i < count; i++)
    free(vectors[i].bytes);
}

#endif /* BIP377_TEST_VECTORS_H */
