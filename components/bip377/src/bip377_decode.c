#include "bip377_internal.h"

#include <string.h>

#define TRY BIP377_TRY

typedef struct {
  const uint8_t *data;
  size_t len;
  size_t pos;
} reader_t;

/* The block a request tree is built in. `mem` is NULL while measuring: every
 * allocation then only advances `used`, and the fields it would have held go
 * to a scratch object of the caller. */
typedef struct {
  uint8_t *mem;
  size_t cap;
  size_t used;
} arena_t;

typedef union {
  void *pointer;
  size_t size;
  uint32_t word;
} arena_align_t;

#define ARENA_ALIGN sizeof(arena_align_t)

static int arena_alloc(arena_t *a, size_t size, bool aligned, void **out) {
  size_t start = a->used;
  if (aligned) {
    size_t pad = (ARENA_ALIGN - start % ARENA_ALIGN) % ARENA_ALIGN;
    if (pad > SIZE_MAX - start)
      return BIP377_ERR_TOO_LARGE;
    start += pad;
  }
  if (size > SIZE_MAX - start)
    return BIP377_ERR_TOO_LARGE;
  *out = NULL;
  if (a->mem) {
    if (size > a->cap || start > a->cap - size)
      return BIP377_ERR_BUFFER_TOO_SMALL;
    *out = a->mem + start;
    memset(*out, 0, size);
  }
  a->used = start + size;
  return BIP377_OK;
}

static int arena_array(arena_t *a, size_t count, size_t item_size, void **out) {
  if (count > SIZE_MAX / item_size)
    return BIP377_ERR_TOO_LARGE;
  return arena_alloc(a, count * item_size, true, out);
}

static size_t reader_left(const reader_t *r) { return r->len - r->pos; }

static int read_slice(reader_t *r, size_t n, const uint8_t **out) {
  if (n > reader_left(r))
    return BIP377_ERR_TRUNCATED;
  *out = r->data + r->pos;
  r->pos += n;
  return BIP377_OK;
}

static int read_array(reader_t *r, uint8_t *out, size_t n) {
  const uint8_t *src;
  TRY(read_slice(r, n, &src));
  memcpy(out, src, n);
  return BIP377_OK;
}

static int read_u8(reader_t *r, uint8_t *out) { return read_array(r, out, 1); }

static int read_u32_be(reader_t *r, uint32_t *out) {
  uint8_t b[4];
  TRY(read_array(r, b, sizeof(b)));
  *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
         ((uint32_t)b[2] << 8) | (uint32_t)b[3];
  return BIP377_OK;
}

/* Little-endian, and only in its shortest form */
static int read_compact(reader_t *r, size_t *out) {
  uint8_t first;
  TRY(read_u8(r, &first));
  uint64_t value = first;
  size_t width = 0;
  uint64_t min = 0;
  if (first == 0xfd) {
    width = 2;
    min = 0xfd;
  } else if (first == 0xfe) {
    width = 4;
    min = 0x10000;
  } else if (first == 0xff) {
    width = 8;
    min = 0x100000000ULL;
  }
  if (width) {
    uint8_t b[8];
    TRY(read_array(r, b, width));
    value = 0;
    for (size_t i = width; i > 0; i--)
      value = (value << 8) | b[i - 1];
    if (value < min)
      return BIP377_ERR_NON_CANONICAL_COMPACT_SIZE;
  }
#if SIZE_MAX < UINT64_MAX
  if (value > SIZE_MAX)
    return BIP377_ERR_COMPACT_SIZE_TOO_LARGE;
#endif
  *out = (size_t)value;
  return BIP377_OK;
}

static int read_flag(reader_t *r, int invalid, bool *out) {
  uint8_t value;
  TRY(read_u8(r, &value));
  if (value > 1)
    return invalid;
  *out = value == 1;
  return BIP377_OK;
}

static int read_bool(reader_t *r, bool *out) {
  return read_flag(r, BIP377_ERR_INVALID_BOOL, out);
}

static int read_presence(reader_t *r, bool *out) {
  return read_flag(r, BIP377_ERR_INVALID_PRESENCE, out);
}

/* The COUNT of a vector. Every element takes at least one byte, so a count
 * above what is left of the message is one the message cannot hold: refusing
 * it here bounds what the vector reserves. */
static int read_count(reader_t *r, size_t *out) {
  TRY(read_compact(r, out));
  if (*out > reader_left(r))
    return BIP377_ERR_TRUNCATED;
  return BIP377_OK;
}

static int read_string(reader_t *r, arena_t *a, size_t max, const char **out) {
  size_t len;
  TRY(read_compact(r, &len));
  if (len > max)
    return BIP377_ERR_STRING_TOO_LARGE;
  const uint8_t *src;
  TRY(read_slice(r, len, &src));
  TRY(bip377_string_check(src, len));
  if (len == SIZE_MAX)
    return BIP377_ERR_TOO_LARGE;
  void *dst;
  TRY(arena_alloc(a, len + 1, false, &dst));
  if (dst) {
    memcpy(dst, src, len);
    ((char *)dst)[len] = '\0';
  }
  *out = dst;
  return BIP377_OK;
}

static int read_alias(reader_t *r, arena_t *a, const char **out) {
  return read_string(r, a, BIP377_MAX_DESCRIPTOR_ALIAS, out);
}

/* A present BYTES always gets a non-NULL ptr, an empty one included. */
static int read_bytes(reader_t *r, arena_t *a, bip377_bytes *out) {
  size_t len;
  TRY(read_compact(r, &len));
  const uint8_t *src;
  TRY(read_slice(r, len, &src));
  void *dst;
  TRY(arena_alloc(a, len ? len : 1, false, &dst));
  if (dst && len)
    memcpy(dst, src, len);
  out->ptr = dst;
  out->len = len;
  return BIP377_OK;
}

static int read_optional_bytes(reader_t *r, arena_t *a, bip377_bytes *out) {
  bool present;
  TRY(read_presence(r, &present));
  out->ptr = NULL;
  out->len = 0;
  return present ? read_bytes(r, a, out) : BIP377_OK;
}

static int read_path(reader_t *r, arena_t *a, bip377_path *out) {
  uint8_t count;
  TRY(read_u8(r, &count));
  if ((size_t)count * sizeof(uint32_t) > reader_left(r))
    return BIP377_ERR_TRUNCATED;
  void *mem = NULL;
  if (count)
    TRY(arena_array(a, count, sizeof(uint32_t), &mem));
  uint32_t *children = mem;
  for (uint8_t i = 0; i < count; i++) {
    uint32_t child;
    TRY(read_u32_be(r, &child));
    if (children)
      children[i] = child;
  }
  out->ptr = children;
  out->len = count;
  return BIP377_OK;
}

static int read_bip388(reader_t *r, arena_t *a, bip377_bip388 *out) {
  size_t count;
  TRY(read_count(r, &count));
  void *mem = NULL;
  if (count)
    TRY(arena_array(a, count, sizeof(const char *), &mem));
  const char **keys = mem;
  for (size_t i = 0; i < count; i++) {
    const char *key;
    TRY(read_string(r, a, SIZE_MAX, &key));
    if (keys)
      keys[i] = key;
  }
  out->keys.ptr = keys;
  out->keys.len = count;
  return read_string(r, a, SIZE_MAX, &out->policy);
}

static int read_sp_keys(reader_t *r, arena_t *a, bip377_sp_keys *out) {
  TRY(read_array(r, out->fingerprint, sizeof(out->fingerprint)));
  TRY(read_path(r, a, &out->spend_path));

  bool has_path;
  bip377_path path = {NULL, 0};
  TRY(read_presence(r, &has_path));
  if (has_path)
    TRY(read_path(r, a, &path));

  bool has_key;
  uint8_t key[BIP377_SECRET_KEY_LEN] = {0};
  TRY(read_presence(r, &has_key));
  if (has_key)
    TRY(read_array(r, key, sizeof(key)));

  if (has_path && has_key)
    return BIP377_ERR_SCAN_PATH_AND_KEY;
  if (!has_path && !has_key)
    return BIP377_ERR_NO_SCAN;
  if (has_path) {
    out->scan_kind = BIP377_SCAN_PATH;
    out->scan.path = path;
  } else {
    out->scan_kind = BIP377_SCAN_KEY;
    memcpy(out->scan.key, key, sizeof(key));
  }
  return BIP377_OK;
}

static int read_descriptor_body(reader_t *r, arena_t *a,
                                const bip377_descriptor_body **out) {
  void *mem;
  TRY(arena_alloc(a, sizeof(bip377_descriptor_body), true, &mem));
  bip377_descriptor_body scratch;
  memset(&scratch, 0, sizeof(scratch));
  bip377_descriptor_body *body = mem ? mem : &scratch;

  TRY(read_u8(r, &body->tag));
  switch (body->tag) {
  case BIP377_DESCRIPTOR_BIP380:
    TRY(read_string(r, a, SIZE_MAX, &body->value.bip380));
    break;
  case BIP377_DESCRIPTOR_BIP388:
    TRY(read_bip388(r, a, &body->value.bip388));
    break;
  case BIP377_DESCRIPTOR_SP_KEYS:
    TRY(read_sp_keys(r, a, &body->value.sp_keys));
    break;
  default:
    return BIP377_ERR_UNKNOWN_DESCRIPTOR_FORM;
  }
  *out = mem;
  return BIP377_OK;
}

static int read_optional_descriptor_body(reader_t *r, arena_t *a,
                                         const bip377_descriptor_body **out) {
  bool present;
  TRY(read_presence(r, &present));
  *out = NULL;
  return present ? read_descriptor_body(r, a, out) : BIP377_OK;
}

static int read_get_keys(reader_t *r, arena_t *a, bip377_get_keys *out) {
  size_t count;
  TRY(read_count(r, &count));
  void *mem = NULL;
  if (count)
    TRY(arena_array(a, count, sizeof(bip377_path), &mem));
  bip377_path *paths = mem;
  for (size_t i = 0; i < count; i++) {
    bip377_path scratch;
    TRY(read_path(r, a, paths ? &paths[i] : &scratch));
  }
  out->keys.ptr = paths;
  out->keys.len = count;
  return BIP377_OK;
}

static int read_register_descriptor(reader_t *r, arena_t *a,
                                    bip377_register_descriptor *out) {
  TRY(read_alias(r, a, &out->descriptor_alias));
  return read_optional_descriptor_body(r, a, &out->descriptor);
}

static int read_verify_address(reader_t *r, arena_t *a,
                               bip377_verify_address *out) {
  TRY(read_alias(r, a, &out->descriptor_alias));
  TRY(read_path(r, a, &out->derivation_path));
  bool has_address;
  TRY(read_presence(r, &has_address));
  out->address = NULL;
  if (has_address)
    TRY(read_string(r, a, SIZE_MAX, &out->address));
  TRY(read_optional_descriptor_body(r, a, &out->descriptor));
  return read_optional_bytes(r, a, &out->proof);
}

static int read_descriptor(reader_t *r, arena_t *a, bip377_descriptor *out) {
  TRY(read_alias(r, a, &out->alias));
  TRY(read_optional_descriptor_body(r, a, &out->body));
  return read_optional_bytes(r, a, &out->proof);
}

static int read_sign(reader_t *r, arena_t *a, bip377_sign *out) {
  size_t count;
  TRY(read_count(r, &count));
  void *mem = NULL;
  if (count)
    TRY(arena_array(a, count, sizeof(bip377_descriptor), &mem));
  bip377_descriptor *descriptors = mem;
  for (size_t i = 0; i < count; i++) {
    bip377_descriptor scratch;
    TRY(read_descriptor(r, a, descriptors ? &descriptors[i] : &scratch));
  }
  out->descriptors.ptr = descriptors;
  out->descriptors.len = count;

  TRY(read_bytes(r, a, &out->psbt));

  /* A preference: a value this version does not know reads as absent */
  bool has_want_kind;
  TRY(read_presence(r, &has_want_kind));
  out->want_kind = BIP377_ABSENT_KIND;
  if (has_want_kind) {
    uint8_t kind;
    TRY(read_u8(r, &kind));
    if (kind == BIP377_SIGN_RESPONSE_PSBT ||
        kind == BIP377_SIGN_RESPONSE_SIGNATURES)
      out->want_kind = kind;
  }
  return read_bool(r, &out->accept_trimmed);
}

static int read_request(reader_t *r, arena_t *a, const bip377_request **out) {
  void *mem;
  TRY(arena_alloc(a, sizeof(bip377_request), true, &mem));
  bip377_request scratch;
  memset(&scratch, 0, sizeof(scratch));
  bip377_request *request = mem ? mem : &scratch;

  if (!bip377_is_message(r->data, r->len))
    return BIP377_ERR_INVALID_MAGIC;
  r->pos = BIP377_MAGIC_LEN;

  TRY(read_u8(r, &request->version));
  if (request->version == 0)
    return BIP377_ERR_RESERVED_VERSION;

  uint8_t msg_type;
  TRY(read_u8(r, &msg_type));
  uint8_t type = msg_type & BIP377_TYPE_MASK;
  bool response = msg_type & BIP377_DIRECTION_RESPONSE;
  if (type != BIP377_MESSAGE_UNREADABLE_REQUEST &&
      !bip377_type_is_request(type))
    return BIP377_ERR_UNKNOWN_MESSAGE_TYPE;
  if ((msg_type & BIP377_STATUS_ERROR) && !response)
    return BIP377_ERR_ERROR_STATUS_ON_REQUEST;
  TRY(read_array(r, request->id, sizeof(request->id)));
  if (response)
    return BIP377_ERR_DIRECTION_DISABLED;
  request->message_type = type;

  switch (type) {
  case BIP377_MESSAGE_GET_INFO:
    break;
  case BIP377_MESSAGE_GET_KEYS:
    TRY(read_get_keys(r, a, &request->body.get_keys));
    break;
  case BIP377_MESSAGE_REGISTER_DESCRIPTOR:
    TRY(read_register_descriptor(r, a, &request->body.register_descriptor));
    break;
  case BIP377_MESSAGE_ADDRESS_VERIFICATION:
    TRY(read_verify_address(r, a, &request->body.verify_address));
    break;
  case BIP377_MESSAGE_SIGNING:
    TRY(read_sign(r, a, &request->body.sign));
    break;
  case BIP377_MESSAGE_UNREGISTER_DESCRIPTOR:
    TRY(read_alias(r, a,
                   &request->body.unregister_descriptor.descriptor_alias));
    break;
  default:
    return BIP377_ERR_UNREADABLE_REQUEST_TYPE;
  }
  /* Whatever follows belongs to a later version */
  *out = mem;
  return BIP377_OK;
}

int bip377_request_decode(const uint8_t *msg, size_t len, void *mem,
                          size_t mem_len, size_t *mem_needed,
                          const bip377_request **out) {
  if (!msg || (mem && !out))
    return BIP377_ERR_NULL_POINTER;

  /* Measuring validates the whole message, so filling cannot fail */
  reader_t reader = {msg, len, 0};
  arena_t arena = {NULL, 0, 0};
  const bip377_request *request = NULL;
  TRY(read_request(&reader, &arena, &request));
  if (mem_needed)
    *mem_needed = arena.used;
  if (!mem)
    return BIP377_OK;

  if ((uintptr_t)mem % ARENA_ALIGN != 0)
    return BIP377_ERR_BUFFER_MISALIGNED;
  if (mem_len < arena.used)
    return BIP377_ERR_BUFFER_TOO_SMALL;
  reader.pos = 0;
  arena.mem = mem;
  arena.cap = mem_len;
  arena.used = 0;
  TRY(read_request(&reader, &arena, &request));
  *out = request;
  return BIP377_OK;
}
