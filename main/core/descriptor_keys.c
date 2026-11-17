#include "descriptor_keys.h"

#include "musig_leaves.h"
#include <string.h>
#include <wally_bip32.h>
#include <wally_core.h>

#define FINGERPRINT_HEX_LEN (2 * BIP32_KEY_FINGERPRINT_LEN)
#define CHILD_PATH_FLAGS                                                       \
  (BIP32_FLAG_STR_WILDCARD | BIP32_FLAG_STR_BARE | BIP32_FLAG_STR_MULTIPATH)

/* libwally's own musig(), the tr() internal key */
static bool is_native_musig(const struct wally_descriptor *desc,
                            uint32_t index) {
  uint32_t features = 0;
  return wally_descriptor_get_key_features(desc, index, &features) ==
             WALLY_OK &&
         (features & WALLY_MS_IS_MUSIG);
}

/* The musig(...) expression a leaf key was rewritten from (musig_leaves.h),
 * or NULL. */
static const char *leaf_expression(const struct wally_descriptor *desc,
                                   uint32_t index) {
  char *text = NULL;
  if (wally_descriptor_get_key(desc, index, &text) != WALLY_OK) {
    wally_free_string(text);
    return NULL;
  }
  const char *key = text;
  if (*key == '[') {
    const char *close = strchr(key, ']');
    key = close ? close + 1 : key;
  }
  char *path = strchr(key, '/');
  if (path)
    *path = '\0';
  const char *expression = musig_leaves_expression(key);
  wally_free_string(text);
  return expression;
}

/* Participant `p` of a leaf musig(...) expression, as written. */
static bool leaf_participant(const char *expression, size_t p,
                             const char **start, size_t *len) {
  const char *participant = strchr(expression, '(') + 1;
  for (; p > 0; p--) {
    participant = strchr(participant, ',');
    if (!participant)
      return false;
    participant++;
  }
  size_t n = strcspn(participant, ",)");
  *start = participant;
  *len = n;
  return true;
}

/* A string wally_free_string() releases: wally's allocator, as the strings
 * libwally hands out. */
static char *wally_string_alloc(const char *text, size_t len) {
  struct wally_operations ops = {.struct_size = sizeof(ops)};
  if (wally_get_operations(&ops) != WALLY_OK)
    return NULL;
  char *copy = ops.malloc_fn(len + 1);
  if (copy) {
    memcpy(copy, text, len);
    copy[len] = '\0';
  }
  return copy;
}

bool descriptor_key_is_musig(const struct wally_descriptor *desc,
                             uint32_t index) {
  return is_native_musig(desc, index) || leaf_expression(desc, index);
}

size_t descriptor_key_musig_participants(const struct wally_descriptor *desc,
                                         uint32_t index) {
  size_t count = 0;
  if (is_native_musig(desc, index))
    return wally_descriptor_get_musig_num_participants(desc, index, &count) ==
                   WALLY_OK
               ? count
               : 0;
  const char *expression = leaf_expression(desc, index);
  if (!expression)
    return 0;
  for (count = 1; *expression; expression++)
    count += *expression == ',';
  return count;
}

/* The [fingerprint/path] origin of a leaf participant, without brackets. */
static bool leaf_origin(const struct wally_descriptor *desc,
                        descriptor_key_ref_t ref, const char **origin,
                        size_t *len) {
  const char *expression = leaf_expression(desc, ref.index);
  const char *participant = NULL;
  size_t participant_len = 0;
  if (!expression ||
      !leaf_participant(expression, ref.participant, &participant,
                        &participant_len) ||
      participant_len == 0 || participant[0] != '[')
    return false;
  const char *close = memchr(participant, ']', participant_len);
  if (!close)
    return false;
  *origin = participant + 1;
  *len = (size_t)(close - participant - 1);
  return true;
}

bool descriptor_key_origin_fingerprint(const struct wally_descriptor *desc,
                                       descriptor_key_ref_t ref,
                                       unsigned char *fingerprint_out) {
  if (ref.participant == DESCRIPTOR_KEY_NOT_MUSIG)
    return wally_descriptor_get_key_origin_fingerprint(
               desc, ref.index, fingerprint_out, BIP32_KEY_FINGERPRINT_LEN) ==
           WALLY_OK;
  if (is_native_musig(desc, ref.index))
    return wally_descriptor_get_musig_participant_key_origin_fingerprint(
               desc, ref.index, ref.participant, fingerprint_out,
               BIP32_KEY_FINGERPRINT_LEN) == WALLY_OK;
  const char *origin = NULL;
  size_t len = 0, written = 0;
  return leaf_origin(desc, ref, &origin, &len) && len >= FINGERPRINT_HEX_LEN &&
         wally_hex_n_to_bytes(origin, FINGERPRINT_HEX_LEN, fingerprint_out,
                              BIP32_KEY_FINGERPRINT_LEN,
                              &written) == WALLY_OK &&
         written == BIP32_KEY_FINGERPRINT_LEN;
}

static bool key_has_fingerprint(const struct wally_descriptor *desc,
                                descriptor_key_ref_t ref,
                                const unsigned char *fingerprint) {
  unsigned char key_fp[BIP32_KEY_FINGERPRINT_LEN];
  return descriptor_key_origin_fingerprint(desc, ref, key_fp) &&
         memcmp(key_fp, fingerprint, BIP32_KEY_FINGERPRINT_LEN) == 0;
}

bool descriptor_key_holds_fingerprint(const struct wally_descriptor *desc,
                                      uint32_t index,
                                      const unsigned char *fingerprint) {
  descriptor_key_ref_t ref = {.index = index,
                              .participant = DESCRIPTOR_KEY_NOT_MUSIG};
  size_t participants = descriptor_key_musig_participants(desc, index);
  if (participants == 0)
    return key_has_fingerprint(desc, ref, fingerprint);
  for (ref.participant = 0; ref.participant < participants; ref.participant++) {
    if (key_has_fingerprint(desc, ref, fingerprint))
      return true;
  }
  return false;
}

bool descriptor_key_find(const struct wally_descriptor *desc,
                         const unsigned char *fingerprint,
                         descriptor_key_ref_t *ref_out) {
  uint32_t num_keys = 0;
  if (!desc || !fingerprint || !ref_out ||
      wally_descriptor_get_num_keys(desc, &num_keys) != WALLY_OK)
    return false;

  for (uint32_t i = 0; i < num_keys; i++) {
    descriptor_key_ref_t ref = {.index = i,
                                .participant = DESCRIPTOR_KEY_NOT_MUSIG};
    size_t participants = descriptor_key_musig_participants(desc, i);
    if (participants == 0 && key_has_fingerprint(desc, ref, fingerprint)) {
      *ref_out = ref;
      return true;
    }
    for (ref.participant = 0; ref.participant < participants;
         ref.participant++) {
      if (key_has_fingerprint(desc, ref, fingerprint)) {
        *ref_out = ref;
        return true;
      }
    }
  }
  return false;
}

char *descriptor_key_origin_path_alloc(const struct wally_descriptor *desc,
                                       descriptor_key_ref_t ref) {
  if (ref.participant != DESCRIPTOR_KEY_NOT_MUSIG &&
      !is_native_musig(desc, ref.index)) {
    const char *origin = NULL;
    size_t len = 0;
    if (!leaf_origin(desc, ref, &origin, &len) || len < FINGERPRINT_HEX_LEN)
      return NULL;
    /* the path after the fingerprint and its '/', empty without one */
    size_t skip = len > FINGERPRINT_HEX_LEN ? FINGERPRINT_HEX_LEN + 1 : len;
    return wally_string_alloc(origin + skip, len - skip);
  }
  char *path = NULL;
  int ret =
      ref.participant == DESCRIPTOR_KEY_NOT_MUSIG
          ? wally_descriptor_get_key_origin_path_str(desc, ref.index, &path)
          : wally_descriptor_get_musig_participant_key_origin_path_str(
                desc, ref.index, ref.participant, &path);
  if (ret != WALLY_OK) {
    wally_free_string(path);
    return NULL;
  }
  return path;
}

char *descriptor_key_string_alloc(const struct wally_descriptor *desc,
                                  descriptor_key_ref_t ref) {
  if (ref.participant != DESCRIPTOR_KEY_NOT_MUSIG &&
      !is_native_musig(desc, ref.index)) {
    const char *expression = leaf_expression(desc, ref.index);
    const char *participant = NULL;
    size_t len = 0;
    return expression && leaf_participant(expression, ref.participant,
                                          &participant, &len)
               ? wally_string_alloc(participant, len)
               : NULL;
  }
  char *key = NULL;
  int ret = ref.participant == DESCRIPTOR_KEY_NOT_MUSIG
                ? wally_descriptor_get_key(desc, ref.index, &key)
                : wally_descriptor_get_musig_participant_key(
                      desc, ref.index, ref.participant, &key);
  if (ret != WALLY_OK) {
    wally_free_string(key);
    return NULL;
  }
  return key;
}

bool descriptor_key_child_steps(const struct wally_descriptor *desc,
                                descriptor_key_ref_t ref, uint32_t multi_index,
                                uint32_t child_num, uint32_t *steps,
                                size_t max_steps, size_t *steps_len) {
  char *text = NULL;
  const char *path = NULL;
  *steps_len = 0;
  if (ref.participant == DESCRIPTOR_KEY_NOT_MUSIG) {
    if (wally_descriptor_get_key_child_path_str(desc, ref.index, &text) !=
        WALLY_OK)
      return false;
    path = text;
  } else {
    text = descriptor_key_string_alloc(desc, ref);
    if (!text)
      return false;
    const char *key = text;
    if (*key == '[') {
      const char *close = strchr(key, ']');
      key = close ? close + 1 : key + strlen(key);
    }
    /* past the '/': a bare path starts with a step */
    path = strchr(key, '/');
    if (path)
      path++;
  }
  bool ok = !path || path[0] == '\0' ||
            bip32_path_from_str_n(path, strlen(path), child_num, multi_index,
                                  CHILD_PATH_FLAGS, steps, max_steps,
                                  steps_len) == WALLY_OK;
  wally_free_string(text);
  return ok;
}
