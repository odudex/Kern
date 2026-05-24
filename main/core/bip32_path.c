#include "bip32_path.h"

#include <stdio.h>

bool bip32_path_parse(const char *path, uint32_t *components_out,
                      size_t *depth_out, size_t max_depth) {
  if (!path || !path[0] || !components_out || !depth_out)
    return false;

  for (const char *c = path; *c; c++) {
    if (*c != 'm' && *c != '/' && *c != '\'' && *c != 'h' &&
        !(*c >= '0' && *c <= '9')) {
      return false;
    }
  }

  const char *p = path;
  if (p[0] == 'm') {
    p++;
    if (p[0] == '/') {
      p++;
      if (p[0] == '\0')
        return false;
    } else if (p[0] != '\0') {
      return false;
    }
  }

  size_t depth = 0;
  while (*p && depth < max_depth) {
    uint32_t value = 0;
    bool has_digits = false;

    if (*p == '0' && p[1] >= '0' && p[1] <= '9')
      return false;

    while (*p >= '0' && *p <= '9') {
      uint32_t digit = (uint32_t)(*p - '0');
      if (value > UINT32_MAX / 10 ||
          (value == UINT32_MAX / 10 && digit > UINT32_MAX % 10))
        return false;
      value = value * 10 + digit;
      p++;
      has_digits = true;
    }

    if (!has_digits)
      return false;

    if (*p == '\'' || *p == 'h') {
      if (value >= BIP32_PATH_HARDENED)
        return false;
      value |= BIP32_PATH_HARDENED;
      p++;
    } else if (value >= BIP32_PATH_HARDENED) {
      return false;
    }

    components_out[depth++] = value;

    if (*p == '/') {
      p++;
      if (*p == '\0')
        return false;
    } else if (*p == '\0') {
      break;
    } else {
      return false;
    }
  }

  if (*p != '\0')
    return false;

  *depth_out = depth;
  return true;
}

bool bip32_path_format(const uint32_t *components, size_t depth, char *buf,
                       size_t buf_size) {
  if ((!components && depth > 0) || !buf || buf_size == 0)
    return false;

  int written = snprintf(buf, buf_size, "m");
  if (written < 0 || (size_t)written >= buf_size)
    return false;

  size_t pos = (size_t)written;
  for (size_t i = 0; i < depth; i++) {
    uint32_t component = components[i];
    written = bip32_path_is_hardened(component)
                  ? snprintf(buf + pos, buf_size - pos, "/%u'",
                             bip32_path_unharden(component))
                  : snprintf(buf + pos, buf_size - pos, "/%u", component);
    if (written < 0 || pos + (size_t)written >= buf_size)
      return false;
    pos += (size_t)written;
  }

  return true;
}

bool bip32_path_from_keypath(const unsigned char *raw_keypath,
                             size_t raw_keypath_len, uint32_t *components_out,
                             size_t *depth_out, size_t max_depth) {
  if (!raw_keypath || !components_out || !depth_out)
    return false;
  if (raw_keypath_len < 4 || (raw_keypath_len - 4) % 4 != 0)
    return false;

  size_t depth = (raw_keypath_len - 4) / 4;
  if (depth > max_depth)
    return false;

  for (size_t i = 0; i < depth; i++)
    components_out[i] = bip32_path_u32_le(raw_keypath + 4 + i * 4);

  *depth_out = depth;
  return true;
}

bool bip32_path_format_keypath(const unsigned char *raw_keypath,
                               size_t raw_keypath_len, char *buf,
                               size_t buf_size, size_t max_depth) {
  uint32_t components[max_depth > 0 ? max_depth : 1];
  size_t depth = 0;

  if (!bip32_path_from_keypath(raw_keypath, raw_keypath_len, components, &depth,
                               max_depth))
    return false;

  return bip32_path_format(components, depth, buf, buf_size);
}
