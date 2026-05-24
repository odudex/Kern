#ifndef BIP32_PATH_H
#define BIP32_PATH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BIP32_PATH_HARDENED 0x80000000u

static inline bool bip32_path_is_hardened(uint32_t component) {
  return (component & BIP32_PATH_HARDENED) != 0;
}

static inline uint32_t bip32_path_unharden(uint32_t component) {
  return component & ~BIP32_PATH_HARDENED;
}

static inline uint32_t bip32_path_u32_le(const unsigned char *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

bool bip32_path_parse(const char *path, uint32_t *components_out,
                      size_t *depth_out, size_t max_depth);

bool bip32_path_format(const uint32_t *components, size_t depth, char *buf,
                       size_t buf_size);

bool bip32_path_from_keypath(const unsigned char *raw_keypath,
                             size_t raw_keypath_len, uint32_t *components_out,
                             size_t *depth_out, size_t max_depth);

bool bip32_path_format_keypath(const unsigned char *raw_keypath,
                               size_t raw_keypath_len, char *buf,
                               size_t buf_size, size_t max_depth);

#endif // BIP32_PATH_H
