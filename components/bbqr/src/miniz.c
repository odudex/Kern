/*
 * miniz.c - Minimal zlib-compatible compression/decompression
 * Based on public domain code. Optimized for embedded use.
 *
 * LZ77 compression with static Huffman codes based on:
 * - uzlib by Paul Sokolovsky (MIT license)
 * - PuTTY deflate code by Simon Tatham
 * - MicroPython deflate module by Jim Mussared, Damien P. George
 */

#include "miniz.h"
#include <stdlib.h>
#include <string.h>

/* Default window bits for BBQr (1024 byte window) */
#define MZ_DEFAULT_WBITS 10

/* LZ77 parameters */
#define MATCH_LEN_MIN 3
#define MATCH_LEN_MAX 258

/* Adler32 checksum */
static uint32_t adler32(uint32_t adler, const uint8_t *ptr, size_t len) {
  uint32_t s1 = adler & 0xffff, s2 = adler >> 16;
  while (len > 0) {
    size_t block_len = len < 5550 ? len : 5550;
    len -= block_len;
    while (block_len--) {
      s1 += *ptr++;
      s2 += s1;
    }
    s1 %= 65521;
    s2 %= 65521;
  }
  return (s2 << 16) + s1;
}

/*
 * ============================================================================
 * LZ77 Compression with Static Huffman Encoding
 * ============================================================================
 */

/* Compression state */
typedef struct {
  /* Output buffer */
  uint8_t *out_buf;
  size_t out_pos;
  size_t out_size;

  /* Bit buffer for output */
  uint32_t out_bits;
  int n_out_bits;

  /* History window (circular buffer) */
  uint8_t *hist_buf;
  size_t hist_max;   /* Window size (power of 2) */
  size_t hist_start; /* Start index in circular buffer */
  size_t hist_len;   /* Current bytes in history */
} mz_compress_state_t;

/* Mirror nibble lookup table for Huffman code output */
static const uint8_t s_mirror_nibble[16] = {0x0, 0x8, 0x4, 0xc, 0x2, 0xa,
                                            0x6, 0xe, 0x1, 0x9, 0x5, 0xd,
                                            0x3, 0xb, 0x7, 0xf};

static inline uint8_t mirror_byte(uint8_t b) {
  return (s_mirror_nibble[b & 0xf] << 4) | s_mirror_nibble[b >> 4];
}

static inline int int_log2(int x) {
  int r = 0;
  while (x >>= 1) {
    ++r;
  }
  return r;
}

/* Output bits to the compression buffer (LSB first) */
static int out_bits(mz_compress_state_t *s, uint32_t bits, int nbits) {
  s->out_bits |= bits << s->n_out_bits;
  s->n_out_bits += nbits;

  while (s->n_out_bits >= 8) {
    if (s->out_pos >= s->out_size) {
      return MZ_BUF_ERROR;
    }
    s->out_buf[s->out_pos++] = s->out_bits & 0xFF;
    s->out_bits >>= 8;
    s->n_out_bits -= 8;
  }
  return MZ_OK;
}

/* Output a literal byte using static Huffman codes */
static int out_literal(mz_compress_state_t *s, uint8_t c) {
  if (c <= 143) {
    /* 0-143: 8 bits starting at 00110000 (0x30) */
    return out_bits(s, mirror_byte(0x30 + c), 8);
  } else {
    /* 144-255: 9 bits starting at 110010000 (0x190) */
    return out_bits(s, 1 + 2 * mirror_byte(0x90 - 144 + c), 9);
  }
}

/* Output a length/distance match using static Huffman codes */
static int out_match(mz_compress_state_t *s, int distance, int len) {
  int ret;
  distance -= 1;

  while (len > 0) {
    int thislen;

    /* Max match length per code is 258; handle longer matches in pieces */
    thislen = (len > 260 ? 258 : len <= 258 ? len : len - 3);
    len -= thislen;

    thislen -= 3;
    int lcode = 28;
    int x = int_log2(thislen);
    int y;
    if (thislen < 255) {
      if (x) {
        --x;
      }
      y = (thislen >> (x ? x - 1 : 0)) & 3;
      lcode = x * 4 + y;
    }

    /* Transmit length code: 256-279 are 7 bits, 280-287 are 8 bits */
    if (lcode <= 22) {
      ret = out_bits(s, mirror_byte((lcode + 1) * 2), 7);
    } else {
      ret = out_bits(s, mirror_byte(lcode + 169), 8);
    }
    if (ret != MZ_OK)
      return ret;

    /* Transmit extra length bits */
    if (thislen < 255 && x > 1) {
      int extrabits = x - 1;
      int lmin = (thislen >> extrabits) << extrabits;
      ret = out_bits(s, thislen - lmin, extrabits);
      if (ret != MZ_OK)
        return ret;
    }

    x = int_log2(distance);
    y = (distance >> (x ? x - 1 : 0)) & 1;

    /* Transmit distance code: 5 bits */
    ret = out_bits(s, mirror_byte((x * 2 + y) * 8), 5);
    if (ret != MZ_OK)
      return ret;

    /* Transmit extra distance bits */
    if (x > 1) {
      int dextrabits = x - 1;
      int dmin = (distance >> dextrabits) << dextrabits;
      ret = out_bits(s, distance - dmin, dextrabits);
      if (ret != MZ_OK)
        return ret;
    }
  }
  return MZ_OK;
}

/* Start a deflate block with static Huffman codes */
static int start_block(mz_compress_state_t *s) {
  /* BFINAL=1 (final block), BTYPE=01 (static Huffman) */
  return out_bits(s, 3, 3);
}

/* End the deflate block */
static int finish_block(mz_compress_state_t *s) {
  int ret;
  /* End-of-block symbol (256): 7 bits = 0000000 */
  ret = out_bits(s, 0, 7);
  if (ret != MZ_OK)
    return ret;

  /* Flush remaining bits (pad to byte boundary) */
  if (s->n_out_bits > 0) {
    ret = out_bits(s, 0, 8 - s->n_out_bits);
  }
  return ret;
}

/* Search history for longest match */
static size_t lz77_find_match(mz_compress_state_t *s, const uint8_t *src,
                              size_t src_len, size_t *match_offset) {
  size_t longest_len = 0;
  size_t mask = s->hist_max - 1;

  for (size_t hist_search = 0; hist_search < s->hist_len; ++hist_search) {
    size_t match_len;
    for (match_len = 0; match_len < MATCH_LEN_MAX && match_len < src_len;
         ++match_len) {
      uint8_t hist;
      if (hist_search + match_len < s->hist_len) {
        hist = s->hist_buf[(s->hist_start + hist_search + match_len) & mask];
      } else {
        hist = src[hist_search + match_len - s->hist_len];
      }
      if (src[match_len] != hist) {
        break;
      }
    }

    /* Take this match if it's at least minimum length and >= previous best */
    if (match_len >= MATCH_LEN_MIN && match_len >= longest_len) {
      longest_len = match_len;
      *match_offset = s->hist_len - hist_search;
    }
  }

  return longest_len;
}

/* Push bytes into history buffer */
static void hist_push(mz_compress_state_t *s, const uint8_t *data, size_t len) {
  size_t mask = s->hist_max - 1;
  for (size_t i = 0; i < len; i++) {
    s->hist_buf[(s->hist_start + s->hist_len) & mask] = data[i];
    if (s->hist_len == s->hist_max) {
      s->hist_start = (s->hist_start + 1) & mask;
    } else {
      ++s->hist_len;
    }
  }
}

/* LZ77 compress data chunk */
static int lz77_compress(mz_compress_state_t *s, const uint8_t *src,
                         size_t len) {
  int ret;
  const uint8_t *end = src + len;

  while (src < end) {
    size_t match_offset = 0;
    size_t match_len = lz77_find_match(s, src, end - src, &match_offset);

    if (match_len == 0) {
      /* Output literal */
      ret = out_literal(s, *src);
      if (ret != MZ_OK)
        return ret;
      hist_push(s, src, 1);
      src++;
    } else {
      /* Output match */
      ret = out_match(s, match_offset, match_len);
      if (ret != MZ_OK)
        return ret;
      hist_push(s, src, match_len);
      src += match_len;
    }
  }
  return MZ_OK;
}

/* Length/distance tables for deflate */
static const uint16_t s_length_base[29] = {
    3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
static const uint8_t s_length_extra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
                                           1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
                                           4, 4, 4, 4, 5, 5, 5, 5, 0};
static const uint16_t s_dist_base[30] = {
    1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
    33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t s_dist_extra[30] = {0, 0, 0,  0,  1,  1,  2,  2,  3,  3,
                                         4, 4, 5,  5,  6,  6,  7,  7,  8,  8,
                                         9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

/* Code length order for dynamic Huffman */
static const uint8_t s_code_order[19] = {16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                         11, 4,  12, 3, 13, 2, 14, 1, 15};

/* Huffman decode table structure */
typedef struct {
  uint16_t counts[16];   /* Number of codes of each length */
  uint16_t symbols[288]; /* Symbols sorted by code */
} HuffTable;

/* Build Huffman table from code lengths */
static int build_huffman(HuffTable *h, const uint8_t *lengths, int num_syms) {
  int offs[16];
  memset(h->counts, 0, sizeof(h->counts));

  /* Count codes of each length */
  for (int i = 0; i < num_syms; i++) {
    if (lengths[i] > 0 && lengths[i] <= 15) {
      h->counts[lengths[i]]++;
    }
  }

  /* Compute offsets */
  offs[0] = 0;
  offs[1] = 0;
  for (int i = 1; i < 15; i++) {
    offs[i + 1] = offs[i] + h->counts[i];
  }

  /* Sort symbols by code length, then by symbol value */
  for (int i = 0; i < num_syms; i++) {
    if (lengths[i] > 0 && lengths[i] <= 15) {
      h->symbols[offs[lengths[i]]++] = i;
    }
  }

  return 0;
}

/* Bit-by-bit Huffman decode */
static int decode_huffman_simple(HuffTable *h, const uint8_t **pSrc,
                                 const uint8_t *pSrc_end, uint32_t *bit_buf,
                                 int *num_bits) {
  int code = 0;
  int first = 0;
  int index = 0;

  for (int len = 1; len <= 15; len++) {
    while (*num_bits < 1) {
      if (*pSrc >= pSrc_end)
        return -1;
      *bit_buf |= (uint32_t)(*(*pSrc)++) << *num_bits;
      *num_bits += 8;
    }

    code = (code << 1) | (*bit_buf & 1);
    *bit_buf >>= 1;
    (*num_bits)--;

    int count = h->counts[len];
    if (code - first < count) {
      return h->symbols[index + code - first];
    }
    first = (first + count) << 1;
    index += count;
  }

  return -1;
}

/* Build fixed Huffman tables */
static void build_fixed_tables(HuffTable *lit_len, HuffTable *dist) {
  uint8_t lengths[288];

  /* Literal/length table: RFC 1951 section 3.2.6 */
  for (int i = 0; i < 144; i++)
    lengths[i] = 8;
  for (int i = 144; i < 256; i++)
    lengths[i] = 9;
  for (int i = 256; i < 280; i++)
    lengths[i] = 7;
  for (int i = 280; i < 288; i++)
    lengths[i] = 8;
  build_huffman(lit_len, lengths, 288);

  /* Distance table: all 5-bit codes */
  for (int i = 0; i < 30; i++)
    lengths[i] = 5;
  build_huffman(dist, lengths, 30);
}

/* Raw deflate decompression */
static int inflate_raw_impl(uint8_t *dest, size_t *dest_len,
                            const uint8_t *source, size_t source_len) {
  const uint8_t *pSrc = source;
  const uint8_t *pSrc_end = source + source_len;
  uint8_t *pDst = dest;
  uint8_t *pDst_end = dest + *dest_len;
  uint32_t bit_buf = 0;
  int num_bits = 0;
  int final_block = 0;

  HuffTable lit_len_table, dist_table;
  HuffTable code_len_table;

  while (!final_block) {
    /* Read block header (3 bits) */
    while (num_bits < 3) {
      if (pSrc >= pSrc_end)
        return MZ_DATA_ERROR;
      bit_buf |= (uint32_t)(*pSrc++) << num_bits;
      num_bits += 8;
    }

    final_block = bit_buf & 1;
    int block_type = (bit_buf >> 1) & 3;
    bit_buf >>= 3;
    num_bits -= 3;

    if (block_type == 0) {
      /* Stored block */
      /* Align to byte boundary */
      num_bits = 0;
      bit_buf = 0;

      if (pSrc + 4 > pSrc_end)
        return MZ_DATA_ERROR;

      uint16_t len = pSrc[0] | (pSrc[1] << 8);
      uint16_t nlen = pSrc[2] | (pSrc[3] << 8);
      pSrc += 4;

      if (len != (uint16_t)~nlen)
        return MZ_DATA_ERROR;
      if (pSrc + len > pSrc_end)
        return MZ_DATA_ERROR;
      if (pDst + len > pDst_end)
        return MZ_BUF_ERROR;

      memcpy(pDst, pSrc, len);
      pSrc += len;
      pDst += len;

    } else if (block_type == 1) {
      /* Fixed Huffman codes */
      build_fixed_tables(&lit_len_table, &dist_table);

      for (;;) {
        int sym = decode_huffman_simple(&lit_len_table, &pSrc, pSrc_end,
                                        &bit_buf, &num_bits);
        if (sym < 0)
          return MZ_DATA_ERROR;

        if (sym < 256) {
          /* Literal byte */
          if (pDst >= pDst_end)
            return MZ_BUF_ERROR;
          *pDst++ = (uint8_t)sym;
        } else if (sym == 256) {
          /* End of block */
          break;
        } else {
          /* Length/distance pair */
          int len_idx = sym - 257;
          if (len_idx >= 29)
            return MZ_DATA_ERROR;

          int match_len = s_length_base[len_idx];
          int extra = s_length_extra[len_idx];

          /* Read extra length bits */
          while (num_bits < extra) {
            if (pSrc >= pSrc_end)
              return MZ_DATA_ERROR;
            bit_buf |= (uint32_t)(*pSrc++) << num_bits;
            num_bits += 8;
          }
          match_len += bit_buf & ((1 << extra) - 1);
          bit_buf >>= extra;
          num_bits -= extra;

          /* Decode distance */
          int dist_sym = decode_huffman_simple(&dist_table, &pSrc, pSrc_end,
                                               &bit_buf, &num_bits);
          if (dist_sym < 0 || dist_sym >= 30)
            return MZ_DATA_ERROR;

          int match_dist = s_dist_base[dist_sym];
          extra = s_dist_extra[dist_sym];

          /* Read extra distance bits */
          while (num_bits < extra) {
            if (pSrc >= pSrc_end)
              return MZ_DATA_ERROR;
            bit_buf |= (uint32_t)(*pSrc++) << num_bits;
            num_bits += 8;
          }
          match_dist += bit_buf & ((1 << extra) - 1);
          bit_buf >>= extra;
          num_bits -= extra;

          /* Copy match */
          if ((size_t)match_dist > (size_t)(pDst - dest))
            return MZ_DATA_ERROR;
          if (pDst + match_len > pDst_end)
            return MZ_BUF_ERROR;

          const uint8_t *pMatch = pDst - match_dist;
          while (match_len-- > 0) {
            *pDst++ = *pMatch++;
          }
        }
      }

    } else if (block_type == 2) {
      /* Dynamic Huffman codes */

      /* Read header: HLIT, HDIST, HCLEN */
      while (num_bits < 14) {
        if (pSrc >= pSrc_end)
          return MZ_DATA_ERROR;
        bit_buf |= (uint32_t)(*pSrc++) << num_bits;
        num_bits += 8;
      }

      int hlit = (bit_buf & 0x1F) + 257;
      bit_buf >>= 5;
      num_bits -= 5;

      int hdist = (bit_buf & 0x1F) + 1;
      bit_buf >>= 5;
      num_bits -= 5;

      int hclen = (bit_buf & 0xF) + 4;
      bit_buf >>= 4;
      num_bits -= 4;

      if (hlit > 286 || hdist > 30)
        return MZ_DATA_ERROR;

      /* Read code length code lengths */
      uint8_t code_lengths[19];
      memset(code_lengths, 0, sizeof(code_lengths));

      for (int i = 0; i < hclen; i++) {
        while (num_bits < 3) {
          if (pSrc >= pSrc_end)
            return MZ_DATA_ERROR;
          bit_buf |= (uint32_t)(*pSrc++) << num_bits;
          num_bits += 8;
        }
        code_lengths[s_code_order[i]] = bit_buf & 7;
        bit_buf >>= 3;
        num_bits -= 3;
      }

      build_huffman(&code_len_table, code_lengths, 19);

      /* Read literal/length and distance code lengths */
      uint8_t lengths[286 + 30];
      int total = hlit + hdist;
      int i = 0;

      while (i < total) {
        int sym = decode_huffman_simple(&code_len_table, &pSrc, pSrc_end,
                                        &bit_buf, &num_bits);
        if (sym < 0)
          return MZ_DATA_ERROR;

        if (sym < 16) {
          lengths[i++] = sym;
        } else if (sym == 16) {
          /* Copy previous 3-6 times */
          while (num_bits < 2) {
            if (pSrc >= pSrc_end)
              return MZ_DATA_ERROR;
            bit_buf |= (uint32_t)(*pSrc++) << num_bits;
            num_bits += 8;
          }
          int repeat = 3 + (bit_buf & 3);
          bit_buf >>= 2;
          num_bits -= 2;

          if (i == 0)
            return MZ_DATA_ERROR;
          uint8_t prev = lengths[i - 1];
          while (repeat-- > 0 && i < total) {
            lengths[i++] = prev;
          }
        } else if (sym == 17) {
          /* Repeat 0 for 3-10 times */
          while (num_bits < 3) {
            if (pSrc >= pSrc_end)
              return MZ_DATA_ERROR;
            bit_buf |= (uint32_t)(*pSrc++) << num_bits;
            num_bits += 8;
          }
          int repeat = 3 + (bit_buf & 7);
          bit_buf >>= 3;
          num_bits -= 3;

          while (repeat-- > 0 && i < total) {
            lengths[i++] = 0;
          }
        } else if (sym == 18) {
          /* Repeat 0 for 11-138 times */
          while (num_bits < 7) {
            if (pSrc >= pSrc_end)
              return MZ_DATA_ERROR;
            bit_buf |= (uint32_t)(*pSrc++) << num_bits;
            num_bits += 8;
          }
          int repeat = 11 + (bit_buf & 0x7F);
          bit_buf >>= 7;
          num_bits -= 7;

          while (repeat-- > 0 && i < total) {
            lengths[i++] = 0;
          }
        } else {
          return MZ_DATA_ERROR;
        }
      }

      build_huffman(&lit_len_table, lengths, hlit);
      build_huffman(&dist_table, lengths + hlit, hdist);

      /* Decode compressed data */
      for (;;) {
        int sym = decode_huffman_simple(&lit_len_table, &pSrc, pSrc_end,
                                        &bit_buf, &num_bits);
        if (sym < 0)
          return MZ_DATA_ERROR;

        if (sym < 256) {
          if (pDst >= pDst_end)
            return MZ_BUF_ERROR;
          *pDst++ = (uint8_t)sym;
        } else if (sym == 256) {
          break;
        } else {
          int len_idx = sym - 257;
          if (len_idx >= 29)
            return MZ_DATA_ERROR;

          int match_len = s_length_base[len_idx];
          int extra = s_length_extra[len_idx];

          while (num_bits < extra) {
            if (pSrc >= pSrc_end)
              return MZ_DATA_ERROR;
            bit_buf |= (uint32_t)(*pSrc++) << num_bits;
            num_bits += 8;
          }
          match_len += bit_buf & ((1 << extra) - 1);
          bit_buf >>= extra;
          num_bits -= extra;

          int dist_sym = decode_huffman_simple(&dist_table, &pSrc, pSrc_end,
                                               &bit_buf, &num_bits);
          if (dist_sym < 0 || dist_sym >= 30)
            return MZ_DATA_ERROR;

          int match_dist = s_dist_base[dist_sym];
          extra = s_dist_extra[dist_sym];

          while (num_bits < extra) {
            if (pSrc >= pSrc_end)
              return MZ_DATA_ERROR;
            bit_buf |= (uint32_t)(*pSrc++) << num_bits;
            num_bits += 8;
          }
          match_dist += bit_buf & ((1 << extra) - 1);
          bit_buf >>= extra;
          num_bits -= extra;

          if ((size_t)match_dist > (size_t)(pDst - dest))
            return MZ_DATA_ERROR;
          if (pDst + match_len > pDst_end)
            return MZ_BUF_ERROR;

          const uint8_t *pMatch = pDst - match_dist;
          while (match_len-- > 0) {
            *pDst++ = *pMatch++;
          }
        }
      }

    } else {
      /* Invalid block type */
      return MZ_DATA_ERROR;
    }
  }

  *dest_len = pDst - dest;
  return MZ_OK;
}

/* Public API: Raw deflate inflate */
int mz_inflate_raw(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                   size_t source_len) {
  return inflate_raw_impl(dest, dest_len, source, source_len);
}

uint8_t *mz_inflate_raw_alloc(const uint8_t *source, size_t source_len,
                              size_t *dest_len) {
  /* Estimate output size - start with 4x input */
  size_t alloc_size = source_len * 4;
  if (alloc_size < 1024)
    alloc_size = 1024;

  for (int attempt = 0; attempt < 10; attempt++) {
    uint8_t *dest = (uint8_t *)malloc(alloc_size);
    if (!dest)
      return NULL;

    size_t out_len = alloc_size;
    int status = inflate_raw_impl(dest, &out_len, source, source_len);

    if (status == MZ_OK) {
      *dest_len = out_len;
      return dest;
    } else if (status == MZ_BUF_ERROR) {
      free(dest);
      alloc_size *= 2;
      if (alloc_size > 16 * 1024 * 1024) /* Cap at 16MB */
        return NULL;
      continue;
    } else {
      free(dest);
      return NULL;
    }
  }

  return NULL;
}

/* Zlib-wrapped uncompress (with header/trailer) */
int mz_uncompress(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                  size_t source_len) {
  if (source_len < 6)
    return MZ_DATA_ERROR;

  /* Parse zlib header */
  uint8_t cmf = source[0];
  uint8_t flg = source[1];

  if ((cmf & 0x0F) != 8)
    return MZ_DATA_ERROR; /* Must be deflate */
  if (((cmf << 8) | flg) % 31 != 0)
    return MZ_DATA_ERROR; /* Header checksum */
  if (flg & 0x20)
    return MZ_DATA_ERROR; /* Preset dictionary not supported */

  /* Decompress */
  int ret = inflate_raw_impl(dest, dest_len, source + 2, source_len - 6);
  if (ret != MZ_OK)
    return ret;

  /* Verify Adler32 */
  uint32_t computed = adler32(1, dest, *dest_len);
  const uint8_t *p = source + source_len - 4;
  uint32_t stored = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                    ((uint32_t)p[2] << 8) | (uint32_t)p[3];

  if (computed != stored)
    return MZ_DATA_ERROR;

  return MZ_OK;
}

uint8_t *mz_uncompress_alloc(const uint8_t *source, size_t source_len,
                             size_t *dest_len) {
  if (source_len < 6)
    return NULL;

  size_t alloc_size = (source_len - 6) * 4;
  if (alloc_size < 1024)
    alloc_size = 1024;

  for (int attempt = 0; attempt < 10; attempt++) {
    uint8_t *dest = (uint8_t *)malloc(alloc_size);
    if (!dest)
      return NULL;

    size_t out_len = alloc_size;
    int status = mz_uncompress(dest, &out_len, source, source_len);

    if (status == MZ_OK) {
      *dest_len = out_len;
      return dest;
    } else if (status == MZ_BUF_ERROR) {
      free(dest);
      alloc_size *= 2;
      if (alloc_size > 16 * 1024 * 1024)
        return NULL;
      continue;
    } else {
      free(dest);
      return NULL;
    }
  }

  return NULL;
}

/* Raw deflate compression with LZ77 and static Huffman */
int mz_deflate_raw(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                   size_t source_len) {
  return mz_deflate_raw_wbits(dest, dest_len, source, source_len,
                              MZ_DEFAULT_WBITS);
}

int mz_deflate_raw_wbits(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                         size_t source_len, int wbits) {
  if (wbits < 8 || wbits > 15) {
    wbits = MZ_DEFAULT_WBITS;
  }

  size_t window_size = 1U << wbits;
  uint8_t *hist_buf = (uint8_t *)malloc(window_size);
  if (!hist_buf) {
    return MZ_MEM_ERROR;
  }

  mz_compress_state_t state;
  memset(&state, 0, sizeof(state));
  state.out_buf = dest;
  state.out_pos = 0;
  state.out_size = *dest_len;
  state.hist_buf = hist_buf;
  state.hist_max = window_size;
  state.hist_start = 0;
  state.hist_len = 0;

  int ret = start_block(&state);
  if (ret == MZ_OK) {
    ret = lz77_compress(&state, source, source_len);
  }
  if (ret == MZ_OK) {
    ret = finish_block(&state);
  }

  free(hist_buf);

  if (ret == MZ_OK) {
    *dest_len = state.out_pos;
  }
  return ret;
}

uint8_t *mz_deflate_raw_alloc(const uint8_t *source, size_t source_len,
                              size_t *dest_len) {
  return mz_deflate_raw_alloc_wbits(source, source_len, dest_len,
                                    MZ_DEFAULT_WBITS);
}

uint8_t *mz_deflate_raw_alloc_wbits(const uint8_t *source, size_t source_len,
                                    size_t *dest_len, int wbits) {
  /* Worst case: slightly larger than input + overhead */
  size_t alloc_size = source_len + (source_len / 8) + 64;
  if (alloc_size < 256)
    alloc_size = 256;

  uint8_t *dest = (uint8_t *)malloc(alloc_size);
  if (!dest)
    return NULL;

  *dest_len = alloc_size;
  int ret = mz_deflate_raw_wbits(dest, dest_len, source, source_len, wbits);
  if (ret != MZ_OK) {
    free(dest);
    return NULL;
  }

  return dest;
}

/* Zlib-wrapped compression */
size_t mz_compressBound(size_t source_len) {
  /* Compressed data is typically smaller, but worst case can be larger */
  return source_len + (source_len / 8) + 64 + 6;
}

int mz_compress2(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                 size_t source_len, int level) {
  return mz_compress_wbits(dest, dest_len, source, source_len, level,
                           MZ_DEFAULT_WBITS);
}

int mz_compress_wbits(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                      size_t source_len, int level, int wbits) {
  (void)level;

  if (*dest_len < 6) {
    return MZ_BUF_ERROR;
  }

  if (wbits < 8 || wbits > 15) {
    wbits = MZ_DEFAULT_WBITS;
  }

  /* Zlib header (2 bytes) */
  /* CMF: bits 0-3 = CM (8=deflate), bits 4-7 = CINFO (log2(window)-8) */
  uint8_t cmf = 0x08 | ((wbits - 8) << 4);
  /* FLG: bits 0-4 = FCHECK, bit 5 = FDICT (0), bits 6-7 = FLEVEL */
  uint8_t flg = 0x00; /* level 0, will fix checksum below */
  /* FLG checksum: (CMF*256 + FLG) % 31 == 0 */
  flg |= 31 - ((cmf * 256 + flg) % 31);

  dest[0] = cmf;
  dest[1] = flg;

  /* Compress */
  size_t raw_len = *dest_len - 6;
  int ret = mz_deflate_raw_wbits(dest + 2, &raw_len, source, source_len, wbits);
  if (ret != MZ_OK) {
    return ret;
  }

  /* Adler32 trailer (big-endian) */
  uint32_t adler = adler32(1, source, source_len);
  uint8_t *p = dest + 2 + raw_len;
  p[0] = (adler >> 24) & 0xFF;
  p[1] = (adler >> 16) & 0xFF;
  p[2] = (adler >> 8) & 0xFF;
  p[3] = adler & 0xFF;

  *dest_len = 2 + raw_len + 4;
  return MZ_OK;
}

int mz_compress(uint8_t *dest, size_t *dest_len, const uint8_t *source,
                size_t source_len) {
  return mz_compress2(dest, dest_len, source, source_len,
                      MZ_DEFAULT_COMPRESSION);
}

uint8_t *mz_compress_alloc(const uint8_t *source, size_t source_len,
                           size_t *dest_len, int level) {
  return mz_compress_alloc_wbits(source, source_len, dest_len, level,
                                 MZ_DEFAULT_WBITS);
}

uint8_t *mz_compress_alloc_wbits(const uint8_t *source, size_t source_len,
                                 size_t *dest_len, int level, int wbits) {
  size_t alloc_size = mz_compressBound(source_len);
  uint8_t *dest = (uint8_t *)malloc(alloc_size);
  if (!dest)
    return NULL;

  *dest_len = alloc_size;
  int ret = mz_compress_wbits(dest, dest_len, source, source_len, level, wbits);
  if (ret != MZ_OK) {
    free(dest);
    return NULL;
  }

  return dest;
}
