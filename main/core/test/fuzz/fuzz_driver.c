/*
 * Mutation driver for compilers without libFuzzer (gcc): runs every seed,
 * then a fixed number of mutations of random seeds through
 * LLVMFuzzerTestOneInput. Deterministic for a given -s seed, so a crash
 * reproduces. Coverage-blind; with clang build the targets with
 * -fsanitize=fuzzer instead.
 *
 *   fuzz_<target> [-n iterations] [-s seed] seed-file-or-@json:file ...
 *
 * "@json:<file>" takes every base64 PSBT ("cHNidP...") in a JSON file, such as
 * libwally's src/data/psbt.json, as a seed.
 */
#include "fuzz.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>

#define MAX_SEEDS 4096
#define FUZZ_MAX_INPUT (1 << 16)

static uint8_t *seeds[MAX_SEEDS];
static size_t seed_lens[MAX_SEEDS];
static size_t num_seeds;
static uint64_t rng_state;

static uint32_t rnd(void) {
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return (uint32_t)rng_state;
}

static void add_seed(const uint8_t *data, size_t len) {
  if (num_seeds == MAX_SEEDS || len > FUZZ_MAX_INPUT)
    return;
  uint8_t *copy = malloc(len ? len : 1);
  if (!copy)
    return;
  memcpy(copy, data, len);
  seeds[num_seeds] = copy;
  seed_lens[num_seeds++] = len;
}

static uint8_t *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return NULL;
  uint8_t *buf = malloc(FUZZ_MAX_INPUT * 4);
  size_t n = buf ? fread(buf, 1, FUZZ_MAX_INPUT * 4, f) : 0;
  fclose(f);
  *len = n;
  return buf;
}

static void add_json_psbts(const char *path) {
  size_t len = 0;
  char *text = (char *)read_file(path, &len);
  if (!text)
    return;
  text[len < FUZZ_MAX_INPUT * 4 ? len : len - 1] = '\0';
  for (char *p = strstr(text, "\"cHNidP"); p; p = strstr(p + 1, "\"cHNidP")) {
    char *end = strchr(p + 1, '"');
    if (!end)
      break;
    *end = '\0';
    uint8_t *bytes = malloc(FUZZ_MAX_INPUT);
    size_t written = 0;
    if (bytes && wally_base64_to_bytes(p + 1, 0, bytes, FUZZ_MAX_INPUT,
                                       &written) == WALLY_OK)
      add_seed(bytes, written);
    free(bytes);
    *end = '"';
  }
  free(text);
}

static void add_path(const char *path) {
  if (strncmp(path, "@json:", 6) == 0) {
    add_json_psbts(path + 6);
    return;
  }
  DIR *dir = opendir(path);
  if (dir) {
    struct dirent *e;
    while ((e = readdir(dir))) {
      if (e->d_name[0] == '.')
        continue;
      char sub[1024];
      snprintf(sub, sizeof(sub), "%s/%s", path, e->d_name);
      add_path(sub);
    }
    closedir(dir);
    return;
  }
  size_t len = 0;
  uint8_t *data = read_file(path, &len);
  if (data)
    add_seed(data, len);
  free(data);
}

static size_t mutate(uint8_t *buf, size_t len, size_t cap) {
  int rounds = 1 + rnd() % 4;
  while (rounds--) {
    uint32_t op = rnd() % 6;
    if (len == 0)
      op = 2;
    size_t at = len ? rnd() % len : 0;
    switch (op) {
    case 0: /* flip a bit */
      buf[at] ^= (uint8_t)(1u << (rnd() % 8));
      break;
    case 1: /* set a byte to an interesting value */ {
      static const uint8_t vals[] = {0x00, 0x01, 0x7f, 0x80, 0xff, 0xfd, 0x20};
      buf[at] = vals[rnd() % sizeof(vals)];
      break;
    }
    case 2: /* insert a byte */
      if (len < cap) {
        memmove(buf + at + 1, buf + at, len - at);
        buf[at] = (uint8_t)rnd();
        len++;
      }
      break;
    case 3: /* delete a run */ {
      size_t n = 1 + rnd() % 8;
      if (n > len - at)
        n = len - at;
      memmove(buf + at, buf + at + n, len - at - n);
      len -= n;
      break;
    }
    case 4: /* duplicate a run */ {
      size_t n = 1 + rnd() % 16;
      if (n > len - at)
        n = len - at;
      if (len + n <= cap) {
        memmove(buf + at + n, buf + at, len - at);
        len += n;
      }
      break;
    }
    case 5: /* splice in part of another seed */ {
      if (!num_seeds)
        break;
      size_t s = rnd() % num_seeds;
      if (!seed_lens[s])
        break;
      size_t from = rnd() % seed_lens[s];
      size_t n = 1 + rnd() % (seed_lens[s] - from);
      if (at + n > cap)
        n = cap - at;
      memcpy(buf + at, seeds[s] + from, n);
      if (at + n > len)
        len = at + n;
      break;
    }
    }
  }
  return len;
}

int main(int argc, char **argv) {
  unsigned long iterations = 20000;
  rng_state = 0x4b45524e;
  int i = 1;
  for (; i < argc && argv[i][0] == '-'; i += 2) {
    if (i + 1 >= argc)
      break;
    if (strcmp(argv[i], "-n") == 0)
      iterations = strtoul(argv[i + 1], NULL, 10);
    else if (strcmp(argv[i], "-s") == 0)
      rng_state = strtoull(argv[i + 1], NULL, 10) | 1;
  }
  for (; i < argc; i++)
    add_path(argv[i]);
  if (!num_seeds) {
    static const uint8_t empty[1] = {0};
    add_seed(empty, 0);
  }

  for (size_t s = 0; s < num_seeds; s++)
    LLVMFuzzerTestOneInput(seeds[s], seed_lens[s]);

  uint8_t *buf = malloc(FUZZ_MAX_INPUT);
  if (!buf)
    return 1;
  for (unsigned long n = 0; n < iterations; n++) {
    size_t s = rnd() % num_seeds;
    size_t len = seed_lens[s];
    memcpy(buf, seeds[s], len);
    len = mutate(buf, len, FUZZ_MAX_INPUT);
    LLVMFuzzerTestOneInput(buf, len);
  }
  printf("%s: %zu seeds, %lu mutations, no crash\n", argv[0], num_seeds,
         iterations);
  free(buf);
  for (size_t s = 0; s < num_seeds; s++)
    free(seeds[s]);
  return 0;
}
