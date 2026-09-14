#include "esp_heap_caps.h"
#include "secure_memory.h"
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool exhausted;
static unsigned requests;
void *heap_caps_malloc(size_t size, unsigned caps) {
  assert(caps == (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
  ++requests;
  return exhausted ? NULL : malloc(size);
}
int main(void) {
  char *s = kern_secret_strdup("public fixture");
  assert(s && !strcmp(s, "public fixture"));
  free(s);
  exhausted = true;
  unsigned before = requests;
  assert(!kern_secret_alloc(256));
  assert(requests == before + 1); /* Exactly one attempt, no fallback. */
  assert(!kern_secret_strdup("secret"));
  assert(requests == before + 2);
  exhausted = false;
  s = kern_secret_strndup("abcde", 3);
  assert(s && !strcmp(s, "abc"));
  free(s);
  return 0;
}
