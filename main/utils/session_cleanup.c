#include "session_cleanup.h"
#include <stdlib.h>

#define MAX_SESSION_CLEANUPS 64
static session_cleanup_fn cleanups[MAX_SESSION_CLEANUPS];
static unsigned cleanup_count;

void session_cleanup_unregister(session_cleanup_fn cleanup) {
  for (unsigned i = 0; i < cleanup_count; ++i) {
    if (cleanups[i] == cleanup) {
      for (unsigned j = i + 1; j < cleanup_count; ++j)
        cleanups[j - 1] = cleanups[j];
      cleanups[--cleanup_count] = NULL;
      return;
    }
  }
}

void session_cleanup_register(session_cleanup_fn cleanup) {
  if (!cleanup)
    return;
  for (unsigned i = 0; i < cleanup_count; ++i)
    if (cleanups[i] == cleanup)
      return;
  /* A missing cleanup is a security failure, not a recoverable omission. */
  if (cleanup_count == MAX_SESSION_CLEANUPS)
    abort();
  cleanups[cleanup_count++] = cleanup;
}

void session_cleanup_run(void) {
  /* Child flows are registered after parents. Pop before calling: a parent
   * may also unregister/destroy children, and must never run twice here. */
  while (cleanup_count) {
    session_cleanup_fn cleanup = cleanups[--cleanup_count];
    cleanups[cleanup_count] = NULL;
    cleanup();
  }
}
