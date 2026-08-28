#ifndef STORAGE_BROWSER_MESSAGES_H
#define STORAGE_BROWSER_MESSAGES_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
  STORAGE_BROWSER_LIST_READY,
  STORAGE_BROWSER_LIST_EMPTY,
  STORAGE_BROWSER_LIST_SD_UNAVAILABLE,
  STORAGE_BROWSER_LIST_INTERNAL_ERROR,
} storage_browser_list_outcome_t;

/**
 * Return a user-facing listing status, or NULL when files can be displayed.
 * The caller owns message and must keep it alive while using the result.
 */
const char *storage_browser_list_message(storage_browser_list_outcome_t outcome,
                                         const char *item_type_name,
                                         char *message, size_t message_size);

#endif /* STORAGE_BROWSER_MESSAGES_H */
