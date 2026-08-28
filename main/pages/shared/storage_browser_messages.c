#include "storage_browser_messages.h"

#include <stdio.h>
#include <string.h>

const char *storage_browser_list_message(storage_browser_list_outcome_t outcome,
                                         const char *item_type_name,
                                         char *message, size_t message_size) {
  if (!message || message_size == 0)
    return NULL;

  switch (outcome) {
  case STORAGE_BROWSER_LIST_READY:
    return NULL;
  case STORAGE_BROWSER_LIST_EMPTY:
    break;
  case STORAGE_BROWSER_LIST_SD_UNAVAILABLE:
    snprintf(message, message_size, "%s", "SD card unavailable");
    return message;
  case STORAGE_BROWSER_LIST_INTERNAL_ERROR:
  default:
    snprintf(message, message_size, "%s", "Storage unavailable");
    return message;
  }

  if (item_type_name && strcmp(item_type_name, "mnemonic") == 0) {
    snprintf(message, message_size, "%s", "No mnemonic backups found");
  } else if (item_type_name && item_type_name[0] != '\0') {
    snprintf(message, message_size, "No %ss found", item_type_name);
  } else {
    snprintf(message, message_size, "%s", "No files found");
  }
  return message;
}
