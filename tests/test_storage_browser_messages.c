#include "../main/pages/shared/storage_browser_messages.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  char message[64];
  const char *result;

  result = storage_browser_list_message(STORAGE_BROWSER_LIST_SD_UNAVAILABLE,
                                        "mnemonic", message, sizeof(message));
  assert(result != NULL);
  assert(strcmp(result, "SD card unavailable") == 0);

  result = storage_browser_list_message(STORAGE_BROWSER_LIST_INTERNAL_ERROR,
                                        "mnemonic", message, sizeof(message));
  assert(result != NULL);
  assert(strcmp(result, "Storage unavailable") == 0);

  result = storage_browser_list_message(STORAGE_BROWSER_LIST_EMPTY, "mnemonic",
                                        message, sizeof(message));
  assert(result != NULL);
  assert(strcmp(result, "No mnemonic backups found") == 0);

  result = storage_browser_list_message(STORAGE_BROWSER_LIST_EMPTY,
                                        "descriptor", message, sizeof(message));
  assert(result != NULL);
  assert(strcmp(result, "No descriptors found") == 0);

  result = storage_browser_list_message(STORAGE_BROWSER_LIST_EMPTY, "file",
                                        message, sizeof(message));
  assert(result != NULL);
  assert(strcmp(result, "No files found") == 0);

  result = storage_browser_list_message(STORAGE_BROWSER_LIST_READY, "mnemonic",
                                        message, sizeof(message));
  assert(result == NULL);

  result = storage_browser_list_message((storage_browser_list_outcome_t)999,
                                        "mnemonic", message, sizeof(message));
  assert(result != NULL);
  assert(strcmp(result, "Storage unavailable") == 0);

  puts("storage browser message tests passed");
  return 0;
}
