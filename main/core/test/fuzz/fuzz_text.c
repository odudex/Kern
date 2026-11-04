/* Text parsers fed straight from QR codes and files. */
#include "core/descriptor_text.h"
#include "core/message_sign.h"
#include "core/multisig_setup.h"
#include "fuzz.h"
#include "utils/text_file.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>

void fuzz_load_test_key(void) {
  static bool done;
  if (!done && wally_init(0) != WALLY_OK)
    abort();
  done = true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  fuzz_load_test_key();
  if (size > 8192)
    return 0;
  char *text = malloc(size + 1);
  if (!text)
    return 0;
  memcpy(text, data, size);
  text[size] = '\0';

  parsed_sign_message_t message;
  if (message_sign_parse(text, &message))
    message_sign_free_parsed(&message);
  free(multisig_setup_to_descriptor(text));
  free(descriptor_to_unambiguous(text));
  free(text_file_normalize(data, size));
  free(text);
  return 0;
}
