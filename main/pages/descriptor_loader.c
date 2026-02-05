#include "descriptor_loader.h"
#include "../../components/cUR/src/types/output.h"
#include "../qr/parser.h"
#include "../qr/scanner.h"
#include "../ui/dialog.h"
#include <stdlib.h>
#include <string.h>

bool descriptor_loader_show_error(descriptor_validation_result_t result) {
  switch (result) {
  case VALIDATION_SUCCESS:
  case VALIDATION_USER_DECLINED:
    return false;

  case VALIDATION_FINGERPRINT_NOT_FOUND:
    dialog_show_error("Key not found in descriptor", NULL, 2000);
    return true;

  case VALIDATION_XPUB_MISMATCH:
    dialog_show_error("XPub mismatch - check passphrase", NULL, 2000);
    return true;

  case VALIDATION_PARSE_ERROR:
    dialog_show_error("Invalid descriptor format", NULL, 2000);
    return true;

  case VALIDATION_INTERNAL_ERROR:
  default:
    dialog_show_error("Validation failed", NULL, 2000);
    return true;
  }
}

// UI confirmation wrapper: bridges validation_confirm_cb to dialog_show_confirm
static void descriptor_confirm_wrapper(const char *message,
                                       void (*proceed)(bool confirmed,
                                                       void *user_data)) {
  dialog_show_confirm(message, proceed, NULL, DIALOG_STYLE_FULLSCREEN);
}

void descriptor_loader_process_scanner(validation_complete_cb validation_cb,
                                       void *user_data,
                                       void (*error_cb)(void)) {
  char *descriptor_str = descriptor_extract_from_scanner();

  qr_scanner_page_hide();
  qr_scanner_page_destroy();

  if (descriptor_str) {
    char *unambiguous = descriptor_to_unambiguous(descriptor_str);
    descriptor_validate_and_load(unambiguous ? unambiguous : descriptor_str,
                                 validation_cb, descriptor_confirm_wrapper,
                                 user_data);
    free(unambiguous);
    free(descriptor_str);
  } else {
    dialog_show_error("Unsupported descriptor format", NULL, 2000);
    if (error_cb) {
      error_cb();
    }
  }
}

char *descriptor_extract_from_scanner(void) {
  int format = qr_scanner_get_format();

  if (format == FORMAT_UR) {
    const uint8_t *cbor_data = NULL;
    size_t cbor_len = 0;

    if (qr_scanner_get_ur_result(NULL, &cbor_data, &cbor_len)) {
      // Try crypto-output first, then crypto-account
      output_data_t *output = output_from_cbor(cbor_data, cbor_len);
      if (output) {
        char *descriptor = output_descriptor(output, true);
        output_free(output);
        return descriptor;
      }
      return output_descriptor_from_cbor_account(cbor_data, cbor_len);
    }
    return NULL;
  }

  return qr_scanner_get_completed_content();
}

static bool is_base58_char(char c) {
  return (c >= '1' && c <= '9') || (c >= 'A' && c <= 'H') ||
         (c >= 'J' && c <= 'N') || (c >= 'P' && c <= 'Z') ||
         (c >= 'a' && c <= 'k') || (c >= 'm' && c <= 'z');
}

char *descriptor_to_unambiguous(const char *descriptor) {
  if (!descriptor)
    return NULL;

  size_t desc_len = strlen(descriptor);

  // Strip checksum if present (#xxxxxxxx)
  size_t content_len = desc_len;
  if (desc_len > 9 && descriptor[desc_len - 9] == '#')
    content_len = desc_len - 9;

  // Count keys needing modification
  size_t modifications_needed = 0;
  const char *search = descriptor;
  const char *content_end = descriptor + content_len;

  while ((search = strstr(search, "pub")) != NULL && search < content_end) {
    if (search > descriptor && (*(search - 1) == 'x' || *(search - 1) == 't')) {
      const char *key_end = search + 3;
      while (key_end < content_end && is_base58_char(*key_end))
        key_end++;

      if (key_end >= content_end || *key_end != '/')
        modifications_needed++;
    }
    search += 3;
  }

  if (modifications_needed == 0)
    return NULL;

  size_t new_len = content_len + (modifications_needed * 8) + 1;
  char *result = malloc(new_len);
  if (!result)
    return NULL;

  const char *src = descriptor;
  char *dst = result;

  while (src < content_end) {
    if ((src[0] == 'x' || src[0] == 't') && src + 3 < content_end &&
        strncmp(src + 1, "pub", 3) == 0) {
      *dst++ = *src++;
      *dst++ = *src++;
      *dst++ = *src++;
      *dst++ = *src++;

      while (src < content_end && is_base58_char(*src))
        *dst++ = *src++;

      if (src >= content_end || *src != '/') {
        memcpy(dst, "/<0;1>/*", 8);
        dst += 8;
      }
    } else {
      *dst++ = *src++;
    }
  }
  *dst = '\0';

  return result;
}
