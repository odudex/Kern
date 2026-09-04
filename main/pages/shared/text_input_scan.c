#include "text_input_scan.h"
#include "../../../components/cUR/src/types/bytes_type.h"
#include "../../qr/parser.h"
#include "../../qr/scanner.h"
#include "../../ui/dialog.h"
#include "../../utils/secure_mem.h"
#include "../../utils/utf8.h"
#include <stdlib.h>
#include <string.h>

static text_input_scan_cfg_t s_cfg;
static bool s_active = false;

// Must run before qr_scanner_page_destroy(). NULL with *err unset means cancel
// or a failure the scanner already reported.
static char *extract_text(size_t *len, const char **err) {
  if (qr_scanner_get_format() != FORMAT_UR)
    return qr_scanner_get_completed_content_with_len(len);

  const char *ur_type = NULL;
  const uint8_t *cbor = NULL;
  size_t cbor_len = 0;
  char *text = NULL;
  if (qr_scanner_get_ur_result(&ur_type, &cbor, &cbor_len) && ur_type &&
      strcmp(ur_type, "bytes") == 0) {
    bytes_data_t *bytes = bytes_from_cbor(cbor, cbor_len);
    if (bytes) {
      size_t n = 0;
      const uint8_t *data = bytes_get_data(bytes, &n);
      text = malloc(n + 1);
      if (text) {
        memcpy(text, data, n);
        text[n] = '\0';
        *len = n;
      }
      bytes_free(bytes);
    }
  }
  if (!text)
    *err = "Unsupported QR content";
  return text;
}

static const char *validate(const char *text, size_t len, bool *is_ascii) {
  if (len == 0)
    return "Empty QR content";
  if (strlen(text) != len)
    return "QR content is not text";
  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)text[i];
    if (c < 0x20 || c == 0x7F)
      return "QR content is not text";
  }
  if (!utf8_is_valid((const uint8_t *)text, len, is_ascii))
    return "QR content is not text";
  return NULL;
}

static void scan_return_cb(void) {
  size_t len = 0;
  const char *err = NULL;
  char *text = extract_text(&len, &err);

  qr_scanner_page_hide();
  qr_scanner_page_destroy();

  s_active = false;
  if (s_cfg.show_page)
    s_cfg.show_page();

  if (!text) {
    if (err)
      dialog_show_error_timeout(err, NULL, 0);
    return;
  }

  // Common QR generators append a newline the keyboard could never type.
  if (len > 0 && text[len - 1] == '\n')
    text[--len] = '\0';
  if (len > 0 && text[len - 1] == '\r')
    text[--len] = '\0';

  bool is_ascii = true;
  err = validate(text, len, &is_ascii);
  if (err) {
    dialog_show_error_timeout(err, NULL, 0);
  } else {
    if (s_cfg.input && s_cfg.input->textarea)
      lv_textarea_set_text(s_cfg.input->textarea, text);
    if (s_cfg.loaded_cb)
      s_cfg.loaded_cb();
    if (!is_ascii)
      dialog_show_info("Non-ASCII text",
                       "The scanned text contains non-ASCII characters. This "
                       "is not recommended: other software may encode them "
                       "differently and derive a different key.",
                       NULL, NULL, DIALOG_STYLE_OVERLAY);
  }
  SECURE_FREE_BUFFER(text, len);
}

void text_input_scan_start(const text_input_scan_cfg_t *cfg) {
  if (s_active || !cfg || !cfg->input)
    return;
  s_cfg = *cfg;
  s_active = true;
  if (s_cfg.hide_page)
    s_cfg.hide_page();
  qr_scanner_page_create(NULL, scan_return_cb);
  qr_scanner_page_show();
}
