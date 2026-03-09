#include "descriptor_loader.h"
#include "../../../components/cUR/src/types/bytes_type.h"
#include "../../../components/cUR/src/types/output.h"
#include "../../core/key.h"
#include "../../qr/parser.h"
#include "../../qr/scanner.h"
#include "../../ui/assets/icons_24.h"
#include "../../ui/dialog.h"
#include "../../ui/key_info.h"
#include "../../ui/menu.h"
#include "../../ui/theme.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>

// Convert extended pubkey with non-standard version bytes to xpub/tpub.
// Handles Zpub, Ypub (mainnet) and Vpub, Upub (testnet).
static char *convert_xpub_version(const char *key) {
  static const struct {
    uint8_t from[4], to[4];
  } version_map[] = {
      {{0x02, 0xaa, 0x7e, 0xd3}, {0x04, 0x88, 0xb2, 0x1e}}, // Zpub -> xpub
      {{0x02, 0x95, 0xb4, 0x3f}, {0x04, 0x88, 0xb2, 0x1e}}, // Ypub -> xpub
      {{0x04, 0x5f, 0x1c, 0xf6}, {0x04, 0x35, 0x87, 0xcf}}, // Vpub -> tpub
      {{0x04, 0x4a, 0x52, 0x62}, {0x04, 0x35, 0x87, 0xcf}}, // Upub -> tpub
  };

  uint8_t decoded[78 + BASE58_CHECKSUM_LEN];
  size_t written = 0;
  if (wally_base58_to_bytes(key, BASE58_FLAG_CHECKSUM, decoded, sizeof(decoded),
                            &written) != WALLY_OK ||
      written != 78)
    return NULL;

  for (size_t i = 0; i < sizeof(version_map) / sizeof(version_map[0]); i++) {
    if (memcmp(decoded, version_map[i].from, 4) == 0) {
      memcpy(decoded, version_map[i].to, 4);
      goto encode;
    }
  }

  // Already xpub/tpub — re-encode unchanged
  if (memcmp(decoded, "\x04\x88\xb2\x1e", 4) != 0 &&
      memcmp(decoded, "\x04\x35\x87\xcf", 4) != 0)
    return NULL;

encode:;
  char *wally_str = NULL;
  if (wally_base58_from_bytes(decoded, written, BASE58_FLAG_CHECKSUM,
                              &wally_str) != WALLY_OK)
    return NULL;
  char *result = strdup(wally_str);
  wally_free_string(wally_str);
  return result;
}

// Parse BlueWallet multisig setup file into a standard descriptor.
static char *bluewallet_to_descriptor(const char *text) {
  if (!text)
    return NULL;

  const char *policy_line = strstr(text, "Policy:");
  const char *deriv_line = strstr(text, "Derivation:");
  const char *format_line = strstr(text, "Format:");
  if (!policy_line || !deriv_line || !format_line)
    return NULL;

  unsigned int threshold = 0, num_keys = 0;
  if (sscanf(policy_line, "Policy: %u of %u", &threshold, &num_keys) != 2 ||
      threshold == 0 || num_keys == 0 || threshold > num_keys || num_keys > 15)
    return NULL;

  char derivation[64] = {0};
  if (sscanf(deriv_line, "Derivation: %63s", derivation) != 1)
    return NULL;
  const char *origin_path = derivation;
  if (origin_path[0] == 'm' && origin_path[1] == '/')
    origin_path += 2;

  char format[16] = {0};
  sscanf(format_line, "Format: %15s", format);
  const char *wrapper_open, *wrapper_close;
  if (strcasecmp(format, "P2WSH") == 0) {
    wrapper_open = "wsh(";
    wrapper_close = ")";
  } else if (strcasecmp(format, "P2SH-P2WSH") == 0 ||
             strcasecmp(format, "P2WSH-P2SH") == 0) {
    wrapper_open = "sh(wsh(";
    wrapper_close = "))";
  } else if (strcasecmp(format, "P2SH") == 0) {
    wrapper_open = "sh(";
    wrapper_close = ")";
  } else {
    return NULL;
  }

  char fingerprints[15][9];
  char *xpubs[15];
  unsigned int found_keys = 0;
  memset(xpubs, 0, sizeof(xpubs));

  const char *line = text;
  while (*line && found_keys < num_keys) {
    while (*line == ' ' || *line == '\t')
      line++;

    if (strlen(line) > 10) {
      bool is_hex = true;
      for (int i = 0; i < 8 && is_hex; i++)
        is_hex = isxdigit((unsigned char)line[i]);

      if (is_hex && line[8] == ':' && line[9] == ' ') {
        for (int i = 0; i < 8; i++)
          fingerprints[found_keys][i] = tolower((unsigned char)line[i]);
        fingerprints[found_keys][8] = '\0';

        const char *key_start = line + 10;
        const char *key_end = key_start;
        while (*key_end && *key_end != '\n' && *key_end != '\r' &&
               *key_end != ' ')
          key_end++;

        char *raw_key = malloc(key_end - key_start + 1);
        if (!raw_key)
          goto cleanup;
        memcpy(raw_key, key_start, key_end - key_start);
        raw_key[key_end - key_start] = '\0';

        xpubs[found_keys] = convert_xpub_version(raw_key);
        free(raw_key);
        if (!xpubs[found_keys])
          goto cleanup;
        found_keys++;
      }
    }

    while (*line && *line != '\n')
      line++;
    if (*line == '\n')
      line++;
  }

  if (found_keys != num_keys)
    goto cleanup;

  size_t desc_size = 64;
  for (unsigned int i = 0; i < num_keys; i++)
    desc_size += 8 + strlen(origin_path) + strlen(xpubs[i]) + 5;

  char *descriptor = malloc(desc_size);
  if (!descriptor)
    goto cleanup;

  int pos = snprintf(descriptor, desc_size, "%ssortedmulti(%u", wrapper_open,
                     threshold);
  for (unsigned int i = 0; i < num_keys; i++)
    pos += snprintf(descriptor + pos, desc_size - pos, ",[%s/%s]%s",
                    fingerprints[i], origin_path, xpubs[i]);
  snprintf(descriptor + pos, desc_size - pos, ")%s", wrapper_close);

  for (unsigned int i = 0; i < found_keys; i++)
    free(xpubs[i]);
  return descriptor;

cleanup:
  for (unsigned int i = 0; i < found_keys; i++)
    free(xpubs[i]);
  return NULL;
}

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

// Context for descriptor info confirmation dialog
typedef struct {
  void (*proceed)(bool confirmed, void *user_data);
  lv_obj_t *root;
} info_confirm_context_t;

static void info_confirm_respond(lv_event_t *e, bool confirmed) {
  info_confirm_context_t *ctx = lv_event_get_user_data(e);
  if (!ctx)
    return;
  void (*proceed)(bool, void *) = ctx->proceed;
  if (ctx->root)
    lv_obj_del(ctx->root);
  free(ctx);
  if (proceed)
    proceed(confirmed, NULL);
}

static void info_confirm_yes_cb(lv_event_t *e) {
  info_confirm_respond(e, true);
}

static void info_confirm_no_cb(lv_event_t *e) {
  info_confirm_respond(e, false);
}

// Trim xpub for display: first 12 chars + "..." + last 8 chars
static void trim_xpub_for_display(const char *xpub, char *out,
                                  size_t out_size) {
  size_t len = strlen(xpub);
  if (len <= 23) {
    strncpy(out, xpub, out_size - 1);
    out[out_size - 1] = '\0';
    return;
  }
  snprintf(out, out_size, "%.12s...%.8s", xpub, xpub + len - 8);
}

// UI wrapper for descriptor info confirmation
static void descriptor_info_confirm_wrapper(const descriptor_info_t *info,
                                            void (*proceed)(bool confirmed,
                                                            void *user_data)) {
  info_confirm_context_t *ctx = malloc(sizeof(info_confirm_context_t));
  if (!ctx) {
    proceed(false, NULL);
    return;
  }
  ctx->proceed = proceed;

  // Create fullscreen container
  lv_obj_t *root = lv_obj_create(lv_screen_active());
  lv_obj_set_size(root, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(root);
  lv_obj_clear_flag(root, LV_OBJ_FLAG_SCROLLABLE);
  ctx->root = root;

  // Title with "Load?" prompt
  char title[48];
  if (info->is_multisig) {
    snprintf(title, sizeof(title), "Multisig (%u of %u) - Load?",
             info->threshold, info->num_keys);
  } else {
    snprintf(title, sizeof(title), "Single-sig - Load?");
  }
  lv_obj_t *title_label = theme_create_label(root, title, false);
  lv_obj_set_style_text_font(title_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(title_label, highlight_color(), 0);
  lv_obj_set_style_text_align(title_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(title_label, LV_PCT(100));
  lv_obj_align(title_label, LV_ALIGN_TOP_MID, 0, 10);

  // Scrollable content area (between title and buttons)
  lv_coord_t title_h = theme_font_medium()->line_height + 20;
  lv_coord_t btn_h = theme_get_button_height();
  lv_obj_t *scroll = lv_obj_create(root);
  lv_obj_set_width(scroll, LV_PCT(100));
  lv_obj_set_height(scroll, LV_VER_RES - title_h - btn_h);
  lv_obj_align(scroll, LV_ALIGN_TOP_LEFT, 0, title_h);
  lv_obj_set_style_bg_opa(scroll, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(scroll, 0, 0);
  lv_obj_set_style_pad_all(scroll, 10, 0);
  lv_obj_set_style_pad_row(scroll, 4, 0);
  lv_obj_set_flex_flow(scroll, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(scroll, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_START);
  lv_obj_add_flag(scroll, LV_OBJ_FLAG_SCROLLABLE);

  // Get current wallet fingerprint for highlighting
  char my_fp[9] = {0};
  key_get_fingerprint_hex(my_fp);

  // Key entries
  for (uint32_t i = 0; i < info->num_keys; i++) {
    // Letter + fingerprint on same row
    char letter_fp[20];
    snprintf(letter_fp, sizeof(letter_fp), "%c: %s", 'A' + (char)i,
             info->keys[i].fingerprint_hex);
    bool is_ours = (my_fp[0] != '\0' &&
                    strcasecmp(my_fp, info->keys[i].fingerprint_hex) == 0);
    lv_obj_t *fp_row =
        ui_icon_text_row_create(scroll, ICON_FINGERPRINT, letter_fp,
                                is_ours ? highlight_color() : main_color());
    if (i > 0)
      lv_obj_set_style_pad_top(fp_row, 12, 0);

    // Trimmed xpub (indented)
    char trimmed[24];
    trim_xpub_for_display(info->keys[i].xpub, trimmed, sizeof(trimmed));
    lv_obj_t *xpub_label = theme_create_label(scroll, trimmed, false);
    lv_obj_set_style_text_color(xpub_label, secondary_color(), 0);
    lv_obj_set_style_text_font(xpub_label, theme_font_small(), 0);
    lv_obj_set_style_pad_left(xpub_label, 20, 0);

    // Derivation path row (indented)
    lv_obj_t *deriv_row = ui_icon_text_row_create(
        scroll, ICON_DERIVATION, info->keys[i].derivation, secondary_color());
    lv_obj_set_style_pad_left(deriv_row, 20, 0);
  }

  // Button row (fixed at bottom)
  lv_obj_t *no_btn = theme_create_button(root, "No", false);
  lv_obj_set_size(no_btn, LV_PCT(50), theme_get_button_height());
  lv_obj_align(no_btn, LV_ALIGN_BOTTOM_LEFT, 0, 0);
  lv_obj_add_event_cb(no_btn, info_confirm_no_cb, LV_EVENT_CLICKED, ctx);
  lv_obj_t *no_label = lv_obj_get_child(no_btn, 0);
  if (no_label) {
    lv_obj_set_style_text_color(no_label, no_color(), 0);
    lv_obj_set_style_text_font(no_label, theme_font_medium(), 0);
  }

  lv_obj_t *yes_btn = theme_create_button(root, "Yes", true);
  lv_obj_set_size(yes_btn, LV_PCT(50), theme_get_button_height());
  lv_obj_align(yes_btn, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
  lv_obj_add_event_cb(yes_btn, info_confirm_yes_cb, LV_EVENT_CLICKED, ctx);
  lv_obj_t *yes_label = lv_obj_get_child(yes_btn, 0);
  if (yes_label) {
    lv_obj_set_style_text_color(yes_label, yes_color(), 0);
    lv_obj_set_style_text_font(yes_label, theme_font_medium(), 0);
  }
}

void descriptor_loader_process_scanner(validation_complete_cb validation_cb,
                                       void *user_data,
                                       void (*error_cb)(void)) {
  char *descriptor_str = descriptor_extract_from_scanner();

  qr_scanner_page_hide();
  qr_scanner_page_destroy();

  if (descriptor_str) {
    char *converted = bluewallet_to_descriptor(descriptor_str);
    const char *to_process = converted ? converted : descriptor_str;
    char *unambiguous = descriptor_to_unambiguous(to_process);
    descriptor_validate_and_load(unambiguous ? unambiguous : to_process,
                                 validation_cb, descriptor_confirm_wrapper,
                                 descriptor_info_confirm_wrapper, user_data);
    free(unambiguous);
    free(converted);
    free(descriptor_str);
  } else {
    dialog_show_error("Unsupported descriptor format", NULL, 2000);
    if (error_cb) {
      error_cb();
    }
  }
}

void descriptor_loader_process_string(const char *descriptor_str,
                                      validation_complete_cb validation_cb,
                                      void *user_data) {
  if (!descriptor_str) {
    if (validation_cb)
      validation_cb(VALIDATION_PARSE_ERROR, user_data);
    return;
  }

  char *converted = bluewallet_to_descriptor(descriptor_str);
  const char *to_process = converted ? converted : descriptor_str;
  char *unambiguous = descriptor_to_unambiguous(to_process);
  descriptor_validate_and_load(unambiguous ? unambiguous : to_process,
                               validation_cb, descriptor_confirm_wrapper,
                               descriptor_info_confirm_wrapper, user_data);
  free(unambiguous);
  free(converted);
}

/* ---------- Source selection menu ---------- */

static ui_menu_t *source_menu = NULL;

void descriptor_loader_show_source_menu(lv_obj_t *parent, void (*qr_cb)(void),
                                        void (*flash_cb)(void),
                                        void (*sd_cb)(void),
                                        void (*back_cb)(void)) {
  descriptor_loader_destroy_source_menu();

  source_menu = ui_menu_create(parent, "Load Descriptor", back_cb);
  if (!source_menu)
    return;

  ui_menu_add_entry(source_menu, "From QR Code", qr_cb);
  ui_menu_add_entry(source_menu, "From Flash", flash_cb);
  ui_menu_add_entry(source_menu, "From SD Card", sd_cb);
  ui_menu_show(source_menu);
}

void descriptor_loader_destroy_source_menu(void) {
  if (source_menu) {
    ui_menu_destroy(source_menu);
    source_menu = NULL;
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
      char *account_desc =
          output_descriptor_from_cbor_account(cbor_data, cbor_len);
      if (account_desc)
        return account_desc;

      bytes_data_t *bytes = bytes_from_cbor(cbor_data, cbor_len);
      if (bytes) {
        size_t len = 0;
        const uint8_t *data = bytes_get_data(bytes, &len);
        char *text = (data && len > 0) ? strndup((const char *)data, len) : NULL;
        bytes_free(bytes);
        return text;
      }
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
