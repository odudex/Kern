#include "descriptor_loader.h"
#include "../../../components/cUR/src/types/output.h"
#include "../../qr/parser.h"
#include "../../qr/scanner.h"
#include "../../ui/assets/icons_24.h"
#include "../../ui/dialog.h"
#include "../../ui/key_info.h"
#include "../../ui/menu.h"
#include "../../ui/theme.h"
#include <stdio.h>
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

  // Key entries
  for (uint32_t i = 0; i < info->num_keys; i++) {
    // Letter + fingerprint on same row
    char letter_fp[20];
    snprintf(letter_fp, sizeof(letter_fp), "%c: %s", 'A' + (char)i,
             info->keys[i].fingerprint_hex);
    ui_icon_text_row_create(scroll, ICON_FINGERPRINT, letter_fp,
                            highlight_color());

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

    // Separator between keys (except after last)
    if (i < info->num_keys - 1) {
      theme_create_separator(scroll);
    }
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
    char *unambiguous = descriptor_to_unambiguous(descriptor_str);
    descriptor_validate_and_load(unambiguous ? unambiguous : descriptor_str,
                                 validation_cb, descriptor_confirm_wrapper,
                                 descriptor_info_confirm_wrapper, user_data);
    free(unambiguous);
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

  char *unambiguous = descriptor_to_unambiguous(descriptor_str);
  descriptor_validate_and_load(unambiguous ? unambiguous : descriptor_str,
                               validation_cb, descriptor_confirm_wrapper,
                               descriptor_info_confirm_wrapper, user_data);
  free(unambiguous);
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
