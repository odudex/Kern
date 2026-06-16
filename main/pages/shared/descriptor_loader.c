#include "descriptor_loader.h"
#include "../../../components/cUR/src/types/bytes_type.h"
#include "../../../components/cUR/src/types/output.h"
#include "../../core/key.h"
#include "../../core/miniscript_policy.h"
#include "../../core/registry.h"
#include "../../core/wallet.h"
#include "../../qr/parser.h"
#include "../../qr/scanner.h"
#include "../../ui/assets/icons_24.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/key_info.h"
#include "../../ui/menu.h"
#include "../../ui/text_fit.h"
#include "../../ui/theme_widgets.h"
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
// 15 keys is libwally's CHECKMULTISIG generation cap, enforced for all
// descriptors by VALIDATION_UNSUPPORTED_SCRIPT.
#define BLUEWALLET_MAX_KEYS 15
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
      threshold == 0 || num_keys == 0 || threshold > num_keys ||
      num_keys > BLUEWALLET_MAX_KEYS)
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

  char fingerprints[BLUEWALLET_MAX_KEYS][9];
  char *xpubs[BLUEWALLET_MAX_KEYS];
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

  case VALIDATION_DUPLICATE: {
    char existing_id[REGISTRY_ID_MAX_LEN];
    char msg[96];
    if (descriptor_validator_get_duplicate_id(existing_id, sizeof(existing_id)))
      snprintf(msg, sizeof(msg), "Descriptor already loaded as '%s'",
               existing_id);
    else
      snprintf(msg, sizeof(msg), "Descriptor already loaded");
    dialog_show_error_timeout(msg, NULL, 2500);
    return true;
  }

  case VALIDATION_FINGERPRINT_NOT_FOUND:
    dialog_show_error_timeout("Key not found in descriptor", NULL, 2000);
    return true;

  case VALIDATION_XPUB_MISMATCH:
    dialog_show_error_timeout("XPub mismatch - check passphrase", NULL, 2000);
    return true;

  case VALIDATION_PARSE_ERROR:
    dialog_show_error_timeout("Invalid descriptor format", NULL, 2000);
    return true;

  case VALIDATION_INVALID_HARDENED_NOTATION:
    dialog_show_error_timeout("Descriptor uses 'H'. Use ' or h for hardened.",
                              NULL, 3000);
    return true;

  case VALIDATION_UNSUPPORTED_MINISCRIPT:
    dialog_show_error_timeout("Only wsh() miniscript is supported", NULL, 3000);
    return true;

  case VALIDATION_UNSUPPORTED_SCRIPT:
    dialog_show_error_timeout("Script too large (max 15 multisig keys)", NULL,
                              3000);
    return true;

  case VALIDATION_NETWORK_MISMATCH: {
    const char *expected = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                               ? "Testnet"
                               : "Mainnet";
    char msg[80];
    snprintf(msg, sizeof(msg),
             "Descriptor is for %s. Switch network in Settings.", expected);
    dialog_show_error_timeout(msg, NULL, 3000);
    return true;
  }

  case VALIDATION_INTERNAL_ERROR:
  default:
    dialog_show_error_timeout("Validation failed", NULL, 2000);
    return true;
  }
}

typedef struct {
  void (*proceed)(const char *id, storage_location_t loc, void *user_data);
  ui_text_input_t input;
  /* Wrapper screen owning the textarea + eye-btn so they cascade-delete
   * with the screen on teardown (ui_text_input_destroy only kills the
   * keyboard + input_group). Without this container the textarea kept
   * its parent — whichever screen was active at create time — and
   * stayed rendered on top of the home menu after the success dialog. */
  lv_obj_t *screen;
} id_prompt_ctx_t;

static id_prompt_ctx_t *g_id_prompt_ctx = NULL;

static void id_prompt_ready_cb(lv_event_t *e) {
  (void)e;
  if (!g_id_prompt_ctx)
    return;
  const char *text = lv_textarea_get_text(g_id_prompt_ctx->input.textarea);
  if (!text || strlen(text) == 0) {
    dialog_show_error_timeout("Please enter a name", NULL, 2000);
    return;
  }

  char id_copy[REGISTRY_ID_MAX_LEN];
  strncpy(id_copy, text, sizeof(id_copy) - 1);
  id_copy[sizeof(id_copy) - 1] = '\0';

  void (*proceed)(const char *, storage_location_t, void *) =
      g_id_prompt_ctx->proceed;
  ui_text_input_destroy(&g_id_prompt_ctx->input);
  if (g_id_prompt_ctx->screen) {
    lv_obj_del(g_id_prompt_ctx->screen);
    g_id_prompt_ctx->screen = NULL;
  }
  free(g_id_prompt_ctx);
  g_id_prompt_ctx = NULL;

  proceed(id_copy, STORAGE_FLASH, NULL);
}

static void descriptor_id_loc_wrapper(void (*proceed)(const char *id,
                                                      storage_location_t loc,
                                                      void *user_data),
                                      void *user_data) {
  (void)user_data;
  id_prompt_ctx_t *ctx = malloc(sizeof(id_prompt_ctx_t));
  if (!ctx) {
    proceed(NULL, STORAGE_FLASH, NULL);
    return;
  }
  ctx->proceed = proceed;
  memset(&ctx->input, 0, sizeof(ctx->input));
  ctx->screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(ctx->screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(ctx->screen);
  lv_obj_clear_flag(ctx->screen, LV_OBJ_FLAG_SCROLLABLE);
  g_id_prompt_ctx = ctx;
  ui_text_input_create(&ctx->input, ctx->screen, "Descriptor name", false,
                       id_prompt_ready_cb);
}

// UI confirmation wrapper: validator's confirm_cb fires on danger-style
// warnings (e.g. purpose/script binding mismatch) — render as overlay danger
// confirm.
static void descriptor_confirm_wrapper(const char *message,
                                       void (*proceed)(bool confirmed,
                                                       void *user_data)) {
  dialog_show_danger_confirm(message, proceed, NULL, DIALOG_STYLE_OVERLAY);
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

static lv_color_t policy_token_color(const ms_token_t *tok,
                                     const char *our_letters) {
  switch (tok->kind) {
  case MS_TOKEN_PLUMBING:
  case MS_TOKEN_NOTE:
    return secondary_color();
  case MS_TOKEN_OPERATOR:
  case MS_TOKEN_TIMELOCK:
    return accent_color();
  case MS_TOKEN_KEY:
    return (our_letters && strchr(our_letters, tok->text[0]))
               ? highlight_color()
               : primary_color();
  default:
    return primary_color();
  }
}

// Recover a child spangroup's nesting level from its left padding.
static int32_t policy_line_level(lv_obj_t *child, int32_t indent_px) {
  return lv_obj_get_style_pad_left(child, 0) / indent_px;
}

// Scanning forward from line i, is there another line at exactly `depth` before
// a shallower line closes the branch? (i.e. does this branch have more
// siblings, so its spine should keep descending).
static bool policy_branch_continues(lv_obj_t *cont, uint32_t n, uint32_t i,
                                    int32_t depth, int32_t indent_px) {
  for (uint32_t j = i + 1; j < n; j++) {
    int32_t lj = policy_line_level(lv_obj_get_child(cont, j), indent_px);
    if (lj < depth)
      return false;
    if (lj == depth)
      return true;
  }
  return false;
}

// Draw a file-tree style guide: a vertical spine per nesting branch with an
// elbow joining each line to its parent (tee while siblings remain, corner on
// the last one). Each child spangroup's level is recovered from its padding.
static void policy_tree_draw_cb(lv_event_t *e) {
  lv_obj_t *cont = lv_event_get_target(e);
  lv_layer_t *layer = lv_event_get_layer(e);
  int32_t indent_px = (int32_t)(intptr_t)lv_event_get_user_data(e);
  if (!layer || indent_px <= 0)
    return;

  int32_t guide_px = theme_small_padding() / 4;
  if (guide_px < 1)
    guide_px = 1;
  int32_t inset = indent_px / 4;
  if (inset < 2)
    inset = 2;
  int32_t gap = lv_obj_get_style_pad_row(cont, 0);

  lv_draw_line_dsc_t dsc;
  lv_draw_line_dsc_init(&dsc);
  dsc.color = secondary_color();
  dsc.width = guide_px;
  dsc.opa = LV_OPA_50;

  lv_area_t content;
  lv_obj_get_content_coords(cont, &content);
  int32_t x0 = content.x1;
  uint32_t n = lv_obj_get_child_count(cont);

  for (uint32_t i = 0; i < n; i++) {
    lv_obj_t *child = lv_obj_get_child(cont, i);
    int32_t level = policy_line_level(child, indent_px);
    if (level <= 0)
      continue;

    lv_area_t a;
    lv_obj_get_coords(child, &a);
    int32_t mid = (a.y1 + a.y2) / 2;
    int32_t top = a.y1 - gap; // bridge the inter-row gap up to the parent

    // Ancestor branches still expecting siblings get a pass-through spine.
    for (int32_t d = 1; d < level; d++) {
      if (!policy_branch_continues(cont, n, i, d, indent_px))
        continue;
      int32_t x = x0 + (d - 1) * indent_px + inset;
      dsc.p1.x = dsc.p2.x = x;
      dsc.p1.y = top;
      dsc.p2.y = a.y2;
      lv_draw_line(layer, &dsc);
    }

    // This line's own branch: spine down to the elbow, then across to the text.
    int32_t x = x0 + (level - 1) * indent_px + inset;
    bool last = !policy_branch_continues(cont, n, i, level, indent_px);
    dsc.p1.x = dsc.p2.x = x;
    dsc.p1.y = top;
    dsc.p2.y = last ? mid : a.y2;
    lv_draw_line(layer, &dsc);

    dsc.p1.x = x;
    dsc.p1.y = dsc.p2.y = mid;
    dsc.p2.x = x0 + level * indent_px;
    lv_draw_line(layer, &dsc);
  }
}

lv_obj_t *descriptor_policy_view_create(lv_obj_t *parent, const char *policy,
                                        const char *our_letters) {
  if (!parent || !policy || !*policy)
    return NULL;

  const lv_font_t *font = theme_font_small();
  // Conservative chars-per-line estimate: avg glyph width ~ line_height / 2
  size_t max_chars =
      (size_t)((theme_screen_width() - 2 * theme_default_padding()) * 2 /
               font->line_height);
  if (max_chars < 20)
    max_chars = 20;

  ms_policy_view_t view;
  if (!miniscript_policy_view_build(policy, max_chars, &view))
    return NULL;

  lv_obj_t *cont = lv_obj_create(parent);
  lv_obj_set_style_bg_opa(cont, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(cont, 0, 0);
  lv_obj_set_style_pad_all(cont, 0, 0);
  lv_obj_set_style_pad_row(cont, theme_small_padding() / 2, 0);
  lv_obj_set_size(cont, LV_PCT(100), LV_SIZE_CONTENT);
  lv_obj_set_flex_flow(cont, LV_FLEX_FLOW_COLUMN);
  lv_obj_clear_flag(cont, LV_OBJ_FLAG_SCROLLABLE);

  int32_t indent_px = theme_default_padding() / 2;
  lv_obj_add_event_cb(cont, policy_tree_draw_cb, LV_EVENT_DRAW_MAIN,
                      (void *)(intptr_t)indent_px);

  for (size_t i = 0; i < view.num_lines; i++) {
    const ms_policy_line_t *line = &view.lines[i];
    lv_obj_t *sg = lv_spangroup_create(cont);
    lv_spangroup_set_mode(sg, LV_SPAN_MODE_BREAK);
    lv_obj_set_width(sg, LV_PCT(100));
    lv_obj_set_height(sg, LV_SIZE_CONTENT);
    lv_obj_set_style_text_font(sg, font, 0);
    lv_obj_set_style_pad_left(sg, line->level * indent_px, 0);
    for (size_t j = 0; j < line->num_tokens; j++) {
      const ms_token_t *tok = &line->tokens[j];
      lv_span_t *span = lv_spangroup_add_span(sg);
      if (!span)
        continue;
      if (tok->kind == MS_TOKEN_NOTE) {
        char text[32];
        snprintf(text, sizeof(text), " %s", tok->text);
        lv_span_set_text(span, text);
      } else {
        lv_span_set_text(span, tok->text);
      }
      lv_style_set_text_color(lv_span_get_style(span),
                              policy_token_color(tok, our_letters));
    }
    lv_spangroup_refresh(sg);
  }

  miniscript_policy_view_free(&view);
  return cont;
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
  if (info->is_miniscript) {
    snprintf(title, sizeof(title), "Miniscript (%u key%s) - Load?",
             info->num_keys, info->num_keys == 1 ? "" : "s");
  } else if (info->is_multisig) {
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

  // Scrollable content area (between title and buttons). Use the root's
  // content height: the default theme pads the root, so LV_VER_RES would
  // overlap the bottom buttons.
  lv_obj_update_layout(root);
  // Use the title's laid-out height so a wrapped (multi-line) title on narrow
  // screens still clears the first key. 10px above (align offset) + 10 below.
  lv_coord_t title_h = lv_obj_get_height(title_label) + 20;
  lv_coord_t btn_h = theme_button_height();
  lv_obj_t *scroll = lv_obj_create(root);
  lv_obj_set_width(scroll, LV_PCT(100));
  lv_obj_set_height(scroll, lv_obj_get_content_height(root) - title_h - btn_h);
  lv_obj_align(scroll, LV_ALIGN_TOP_LEFT, 0, title_h);
  lv_obj_set_style_bg_opa(scroll, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(scroll, 0, 0);
  lv_obj_set_style_pad_all(scroll, 10, 0);
  lv_obj_set_style_pad_row(scroll, 4, 0);
  lv_obj_set_flex_flow(scroll, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(scroll, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_START);
  lv_obj_add_flag(scroll, LV_OBJ_FLAG_SCROLLABLE);

  // Resolve the scroll's content width so long xpubs can be cropped to fill it.
  lv_obj_update_layout(root);
  int32_t scroll_w = lv_obj_get_content_width(scroll);

  // Get current wallet fingerprint for highlighting
  char my_fp[9] = {0};
  key_get_fingerprint_hex(my_fp);

  // Key entries
  for (uint32_t i = 0; i < info->num_keys; i++) {
    // Identifier letter at line start, then fingerprint icon + hex
    char letter_icon[12];
    snprintf(letter_icon, sizeof(letter_icon), "%c: %s", 'A' + (char)i,
             ICON_FINGERPRINT);
    bool is_ours = (my_fp[0] != '\0' &&
                    strcasecmp(my_fp, info->keys[i].fingerprint_hex) == 0);
    lv_obj_t *fp_row = ui_icon_text_row_create(
        scroll, letter_icon, info->keys[i].fingerprint_hex,
        is_ours ? highlight_color() : primary_color());
    if (i > 0)
      lv_obj_set_style_pad_top(fp_row, 12, 0);

    // Indent the following lines to sit under the fingerprint icon, i.e.
    // past the "X: " identifier prefix on the first line.
    char prefix[4];
    snprintf(prefix, sizeof(prefix), "%c: ", 'A' + (char)i);
    lv_point_t prefix_size = {0};
    lv_text_get_size(&prefix_size, prefix, theme_font_small(), 0, 0,
                     LV_COORD_MAX, LV_TEXT_FLAG_NONE);
    int32_t indent = prefix_size.x;

    // Derivation path row (indented), hardened marks shown as 'h'
    char deriv[64];
    strncpy(deriv, info->keys[i].derivation, sizeof(deriv) - 1);
    deriv[sizeof(deriv) - 1] = '\0';
    for (char *p = deriv; *p; p++)
      if (*p == '\'')
        *p = 'h';
    lv_obj_t *deriv_row = ui_icon_text_row_create(scroll, ICON_DERIVATION,
                                                  deriv, secondary_color());
    lv_obj_set_style_pad_left(deriv_row, indent, 0);

    // Xpub (indented), middle-cropped to fill the remaining width.
    ui_text_fit_t xpub_fit = ui_text_fit_middle(
        info->keys[i].xpub, theme_font_small(), scroll_w - indent);
    lv_obj_t *xpub_row = ui_text_fit_row_create(
        scroll, &xpub_fit, theme_font_small(), scroll_w, secondary_color());
    lv_obj_set_style_pad_left(xpub_row, indent, 0);
  }

  // Indented miniscript policy with key letters, our keys highlighted
  if (info->is_miniscript && info->policy[0]) {
    char ours[DESCRIPTOR_INFO_MAX_KEYS + 1];
    size_t n_ours = 0;
    for (uint32_t i = 0; my_fp[0] != '\0' && i < info->num_keys; i++)
      if (strcasecmp(my_fp, info->keys[i].fingerprint_hex) == 0)
        ours[n_ours++] = (char)('A' + i);
    ours[n_ours] = '\0';

    lv_obj_t *policy_view =
        descriptor_policy_view_create(scroll, info->policy, ours);
    if (policy_view)
      lv_obj_set_style_pad_top(policy_view, theme_small_padding(), 0);
  }

  // Button row (fixed at bottom)
  lv_obj_t *no_btn = theme_create_button(root, "No", false);
  lv_obj_set_size(no_btn, LV_PCT(50), theme_button_height());
  lv_obj_align(no_btn, LV_ALIGN_BOTTOM_LEFT, 0, 0);
  lv_obj_add_event_cb(no_btn, info_confirm_no_cb, LV_EVENT_CLICKED, ctx);
  lv_obj_t *no_label = lv_obj_get_child(no_btn, 0);
  if (no_label) {
    lv_obj_set_style_text_color(no_label, discourage_color(), 0);
    lv_obj_set_style_text_font(no_label, theme_font_medium(), 0);
  }

  lv_obj_t *yes_btn = theme_create_button(root, "Yes", true);
  lv_obj_set_size(yes_btn, LV_PCT(50), theme_button_height());
  lv_obj_align(yes_btn, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
  lv_obj_add_event_cb(yes_btn, info_confirm_yes_cb, LV_EVENT_CLICKED, ctx);
  lv_obj_t *yes_label = lv_obj_get_child(yes_btn, 0);
  if (yes_label) {
    lv_obj_set_style_text_color(yes_label, encourage_color(), 0);
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
                                 descriptor_info_confirm_wrapper,
                                 descriptor_id_loc_wrapper, user_data);
    free(unambiguous);
    free(converted);
    free(descriptor_str);
  } else {
    dialog_show_error_timeout("Unsupported descriptor format", NULL, 2000);
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
                               descriptor_info_confirm_wrapper,
                               descriptor_id_loc_wrapper, user_data);
  free(unambiguous);
  free(converted);
}

void descriptor_loader_process_string_watch_only(
    const char *descriptor_str, validation_complete_cb validation_cb,
    void *user_data) {
  if (!descriptor_str) {
    if (validation_cb)
      validation_cb(VALIDATION_PARSE_ERROR, user_data);
    return;
  }

  char *converted = bluewallet_to_descriptor(descriptor_str);
  const char *to_process = converted ? converted : descriptor_str;
  char *unambiguous = descriptor_to_unambiguous(to_process);
  const char *final = unambiguous ? unambiguous : to_process;

  wallet_network_t net;
  if (!descriptor_infer_network(final, &net)) {
    if (validation_cb)
      validation_cb(VALIDATION_PARSE_ERROR, user_data);
    free(unambiguous);
    free(converted);
    return;
  }

  wallet_set_watch_only(net);
  descriptor_validate_and_load_watch_only(
      final, net, validation_cb, descriptor_info_confirm_wrapper, user_data);
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
        char *text =
            (data && len > 0) ? strndup((const char *)data, len) : NULL;
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
