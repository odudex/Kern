// Address Checker — shared address verification via sweep

#include "address_checker.h"
#include "../../core/address_match.h"
#include "../../core/registry.h"
#include "../../core/ss_whitelist.h"
#include "../../core/wallet.h"
#include "../../ui/dialog.h"
#include "../../ui/oneshot.h"
#include "../../ui/theme_widgets.h"
#include "../../ui/wallet_source_picker.h"
#include "../../utils/session_cleanup.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define SEARCH_BATCH 100

static uint8_t checked_spk[ADDRESS_MATCH_SPK_MAX];
static size_t checked_spk_len = 0;
static uint32_t search_start = 0;
static uint32_t search_limit = SEARCH_BATCH;
static void (*on_found)(void) = NULL;
static void (*on_not_found)(void) = NULL;
static lv_obj_t *progress_dialog = NULL;
static ui_oneshot_t sweep_timer;

// Source picker state — persists between invocations (page-scoped)
static wallet_source_t ac_source = {0, 0};

static lv_obj_t *ac_overlay = NULL;
static wallet_source_picker_t *ac_picker = NULL;

static void perform_sweep(void);
static void perform_sweep_deferred(lv_timer_t *timer);
static void show_source_picker(void);
static void destroy_source_picker(void);

static void dismiss_progress(void) {
  if (progress_dialog) {
    lv_obj_delete(progress_dialog);
    progress_dialog = NULL;
  }
}

static void ac_picker_changed_cb(const wallet_source_t *src, void *user_data) {
  (void)user_data;
  ac_source = *src;
}

static void destroy_source_picker(void) {
  wallet_source_picker_destroy(ac_picker);
  ac_picker = NULL;
  if (ac_overlay) {
    lv_obj_del(ac_overlay);
    ac_overlay = NULL;
  }
}

static void ac_verify_btn_cb(lv_event_t *e) {
  (void)e;
  destroy_source_picker();
  search_start = 0;
  search_limit = SEARCH_BATCH;
  perform_sweep();
}

static void show_source_picker(void) {
  ac_overlay = lv_obj_create(lv_screen_active());
  lv_obj_set_size(ac_overlay, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(ac_overlay);
  lv_obj_set_style_pad_all(ac_overlay, theme_default_padding(), 0);
  lv_obj_set_flex_flow(ac_overlay, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(ac_overlay, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(ac_overlay, theme_default_padding(), 0);

  lv_obj_t *picker_row = lv_obj_create(ac_overlay);
  lv_obj_set_size(picker_row, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(picker_row);
  lv_obj_set_flex_flow(picker_row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(picker_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  ac_picker = wallet_source_picker_create(
      picker_row, WALLET_PICKER_SINGLESIG_WITH_DESCRIPTORS, &ac_source,
      ac_picker_changed_cb, NULL);

  lv_obj_t *verify_btn = lv_btn_create(ac_overlay);
  lv_obj_set_size(verify_btn, LV_PCT(60), LV_SIZE_CONTENT);
  theme_apply_touch_button(verify_btn, false);
  lv_obj_t *verify_lbl = lv_label_create(verify_btn);
  lv_label_set_text(verify_lbl, "Verify");
  lv_obj_center(verify_lbl);
  theme_apply_button_label(verify_lbl, false);
  lv_obj_add_event_cb(verify_btn, ac_verify_btn_cb, LV_EVENT_CLICKED, NULL);
}

static void invalid_address_cb(void) {
  if (on_not_found)
    on_not_found();
}

static void found_info_cb(void *user_data) {
  (void)user_data;
  if (on_found)
    on_found();
}

static void not_found_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed) {
    address_checker_search_more();
    return;
  }
  if (on_not_found)
    on_not_found();
}

// Sweeping up to SEARCH_BATCH receive + change addresses derives many keys
// (especially for multisig) and blocks the LVGL loop. Show a progress overlay
// first, then defer the work via a one-shot timer so LVGL can render it.
static void perform_sweep(void) {
  progress_dialog = dialog_show_progress("Verifying", "Checking addresses...",
                                         DIALOG_STYLE_FULLSCREEN);
  ui_oneshot_start(&sweep_timer, perform_sweep_deferred, 50);
}

static void perform_sweep_deferred(lv_timer_t *timer) {
  (void)timer;
  bool is_testnet = (wallet_get_network() == WALLET_NETWORK_TESTNET);
  const registry_entry_t *reg_entry = NULL;

  if (ac_source.source >= 4) {
    reg_entry = registry_get((size_t)(ac_source.source - 4));
    if (!reg_entry) {
      dismiss_progress();
      if (on_not_found)
        on_not_found();
      return;
    }
  }

  address_match_t match;
  bool found;
  if (reg_entry) {
    found = address_match_descriptor(reg_entry->desc, reg_entry->num_paths,
                                     checked_spk, checked_spk_len, search_start,
                                     search_limit, &match);
  } else {
    // Fixed account: user selected it in the picker; do not iterate accounts.
    found = address_match_singlesig(
        wallet_source_picker_script_type(ac_source.source), ac_source.account,
        is_testnet, checked_spk, checked_spk_len, search_start, search_limit,
        &match);
  }
  if (found) {
    dismiss_progress();
    char msg[64];
    snprintf(msg, sizeof(msg), "%s #%u", match.chain ? "Change" : "Receive",
             match.index);
    dialog_show_info("Address Verified", msg, found_info_cb, NULL,
                     DIALOG_STYLE_FULLSCREEN);
    return;
  }

  dismiss_progress();

  // Not found — offer to search another batch
  char msg[192];
  snprintf(msg, sizeof(msg),
           "Address not found in first %u addresses.\n\n"
           "(Check if loaded wallet settings match coordinator's)\n\n"
           "Search %u more?",
           search_limit, SEARCH_BATCH);
  dialog_show_confirm(msg, not_found_confirm_cb, NULL, DIALOG_STYLE_FULLSCREEN);
}

void address_checker_check(const char *raw_content, void (*found_cb)(void),
                           void (*not_found_cb)(void),
                           const wallet_source_t *initial) {
  address_checker_destroy();
  session_cleanup_register(address_checker_destroy);

  if (!raw_content)
    return;

  char *content = strdup(raw_content);
  if (!content)
    return;

  // Strip BIP21 "bitcoin:" URI prefix if present
  if (strncasecmp(content, "bitcoin:", 8) == 0) {
    char *query = strchr(content + 8, '?');
    size_t addr_len =
        query ? (size_t)(query - content - 8) : strlen(content + 8);
    memmove(content, content + 8, addr_len);
    content[addr_len] = '\0';
  }

  bool valid = address_match_decode(
      content, wallet_get_network() == WALLET_NETWORK_TESTNET, checked_spk,
      sizeof(checked_spk), &checked_spk_len);
  free(content);
  if (!valid) {
    dialog_show_error_timeout("Invalid address", invalid_address_cb, 0);
    return;
  }

  search_start = 0;
  search_limit = SEARCH_BATCH;
  on_found = found_cb;
  on_not_found = not_found_cb;
  if (initial)
    ac_source = *initial;
  show_source_picker();
}

void address_checker_search_more(void) {
  search_start = search_limit;
  search_limit += SEARCH_BATCH;
  perform_sweep();
}

void address_checker_destroy(void) {
  session_cleanup_unregister(address_checker_destroy);
  ui_oneshot_cancel(&sweep_timer);
  dismiss_progress();
  destroy_source_picker();
  memset(checked_spk, 0, sizeof(checked_spk));
  checked_spk_len = 0;
  search_start = 0;
  search_limit = SEARCH_BATCH;
  on_found = NULL;
  on_not_found = NULL;
  // ac_source intentionally NOT reset — persist session selection
}
