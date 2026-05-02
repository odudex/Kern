// Address Checker — shared address verification via sweep

#include "address_checker.h"
#include "../../core/registry.h"
#include "../../core/ss_whitelist.h"
#include "../../core/wallet.h"
#include "../../ui/dialog.h"
#include "../../ui/theme.h"
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <wally_address.h>
#include <wally_core.h>

#define SEARCH_BATCH 100

static char *checked_address = NULL;
static uint32_t search_start = 0;
static uint32_t search_limit = SEARCH_BATCH;
static void (*on_found)(void) = NULL;
static void (*on_not_found)(void) = NULL;
static lv_obj_t *progress_dialog = NULL;

// Source picker state — persists between invocations (page-scoped)
static uint16_t ac_source = 0;  // 0–3 = SS types, 4+ = registry entries
static uint32_t ac_account = 0; // account for SS sources only

// Source picker UI widgets
static lv_obj_t *ac_overlay = NULL;
static lv_obj_t *ac_source_dropdown = NULL;
static lv_obj_t *ac_account_btn = NULL;
static lv_obj_t *ac_account_value_lbl = NULL;

// Account numpad sub-overlay
static lv_obj_t *ac_account_overlay = NULL;
static lv_obj_t *ac_account_numpad = NULL;
static lv_obj_t *ac_account_input_lbl = NULL;
static char ac_account_input_buf[12];
static int ac_account_input_len = 0;

static const ss_script_type_t ac_script_map[4] = {
    SS_SCRIPT_P2WPKH,      /* 0 Native SegWit  */
    SS_SCRIPT_P2TR,        /* 1 Taproot        */
    SS_SCRIPT_P2PKH,       /* 2 Legacy         */
    SS_SCRIPT_P2SH_P2WPKH, /* 3 Nested SegWit */
};

static const char *ac_numpad_map[] = {"1",
                                      "2",
                                      "3",
                                      "\n",
                                      "4",
                                      "5",
                                      "6",
                                      "\n",
                                      "7",
                                      "8",
                                      "9",
                                      "\n",
                                      LV_SYMBOL_BACKSPACE,
                                      "0",
                                      LV_SYMBOL_OK,
                                      ""};

static void perform_sweep(void);
static void perform_sweep_deferred(lv_timer_t *timer);
static void show_source_picker(void);
static void destroy_source_picker(void);
static void update_ac_account_button_visibility(void);

static void dismiss_progress(void) {
  if (progress_dialog) {
    lv_obj_delete(progress_dialog);
    progress_dialog = NULL;
  }
}

static void update_ac_account_button_visibility(void) {
  if (!ac_account_btn)
    return;
  if (ac_source >= 4)
    lv_obj_add_flag(ac_account_btn, LV_OBJ_FLAG_HIDDEN);
  else
    lv_obj_clear_flag(ac_account_btn, LV_OBJ_FLAG_HIDDEN);
}

static void ac_source_dropdown_cb(lv_event_t *e) {
  (void)e;
  ac_source = lv_dropdown_get_selected(ac_source_dropdown);
  update_ac_account_button_visibility();
}

static void update_ac_account_display(void) {
  if (!ac_account_value_lbl)
    return;
  char buf[12];
  snprintf(buf, sizeof(buf), "%u", ac_account);
  lv_label_set_text(ac_account_value_lbl, buf);
}

static void update_ac_account_input_display(void) {
  if (!ac_account_input_lbl)
    return;
  char display[14];
  if (ac_account_input_len == 0)
    snprintf(display, sizeof(display), "_");
  else
    snprintf(display, sizeof(display), "%s_", ac_account_input_buf);
  lv_label_set_text(ac_account_input_lbl, display);
}

static void update_ac_numpad_buttons(void) {
  if (!ac_account_numpad)
    return;
  bool empty = (ac_account_input_len == 0);
  if (empty) {
    lv_btnmatrix_set_btn_ctrl(ac_account_numpad, 9, LV_BTNMATRIX_CTRL_DISABLED);
    lv_btnmatrix_set_btn_ctrl(ac_account_numpad, 11,
                              LV_BTNMATRIX_CTRL_DISABLED);
  } else {
    lv_btnmatrix_clear_btn_ctrl(ac_account_numpad, 9,
                                LV_BTNMATRIX_CTRL_DISABLED);
    lv_btnmatrix_clear_btn_ctrl(ac_account_numpad, 11,
                                LV_BTNMATRIX_CTRL_DISABLED);
  }
}

static void close_ac_account_overlay(void) {
  if (ac_account_overlay) {
    lv_obj_del(ac_account_overlay);
    ac_account_overlay = NULL;
    ac_account_numpad = NULL;
    ac_account_input_lbl = NULL;
  }
}

static void ac_account_numpad_event_cb(lv_event_t *e) {
  lv_obj_t *btnm = lv_event_get_target(e);
  uint32_t btn_id = lv_btnmatrix_get_selected_btn(btnm);
  const char *txt = lv_btnmatrix_get_btn_text(btnm, btn_id);

  if (strcmp(txt, LV_SYMBOL_OK) == 0) {
    if (ac_account_input_len > 0) {
      unsigned long val = strtoul(ac_account_input_buf, NULL, 10);
      if (val < SS_MAX_ACCOUNT) {
        ac_account = (uint32_t)val;
        update_ac_account_display();
      }
    }
    close_ac_account_overlay();
  } else if (strcmp(txt, LV_SYMBOL_BACKSPACE) == 0) {
    if (ac_account_input_len > 0) {
      ac_account_input_len--;
      ac_account_input_buf[ac_account_input_len] = '\0';
      update_ac_account_input_display();
      update_ac_numpad_buttons();
    }
  } else if (ac_account_input_len < 10) {
    ac_account_input_buf[ac_account_input_len++] = txt[0];
    ac_account_input_buf[ac_account_input_len] = '\0';
    update_ac_account_input_display();
    update_ac_numpad_buttons();
  }
}

static void show_ac_account_overlay(void) {
  ac_account_input_len = snprintf(
      ac_account_input_buf, sizeof(ac_account_input_buf), "%u", ac_account);

  ac_account_overlay = lv_obj_create(lv_screen_active());
  lv_obj_remove_style_all(ac_account_overlay);
  lv_obj_set_size(ac_account_overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(ac_account_overlay, lv_color_black(), 0);
  lv_obj_set_style_bg_opa(ac_account_overlay, LV_OPA_50, 0);
  lv_obj_add_flag(ac_account_overlay, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *modal = lv_obj_create(ac_account_overlay);
  lv_obj_set_size(modal, LV_PCT(80), LV_PCT(80));
  lv_obj_center(modal);
  theme_apply_frame(modal);
  lv_obj_set_style_bg_opa(modal, LV_OPA_90, 0);
  lv_obj_clear_flag(modal, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_flex_flow(modal, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(modal, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(modal, theme_get_default_padding(), 0);
  lv_obj_set_style_pad_gap(modal, 15, 0);

  lv_obj_t *title = lv_label_create(modal);
  lv_label_set_text(title, "Account");
  lv_obj_set_style_text_font(title, theme_font_medium(), 0);
  lv_obj_set_style_text_color(title, main_color(), 0);

  ac_account_input_lbl = lv_label_create(modal);
  lv_obj_set_style_text_font(ac_account_input_lbl, theme_font_medium(), 0);
  lv_obj_set_style_text_color(ac_account_input_lbl, highlight_color(), 0);
  update_ac_account_input_display();

  ac_account_numpad = lv_btnmatrix_create(modal);
  lv_btnmatrix_set_map(ac_account_numpad, ac_numpad_map);
  lv_obj_set_size(ac_account_numpad, LV_PCT(100), LV_PCT(70));
  lv_obj_set_flex_grow(ac_account_numpad, 1);
  theme_apply_btnmatrix(ac_account_numpad);
  lv_obj_add_event_cb(ac_account_numpad, ac_account_numpad_event_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);
  update_ac_numpad_buttons();
}

static void ac_account_btn_cb(lv_event_t *e) {
  (void)e;
  show_ac_account_overlay();
}

static void destroy_source_picker(void) {
  close_ac_account_overlay();
  if (ac_overlay) {
    lv_obj_del(ac_overlay);
    ac_overlay = NULL;
    ac_source_dropdown = NULL;
    ac_account_btn = NULL;
    ac_account_value_lbl = NULL;
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
  lv_obj_set_style_pad_all(ac_overlay, theme_get_default_padding(), 0);
  lv_obj_set_flex_flow(ac_overlay, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(ac_overlay, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(ac_overlay, theme_get_default_padding(), 0);

  lv_obj_t *btn_cont = lv_obj_create(ac_overlay);
  lv_obj_set_size(btn_cont, LV_PCT(100), LV_SIZE_CONTENT);
  theme_apply_transparent_container(btn_cont);
  lv_obj_set_flex_flow(btn_cont, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(btn_cont, LV_FLEX_ALIGN_SPACE_BETWEEN,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  // Build dropdown options string
  char source_opts[600];
  size_t written =
      (size_t)snprintf(source_opts, sizeof(source_opts),
                       "Native SegWit\nTaproot\nLegacy\nNested SegWit");
  size_t reg_count = registry_count();
  for (size_t ri = 0; ri < reg_count && written < sizeof(source_opts) - 1;
       ri++) {
    const registry_entry_t *entry = registry_get(ri);
    int n = snprintf(source_opts + written, sizeof(source_opts) - written,
                     "\n%s", entry->id);
    if (n > 0)
      written += (size_t)n;
  }

  ac_source_dropdown = theme_create_dropdown(btn_cont, source_opts);
  lv_dropdown_set_selected(ac_source_dropdown, ac_source);
  lv_obj_set_width(ac_source_dropdown, LV_PCT(35));
  lv_obj_add_event_cb(ac_source_dropdown, ac_source_dropdown_cb,
                      LV_EVENT_VALUE_CHANGED, NULL);

  // Account button (hidden for registry entries)
  ac_account_btn = lv_btn_create(btn_cont);
  lv_obj_set_size(ac_account_btn, LV_PCT(13), LV_SIZE_CONTENT);
  theme_apply_touch_button(ac_account_btn, false);
  ac_account_value_lbl = lv_label_create(ac_account_btn);
  lv_obj_set_style_text_font(ac_account_value_lbl, theme_font_small(), 0);
  lv_obj_center(ac_account_value_lbl);
  lv_obj_add_event_cb(ac_account_btn, ac_account_btn_cb, LV_EVENT_CLICKED,
                      NULL);
  update_ac_account_display();

  // Verify button
  lv_obj_t *verify_btn = lv_btn_create(btn_cont);
  lv_obj_set_size(verify_btn, LV_PCT(35), LV_SIZE_CONTENT);
  theme_apply_touch_button(verify_btn, false);
  lv_obj_t *verify_lbl = lv_label_create(verify_btn);
  lv_label_set_text(verify_lbl, "Verify");
  lv_obj_center(verify_lbl);
  theme_apply_button_label(verify_lbl, false);
  lv_obj_add_event_cb(verify_btn, ac_verify_btn_cb, LV_EVENT_CLICKED, NULL);

  update_ac_account_button_visibility();
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
  lv_timer_t *t = lv_timer_create(perform_sweep_deferred, 50, NULL);
  lv_timer_set_repeat_count(t, 1);
}

static void perform_sweep_deferred(lv_timer_t *timer) {
  (void)timer;
  bool is_testnet = (wallet_get_network() == WALLET_NETWORK_TESTNET);
  const registry_entry_t *reg_entry = NULL;

  if (ac_source >= 4) {
    reg_entry = registry_get((size_t)(ac_source - 4));
    if (!reg_entry) {
      dismiss_progress();
      if (on_not_found)
        on_not_found();
      return;
    }
  }

  // Search receive addresses (chain = 0)
  for (uint32_t i = search_start; i < search_limit; i++) {
    char addr_buf[SS_ADDRESS_MAX_LEN];
    char *dyn = NULL;
    bool success = false;

    if (reg_entry) {
      uint32_t mp = 0;
      int ret = wally_descriptor_to_address(reg_entry->desc, 0, mp, i, 0, &dyn);
      success = (ret == WALLY_OK) && dyn;
    } else {
      // Fixed account: user selected it in the picker; do not iterate accounts.
      success = ss_address(ac_script_map[ac_source], ac_account, 0, i,
                           is_testnet, addr_buf, sizeof(addr_buf));
    }
    if (!success)
      continue;

    const char *addr = dyn ? dyn : addr_buf;
    if (strcasecmp(addr, checked_address) == 0) {
      if (dyn)
        wally_free_string(dyn);
      dismiss_progress();
      char msg[64];
      snprintf(msg, sizeof(msg), "Receive #%u", i);
      dialog_show_info("Address Verified", msg, found_info_cb, NULL,
                       DIALOG_STYLE_FULLSCREEN);
      return;
    }
    if (dyn) {
      wally_free_string(dyn);
      dyn = NULL;
    }
  }

  // Search change addresses (chain = 1)
  for (uint32_t i = search_start; i < search_limit; i++) {
    char addr_buf[SS_ADDRESS_MAX_LEN];
    char *dyn = NULL;
    bool success = false;

    if (reg_entry) {
      uint32_t mp = (reg_entry->num_paths <= 1) ? 0 : 1;
      int ret = wally_descriptor_to_address(reg_entry->desc, 0, mp, i, 0, &dyn);
      success = (ret == WALLY_OK) && dyn;
    } else {
      // Fixed account: same rationale as receive loop above.
      success = ss_address(ac_script_map[ac_source], ac_account, 1, i,
                           is_testnet, addr_buf, sizeof(addr_buf));
    }
    if (!success)
      continue;

    const char *addr = dyn ? dyn : addr_buf;
    if (strcasecmp(addr, checked_address) == 0) {
      if (dyn)
        wally_free_string(dyn);
      dismiss_progress();
      char msg[64];
      snprintf(msg, sizeof(msg), "Change #%u", i);
      dialog_show_info("Address Verified", msg, found_info_cb, NULL,
                       DIALOG_STYLE_FULLSCREEN);
      return;
    }
    if (dyn) {
      wally_free_string(dyn);
      dyn = NULL;
    }
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
                           void (*not_found_cb)(void)) {
  address_checker_destroy();

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

  // Validate address using libwally
  const char *hrp =
      (wallet_get_network() == WALLET_NETWORK_MAINNET) ? "bc" : "tb";
  uint32_t wally_net = (wallet_get_network() == WALLET_NETWORK_MAINNET)
                           ? WALLY_NETWORK_BITCOIN_MAINNET
                           : WALLY_NETWORK_BITCOIN_TESTNET;
  unsigned char script[128];
  size_t written = 0;
  bool valid =
      (wally_addr_segwit_to_bytes(content, hrp, 0, script, sizeof(script),
                                  &written) == WALLY_OK) ||
      (wally_address_to_scriptpubkey(content, wally_net, script, sizeof(script),
                                     &written) == WALLY_OK);
  if (!valid) {
    free(content);
    dialog_show_error("Invalid address", invalid_address_cb, 0);
    return;
  }

  checked_address = content;
  search_start = 0;
  search_limit = SEARCH_BATCH;
  on_found = found_cb;
  on_not_found = not_found_cb;
  show_source_picker();
}

void address_checker_search_more(void) {
  search_start = search_limit;
  search_limit += SEARCH_BATCH;
  perform_sweep();
}

void address_checker_destroy(void) {
  dismiss_progress();
  destroy_source_picker();
  ac_account_input_len = 0;
  if (checked_address) {
    free(checked_address);
    checked_address = NULL;
  }
  search_start = 0;
  search_limit = SEARCH_BATCH;
  on_found = NULL;
  on_not_found = NULL;
  // ac_source and ac_account intentionally NOT reset — persist session
  // selection
}
