// Wallet source picker — see header for shape.

#include "wallet_source_picker.h"
#include "../../core/registry.h"
#include "../../ui/theme.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct wallet_source_picker_s {
  wallet_picker_mode_t mode;
  wallet_source_t state;
  wallet_source_changed_cb on_change;
  void *user_data;

  lv_obj_t *dropdown;
  lv_obj_t *account_btn;
  lv_obj_t *account_value_label;

  // Numpad overlay (lazy)
  lv_obj_t *overlay;
  lv_obj_t *numpad;
  lv_obj_t *input_label;
  char input_buf[12];
  int input_len;
};

static const ss_script_type_t SINGLESIG_SCRIPT_MAP[4] = {
    SS_SCRIPT_P2WPKH,      /* 0 Native SegWit  */
    SS_SCRIPT_P2TR,        /* 1 Taproot        */
    SS_SCRIPT_P2PKH,       /* 2 Legacy         */
    SS_SCRIPT_P2SH_P2WPKH, /* 3 Nested SegWit  */
};

static const wallet_bip48_script_t BIP48_SCRIPT_MAP[2] = {
    WALLET_BIP48_P2WSH,      /* 0 Native SegWit (BIP48 subscript 2') */
    WALLET_BIP48_P2SH_P2WSH, /* 1 Nested SegWit (BIP48 subscript 1') */
};

static const char *NUMPAD_MAP[] = {"1",
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

ss_script_type_t wallet_source_picker_script_type(uint16_t source) {
  return SINGLESIG_SCRIPT_MAP[source];
}

wallet_bip48_script_t wallet_source_picker_bip48_script(uint16_t source) {
  return BIP48_SCRIPT_MAP[source];
}

static void emit_change(wallet_source_picker_t *p) {
  if (p->on_change)
    p->on_change(&p->state, p->user_data);
}

static bool source_has_account(const wallet_source_picker_t *p) {
  switch (p->mode) {
  case WALLET_PICKER_SINGLESIG:
    return true;
  case WALLET_PICKER_SINGLESIG_WITH_DESCRIPTORS:
    return p->state.source < 4;
  case WALLET_PICKER_MULTISIG_BIP48:
    return true;
  }
  return false;
}

static void update_account_visibility(wallet_source_picker_t *p) {
  if (!p->account_btn)
    return;
  if (source_has_account(p))
    lv_obj_clear_flag(p->account_btn, LV_OBJ_FLAG_HIDDEN);
  else
    lv_obj_add_flag(p->account_btn, LV_OBJ_FLAG_HIDDEN);
}

static void update_account_display(wallet_source_picker_t *p) {
  if (!p->account_value_label)
    return;
  char buf[16];
  snprintf(buf, sizeof(buf), "acc:%u", p->state.account);
  lv_label_set_text(p->account_value_label, buf);
}

static void update_input_display(wallet_source_picker_t *p) {
  if (!p->input_label)
    return;
  char display[14];
  if (p->input_len == 0)
    snprintf(display, sizeof(display), "_");
  else
    snprintf(display, sizeof(display), "%s_", p->input_buf);
  lv_label_set_text(p->input_label, display);
}

static void update_numpad_buttons(wallet_source_picker_t *p) {
  if (!p->numpad)
    return;
  bool empty = (p->input_len == 0);
  if (empty) {
    lv_btnmatrix_set_btn_ctrl(p->numpad, 12, LV_BTNMATRIX_CTRL_DISABLED);
    lv_btnmatrix_set_btn_ctrl(p->numpad, 14, LV_BTNMATRIX_CTRL_DISABLED);
  } else {
    lv_btnmatrix_clear_btn_ctrl(p->numpad, 12, LV_BTNMATRIX_CTRL_DISABLED);
    lv_btnmatrix_clear_btn_ctrl(p->numpad, 14, LV_BTNMATRIX_CTRL_DISABLED);
  }
}

static void close_overlay(wallet_source_picker_t *p) {
  if (p->overlay) {
    lv_obj_del(p->overlay);
    p->overlay = NULL;
    p->numpad = NULL;
    p->input_label = NULL;
  }
}

static void numpad_event_cb(lv_event_t *e) {
  wallet_source_picker_t *p = lv_event_get_user_data(e);
  lv_obj_t *btnm = lv_event_get_target(e);
  uint32_t btn_id = lv_btnmatrix_get_selected_btn(btnm);
  const char *txt = lv_btnmatrix_get_btn_text(btnm, btn_id);

  if (strcmp(txt, LV_SYMBOL_OK) == 0) {
    if (p->input_len > 0) {
      unsigned long val = strtoul(p->input_buf, NULL, 10);
      if (val < SS_MAX_ACCOUNT) {
        p->state.account = (uint32_t)val;
        update_account_display(p);
        close_overlay(p);
        emit_change(p);
        return;
      }
    }
    close_overlay(p);
  } else if (strcmp(txt, LV_SYMBOL_BACKSPACE) == 0) {
    if (p->input_len > 0) {
      p->input_len--;
      p->input_buf[p->input_len] = '\0';
      update_input_display(p);
      update_numpad_buttons(p);
    }
  } else if (p->input_len < 10) {
    p->input_buf[p->input_len++] = txt[0];
    p->input_buf[p->input_len] = '\0';
    update_input_display(p);
    update_numpad_buttons(p);
  }
}

static void show_overlay(wallet_source_picker_t *p) {
  p->input_len =
      snprintf(p->input_buf, sizeof(p->input_buf), "%u", p->state.account);

  p->overlay = lv_obj_create(lv_screen_active());
  lv_obj_remove_style_all(p->overlay);
  lv_obj_set_size(p->overlay, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(p->overlay, lv_color_black(), 0);
  lv_obj_set_style_bg_opa(p->overlay, LV_OPA_50, 0);
  lv_obj_add_flag(p->overlay, LV_OBJ_FLAG_CLICKABLE);

  lv_obj_t *modal = lv_obj_create(p->overlay);
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

  p->input_label = lv_label_create(modal);
  lv_obj_set_style_text_font(p->input_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(p->input_label, highlight_color(), 0);
  update_input_display(p);

  p->numpad = lv_btnmatrix_create(modal);
  lv_btnmatrix_set_map(p->numpad, NUMPAD_MAP);
  lv_obj_set_size(p->numpad, LV_PCT(100), LV_PCT(70));
  lv_obj_set_flex_grow(p->numpad, 1);
  theme_apply_btnmatrix(p->numpad);
  lv_obj_add_event_cb(p->numpad, numpad_event_cb, LV_EVENT_VALUE_CHANGED, p);
  update_numpad_buttons(p);
}

static void account_btn_cb(lv_event_t *e) {
  wallet_source_picker_t *p = lv_event_get_user_data(e);
  show_overlay(p);
}

static void dropdown_cb(lv_event_t *e) {
  wallet_source_picker_t *p = lv_event_get_user_data(e);
  p->state.source = lv_dropdown_get_selected(p->dropdown);
  update_account_visibility(p);
  emit_change(p);
}

static void build_options(wallet_picker_mode_t mode, char *out, size_t out_sz) {
  switch (mode) {
  case WALLET_PICKER_SINGLESIG:
    snprintf(out, out_sz, "Native SegWit\nTaproot\nLegacy\nNested SegWit");
    return;
  case WALLET_PICKER_SINGLESIG_WITH_DESCRIPTORS: {
    size_t written = (size_t)snprintf(
        out, out_sz, "Native SegWit\nTaproot\nLegacy\nNested SegWit");
    size_t reg_count = registry_count();
    for (size_t ri = 0; ri < reg_count && written < out_sz - 1; ri++) {
      const registry_entry_t *entry = registry_get(ri);
      int n = snprintf(out + written, out_sz - written, "\n%s", entry->id);
      if (n > 0)
        written += (size_t)n;
    }
    return;
  }
  case WALLET_PICKER_MULTISIG_BIP48:
    snprintf(out, out_sz, "Native SegWit\nNested SegWit");
    return;
  }
}

wallet_source_picker_t *wallet_source_picker_create(
    lv_obj_t *parent, wallet_picker_mode_t mode, const wallet_source_t *initial,
    wallet_source_changed_cb on_change, void *user_data) {
  if (!parent)
    return NULL;

  wallet_source_picker_t *p = calloc(1, sizeof(*p));
  if (!p)
    return NULL;

  p->mode = mode;
  p->state.source = initial ? initial->source : 0;
  p->state.account = initial ? initial->account : 0;
  p->on_change = on_change;
  p->user_data = user_data;

  char source_opts[600];
  build_options(mode, source_opts, sizeof(source_opts));

  p->dropdown = theme_create_dropdown(parent, source_opts);
  lv_obj_set_width(p->dropdown, LV_PCT(72));
  if (p->state.source > 0)
    lv_dropdown_set_selected(p->dropdown, p->state.source);
  lv_obj_add_event_cb(p->dropdown, dropdown_cb, LV_EVENT_VALUE_CHANGED, p);

  p->account_btn = lv_btn_create(parent);
  lv_obj_set_size(p->account_btn, LV_PCT(25), LV_SIZE_CONTENT);
  theme_apply_touch_button(p->account_btn, false);
  p->account_value_label = lv_label_create(p->account_btn);
  lv_obj_set_style_text_font(p->account_value_label, theme_font_small(), 0);
  lv_obj_center(p->account_value_label);
  lv_obj_add_event_cb(p->account_btn, account_btn_cb, LV_EVENT_CLICKED, p);
  update_account_display(p);
  update_account_visibility(p);

  return p;
}

void wallet_source_picker_get(const wallet_source_picker_t *picker,
                              wallet_source_t *out) {
  if (!picker || !out)
    return;
  *out = picker->state;
}

void wallet_source_picker_destroy(wallet_source_picker_t *picker) {
  if (!picker)
    return;
  close_overlay(picker);
  // Explicitly delete the widgets so callers can recreate the picker into the
  // same parent row (e.g. the public-key page's multisig toggle). Otherwise
  // the new dropdown / account button would stack on top of the old ones.
  if (picker->dropdown)
    lv_obj_del(picker->dropdown);
  if (picker->account_btn)
    lv_obj_del(picker->account_btn);
  free(picker);
}
