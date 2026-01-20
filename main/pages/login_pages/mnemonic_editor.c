// Mnemonic Editor Page - Review and edit mnemonic words before loading

#include "mnemonic_editor.h"
#include "../../ui_components/flash_error.h"
#include "../../ui_components/icons/icons_24.h"
#include "../../ui_components/prompt_dialog.h"
#include "../../ui_components/theme.h"
#include "../../ui_components/ui_input_helpers.h"
#include "../../ui_components/ui_keyboard.h"
#include "../../ui_components/ui_menu.h"
#include "../../utils/bip39_filter.h"
#include "key_confirmation.h"
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>

#define MAX_MNEMONIC_LEN 256

typedef enum {
  MODE_WORD_GRID,
  MODE_KEYBOARD_INPUT,
  MODE_WORD_SELECT
} editor_mode_t;

static lv_obj_t *mnemonic_editor_screen = NULL;
static lv_obj_t *word_grid_container = NULL;
static lv_obj_t *word_labels[24];
static lv_obj_t *grid_back_btn = NULL;
static lv_obj_t *keyboard_back_btn = NULL;
static lv_obj_t *load_btn = NULL;
static lv_obj_t *load_label = NULL;
static lv_obj_t *header_container = NULL;
static lv_obj_t *fingerprint_icon = NULL;
static lv_obj_t *fingerprint_text = NULL;
static ui_keyboard_t *keyboard = NULL;
static ui_menu_t *current_menu = NULL;

static void (*return_callback)(void) = NULL;
static void (*success_callback)(void) = NULL;

static char entered_words[24][16];
static char original_words[24][16];
static int total_words = 0;
static int editing_word_index = -1;

static char current_prefix[BIP39_MAX_PREFIX_LEN + 1];
static int prefix_len = 0;
static const char *filtered_words[BIP39_MAX_FILTERED_WORDS];
static int filtered_count = 0;
static editor_mode_t current_mode = MODE_WORD_GRID;
static char pending_word[16] = {0};
static bool is_new_mnemonic = false;
static lv_obj_t *checksum_error_label = NULL;

static void create_ui(void);
static void create_word_grid(void);
static void cleanup_editing_ui(void);
static void show_keyboard_for_word(int index);
static void keyboard_callback(char key);
static void update_keyboard_state(void);
static void filter_words_by_prefix(void);
static void create_word_select_menu(void);
static void word_selected_cb(void);
static void back_to_keyboard_cb(void);
static void word_clicked_cb(lv_event_t *e);
static void back_btn_cb(lv_event_t *e);
static void load_btn_cb(lv_event_t *e);
static void show_word_confirmation(const char *word);
static void word_confirmation_cb(bool confirmed, void *user_data);
static void update_word_label(int index);
static bool is_checksum_valid(void);
static bool recalculate_last_word(void);
static void update_checksum_ui(void);

static bool is_checksum_valid(void) {
  char mnemonic[MAX_MNEMONIC_LEN];
  mnemonic[0] = '\0';

  for (int i = 0; i < total_words; i++) {
    if (i > 0)
      strncat(mnemonic, " ", sizeof(mnemonic) - strlen(mnemonic) - 1);
    strncat(mnemonic, entered_words[i],
            sizeof(mnemonic) - strlen(mnemonic) - 1);
  }

  return bip39_mnemonic_validate(NULL, mnemonic) == WALLY_OK;
}

static bool get_mnemonic_fingerprint_hex(char *hex_out) {
  if (!hex_out)
    return false;

  char mnemonic[MAX_MNEMONIC_LEN];
  mnemonic[0] = '\0';
  for (int i = 0; i < total_words; i++) {
    if (i > 0)
      strncat(mnemonic, " ", sizeof(mnemonic) - strlen(mnemonic) - 1);
    strncat(mnemonic, entered_words[i],
            sizeof(mnemonic) - strlen(mnemonic) - 1);
  }

  unsigned char seed[BIP39_SEED_LEN_512];
  if (bip39_mnemonic_to_seed512(mnemonic, NULL, seed, sizeof(seed)) != WALLY_OK)
    return false;

  struct ext_key *master_key = NULL;
  if (bip32_key_from_seed_alloc(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0,
                                &master_key) != WALLY_OK) {
    memset(seed, 0, sizeof(seed));
    return false;
  }
  memset(seed, 0, sizeof(seed));

  unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
  if (bip32_key_get_fingerprint(master_key, fingerprint,
                                BIP32_KEY_FINGERPRINT_LEN) != WALLY_OK) {
    bip32_key_free(master_key);
    return false;
  }
  bip32_key_free(master_key);

  for (int i = 0; i < BIP32_KEY_FINGERPRINT_LEN; i++)
    sprintf(hex_out + (i * 2), "%02x", fingerprint[i]);
  hex_out[BIP32_KEY_FINGERPRINT_LEN * 2] = '\0';

  return true;
}

static bool recalculate_last_word(void) {
  if (total_words < 12)
    return false;

  // Calculate entropy and checksum sizes based on word count
  // 12 words: 128 bits entropy + 4 bits checksum = 132 bits total
  // 24 words: 256 bits entropy + 8 bits checksum = 264 bits total
  size_t checksum_bits = total_words / 3; // 4 for 12 words, 8 for 24 words
  size_t entropy_bits = (total_words * 11) - checksum_bits;
  size_t entropy_bytes = entropy_bits / 8;
  size_t last_word_entropy_bits = 11 - checksum_bits; // 7 for 12, 3 for 24

  // Pack word indices (11 bits each) from first N-1 words
  uint8_t packed[32] = {0};
  int bit_pos = 0;

  for (int i = 0; i < total_words - 1; i++) {
    int idx = bip39_filter_get_word_index(entered_words[i]);
    if (idx < 0)
      return false;

    // Pack 11 bits into packed array
    for (int b = 10; b >= 0; b--) {
      int byte_idx = bit_pos / 8;
      int bit_idx = 7 - (bit_pos % 8);
      if (idx & (1 << b))
        packed[byte_idx] |= (1 << bit_idx);
      bit_pos++;
    }
  }

  // Pack the entropy bits from the current last word (top bits only)
  int last_idx = bip39_filter_get_word_index(entered_words[total_words - 1]);
  if (last_idx >= 0) {
    for (int b = 10; b > (int)(10 - last_word_entropy_bits); b--) {
      int byte_idx = bit_pos / 8;
      int bit_idx = 7 - (bit_pos % 8);
      if (last_idx & (1 << b))
        packed[byte_idx] |= (1 << bit_idx);
      bit_pos++;
    }
  }

  // Generate mnemonic from entropy using libwally
  char *new_mnemonic = NULL;
  if (bip39_mnemonic_from_bytes(NULL, packed, entropy_bytes, &new_mnemonic) !=
      WALLY_OK) {
    return false;
  }

  // Extract last word from generated mnemonic
  char *last_space = strrchr(new_mnemonic, ' ');
  if (last_space) {
    strncpy(entered_words[total_words - 1], last_space + 1,
            sizeof(entered_words[0]) - 1);
    entered_words[total_words - 1][sizeof(entered_words[0]) - 1] = '\0';
  }

  wally_free_string(new_mnemonic);
  return true;
}

static void update_fingerprint_display(void) {
  if (!fingerprint_icon || !fingerprint_text)
    return;

  if (is_checksum_valid()) {
    char fp_hex[9];
    if (get_mnemonic_fingerprint_hex(fp_hex)) {
      lv_label_set_text(fingerprint_text, fp_hex);
      lv_obj_clear_flag(fingerprint_icon, LV_OBJ_FLAG_HIDDEN);
      lv_obj_clear_flag(fingerprint_text, LV_OBJ_FLAG_HIDDEN);
    } else {
      lv_obj_add_flag(fingerprint_icon, LV_OBJ_FLAG_HIDDEN);
      lv_obj_add_flag(fingerprint_text, LV_OBJ_FLAG_HIDDEN);
    }
  } else {
    lv_obj_add_flag(fingerprint_icon, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(fingerprint_text, LV_OBJ_FLAG_HIDDEN);
  }
}

static void update_checksum_ui(void) {
  if (!checksum_error_label || !load_btn || !load_label)
    return;

  bool valid = is_checksum_valid();

  if (valid) {
    lv_obj_add_flag(checksum_error_label, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_state(load_btn, LV_STATE_DISABLED);
    lv_obj_set_style_text_color(load_label, main_color(), 0);
  } else {
    lv_obj_clear_flag(checksum_error_label, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_state(load_btn, LV_STATE_DISABLED);
    lv_obj_set_style_text_color(load_label, disabled_color(), 0);
  }

  update_fingerprint_display();
}

static void filter_words_by_prefix(void) {
  filtered_count = bip39_filter_by_prefix(
      current_prefix, prefix_len, filtered_words, BIP39_MAX_FILTERED_WORDS);
}

static void parse_mnemonic(const char *mnemonic) {
  total_words = 0;
  memset(entered_words, 0, sizeof(entered_words));
  memset(original_words, 0, sizeof(original_words));

  if (!mnemonic || !*mnemonic)
    return;

  char mnemonic_copy[MAX_MNEMONIC_LEN];
  strncpy(mnemonic_copy, mnemonic, sizeof(mnemonic_copy) - 1);
  mnemonic_copy[sizeof(mnemonic_copy) - 1] = '\0';

  char *token = strtok(mnemonic_copy, " ");
  while (token && total_words < 24) {
    strncpy(entered_words[total_words], token, sizeof(entered_words[0]) - 1);
    entered_words[total_words][sizeof(entered_words[0]) - 1] = '\0';
    strncpy(original_words[total_words], token, sizeof(original_words[0]) - 1);
    original_words[total_words][sizeof(original_words[0]) - 1] = '\0';
    total_words++;
    token = strtok(NULL, " ");
  }
}

static void cleanup_editing_ui(void) {
  if (current_menu) {
    ui_menu_destroy(current_menu);
    current_menu = NULL;
  }
  if (keyboard) {
    ui_keyboard_destroy(keyboard);
    keyboard = NULL;
  }
  if (keyboard_back_btn) {
    lv_obj_del(keyboard_back_btn);
    keyboard_back_btn = NULL;
  }
}

static void update_word_label(int index) {
  if (index < 0 || index >= total_words || !word_labels[index])
    return;

  char text[24];
  snprintf(text, sizeof(text), "%2d. %s", index + 1, entered_words[index]);
  lv_label_set_text(word_labels[index], text);

  bool changed = strcmp(entered_words[index], original_words[index]) != 0;
  lv_obj_set_style_text_color(word_labels[index],
                              changed ? highlight_color() : main_color(), 0);
}

static void show_word_grid(void) {
  if (word_grid_container)
    lv_obj_clear_flag(word_grid_container, LV_OBJ_FLAG_HIDDEN);
  if (grid_back_btn)
    lv_obj_clear_flag(grid_back_btn, LV_OBJ_FLAG_HIDDEN);
  if (load_btn)
    lv_obj_clear_flag(load_btn, LV_OBJ_FLAG_HIDDEN);
  if (header_container)
    lv_obj_clear_flag(header_container, LV_OBJ_FLAG_HIDDEN);
  if (is_new_mnemonic)
    update_fingerprint_display();
  else
    update_checksum_ui();
}

static void hide_word_grid(void) {
  if (word_grid_container)
    lv_obj_add_flag(word_grid_container, LV_OBJ_FLAG_HIDDEN);
  if (grid_back_btn)
    lv_obj_add_flag(grid_back_btn, LV_OBJ_FLAG_HIDDEN);
  if (header_container)
    lv_obj_add_flag(header_container, LV_OBJ_FLAG_HIDDEN);
  if (load_btn)
    lv_obj_add_flag(load_btn, LV_OBJ_FLAG_HIDDEN);
  if (checksum_error_label)
    lv_obj_add_flag(checksum_error_label, LV_OBJ_FLAG_HIDDEN);
}

static void return_to_word_grid(void) {
  cleanup_editing_ui();
  editing_word_index = -1;
  prefix_len = 0;
  current_prefix[0] = '\0';
  current_mode = MODE_WORD_GRID;
  show_word_grid();
}

static void word_clicked_cb(lv_event_t *e) {
  int index = (int)(intptr_t)lv_event_get_user_data(e);
  if (index < 0 || index >= total_words)
    return;

  editing_word_index = index;
  strncpy(current_prefix, entered_words[index], BIP39_MAX_PREFIX_LEN);
  current_prefix[BIP39_MAX_PREFIX_LEN] = '\0';
  prefix_len = strlen(current_prefix);

  hide_word_grid();
  show_keyboard_for_word(index);
}

static void update_keyboard_state(void) {
  if (!keyboard)
    return;

  char title[32];
  snprintf(title, sizeof(title), "Word %d/%d", editing_word_index + 1,
           total_words);
  ui_keyboard_set_title(keyboard, title);
  ui_keyboard_set_input_text(keyboard, current_prefix);
  ui_keyboard_set_letters_enabled(
      keyboard, bip39_filter_get_valid_letters(current_prefix, prefix_len));
  ui_keyboard_set_key_enabled(keyboard, UI_KB_KEY_BACKSPACE, prefix_len > 0);

  int match_count = bip39_filter_count_matches(current_prefix, prefix_len);
  ui_keyboard_set_ok_enabled(keyboard,
                             prefix_len > 0 && match_count > 0 &&
                                 match_count <= BIP39_MAX_FILTERED_WORDS);
}

static void keyboard_back_btn_cb(lv_event_t *e) {
  (void)e;
  return_to_word_grid();
}

static void show_keyboard_for_word(int index) {
  cleanup_editing_ui();
  current_mode = MODE_KEYBOARD_INPUT;

  char title[32];
  snprintf(title, sizeof(title), "Word %d/%d", index + 1, total_words);

  keyboard =
      ui_keyboard_create(mnemonic_editor_screen, title, keyboard_callback);
  if (!keyboard) {
    return_to_word_grid();
    return;
  }

  keyboard_back_btn =
      ui_create_back_button(mnemonic_editor_screen, keyboard_back_btn_cb);

  update_keyboard_state();
  ui_keyboard_show(keyboard);
}

static void show_word_confirmation(const char *word) {
  strncpy(pending_word, word, sizeof(pending_word) - 1);
  pending_word[sizeof(pending_word) - 1] = '\0';

  char msg[64];
  snprintf(msg, sizeof(msg), "Word %d: %s", editing_word_index + 1, word);

  show_prompt_dialog_overlay(msg, word_confirmation_cb, NULL);
}

static void word_confirmation_cb(bool confirmed, void *user_data) {
  (void)user_data;

  if (confirmed) {
    snprintf(entered_words[editing_word_index], sizeof(entered_words[0]), "%s",
             pending_word);
    pending_word[0] = '\0';
    update_word_label(editing_word_index);

    if (is_new_mnemonic) {
      // Auto-update last word if a different word was edited
      if (editing_word_index != total_words - 1) {
        if (recalculate_last_word()) {
          update_word_label(total_words - 1);
        }
      }
    } else {
      update_checksum_ui();
    }

    return_to_word_grid();
  } else {
    pending_word[0] = '\0';
    if (current_menu) {
      ui_menu_destroy(current_menu);
      current_menu = NULL;
    }

    if (keyboard) {
      ui_keyboard_show(keyboard);
      update_keyboard_state();
    } else {
      show_keyboard_for_word(editing_word_index);
    }
  }
}

static void keyboard_callback(char key) {
  if (key >= 'a' && key <= 'z') {
    if (prefix_len < BIP39_MAX_PREFIX_LEN) {
      current_prefix[prefix_len++] = key;
      current_prefix[prefix_len] = '\0';

      filter_words_by_prefix();
      if (filtered_count == 1) {
        show_word_confirmation(filtered_words[0]);
      } else {
        update_keyboard_state();
      }
    }
  } else if (key == UI_KB_BACKSPACE) {
    if (prefix_len > 0) {
      prefix_len--;
      current_prefix[prefix_len] = '\0';
      update_keyboard_state();
    }
  } else if (key == UI_KB_OK) {
    filter_words_by_prefix();
    if (filtered_count > 0)
      create_word_select_menu();
  }
}

static void create_word_select_menu(void) {
  if (keyboard) {
    ui_keyboard_hide(keyboard);
  }
  current_mode = MODE_WORD_SELECT;
  filter_words_by_prefix();

  if (filtered_count == 0) {
    if (keyboard)
      ui_keyboard_show(keyboard);
    current_mode = MODE_KEYBOARD_INPUT;
    return;
  }

  char title[64];
  snprintf(title, sizeof(title), "Select: %s...", current_prefix);

  current_menu =
      ui_menu_create(mnemonic_editor_screen, title, back_to_keyboard_cb);
  if (!current_menu)
    return;

  for (int i = 0; i < filtered_count; i++) {
    ui_menu_add_entry(current_menu, filtered_words[i], word_selected_cb);
  }
  ui_menu_show(current_menu);
}

static void word_selected_cb(void) {
  if (!current_menu)
    return;

  int selected = ui_menu_get_selected(current_menu);
  if (selected < 0 || selected >= filtered_count)
    return;

  const char *word = filtered_words[selected];
  if (current_menu)
    ui_menu_hide(current_menu);
  show_word_confirmation(word);
}

static void back_to_keyboard_cb(void) {
  if (current_menu) {
    ui_menu_destroy(current_menu);
    current_menu = NULL;
  }
  current_mode = MODE_KEYBOARD_INPUT;
  if (keyboard) {
    ui_keyboard_show(keyboard);
    update_keyboard_state();
  } else {
    show_keyboard_for_word(editing_word_index);
  }
}

static void back_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed && return_callback)
    return_callback();
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  show_prompt_dialog_overlay("Are you sure?", back_confirm_cb, NULL);
}

static void return_from_key_confirmation_cb(void) {
  key_confirmation_page_destroy();
  mnemonic_editor_page_show();
}

static void load_btn_cb(lv_event_t *e) {
  (void)e;

  char mnemonic[MAX_MNEMONIC_LEN];
  mnemonic[0] = '\0';

  for (int i = 0; i < total_words; i++) {
    if (i > 0)
      strncat(mnemonic, " ", sizeof(mnemonic) - strlen(mnemonic) - 1);
    strncat(mnemonic, entered_words[i],
            sizeof(mnemonic) - strlen(mnemonic) - 1);
  }

  if (bip39_mnemonic_validate(NULL, mnemonic) != WALLY_OK) {
    show_flash_error("Invalid checksum", NULL, 0);
    return;
  }

  mnemonic_editor_page_hide();
  key_confirmation_page_create(lv_screen_active(),
                               return_from_key_confirmation_cb,
                               success_callback, mnemonic, strlen(mnemonic));
  key_confirmation_page_show();
}

#define GRID_MARGIN_H 10
#define GRID_TOP_OFFSET 80 // Below back button area (20 padding + 60 button)
#define GRID_BOTTOM_OFFSET                                                     \
  80 // Above load button area (10 margin + 60 button + 10)

static lv_obj_t *create_column(lv_obj_t *parent, int x, int width, int height) {
  lv_obj_t *col = lv_obj_create(parent);
  lv_obj_set_pos(col, x, 0);
  lv_obj_set_size(col, width, height);
  lv_obj_set_style_bg_opa(col, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(col, 0, 0);
  lv_obj_set_style_pad_all(col, 0, 0);
  lv_obj_set_style_pad_row(col, 0, 0);
  lv_obj_set_style_pad_column(col, 0, 0);
  lv_obj_set_style_radius(col, 0, 0);
  lv_obj_set_flex_flow(col, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(col, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_START);
  lv_obj_clear_flag(col, LV_OBJ_FLAG_SCROLLABLE);
  return col;
}

static lv_obj_t *create_word_button(lv_obj_t *parent, int index, int height,
                                    lv_color_t bg) {
  char text[24];
  snprintf(text, sizeof(text), "%2d. %s", index + 1, entered_words[index]);

  lv_obj_t *btn = lv_btn_create(parent);
  lv_obj_set_size(btn, LV_PCT(100), height);
  theme_apply_touch_button(btn, false);
  lv_obj_set_style_radius(btn, 0, LV_STATE_DEFAULT);
  lv_obj_set_style_bg_color(btn, bg, LV_STATE_DEFAULT);
  lv_obj_set_style_bg_opa(btn, LV_OPA_COVER, LV_STATE_DEFAULT);
  lv_obj_add_event_cb(btn, word_clicked_cb, LV_EVENT_CLICKED,
                      (void *)(intptr_t)index);

  lv_obj_t *label = lv_label_create(btn);
  lv_label_set_text(label, text);
  lv_obj_align(label, LV_ALIGN_LEFT_MID, -10, 0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(label, main_color(), 0);

  word_labels[index] = label;
  return btn;
}

static void create_word_grid(void) {
  bool two_columns = (total_words > 12);
  int screen_width = lv_disp_get_hor_res(NULL);
  int screen_height = lv_disp_get_ver_res(NULL);
  int grid_width = screen_width - (2 * GRID_MARGIN_H);
  int grid_height = screen_height - GRID_TOP_OFFSET - GRID_BOTTOM_OFFSET;

  word_grid_container = lv_obj_create(mnemonic_editor_screen);
  lv_obj_set_pos(word_grid_container, GRID_MARGIN_H, GRID_TOP_OFFSET);
  lv_obj_set_size(word_grid_container, grid_width, grid_height);
  lv_obj_set_style_bg_opa(word_grid_container, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(word_grid_container, 0, 0);
  lv_obj_set_style_pad_all(word_grid_container, 0, 0);
  lv_obj_set_style_radius(word_grid_container, 0, 0);
  lv_obj_clear_flag(word_grid_container, LV_OBJ_FLAG_SCROLLABLE);

  if (two_columns) {
    // Two columns with chess pattern coloring
    int col_width = grid_width / 2 - 10;
    int btn_height = grid_height / 12;
    lv_obj_t *left_col =
        create_column(word_grid_container, 0, col_width, grid_height);
    lv_obj_t *right_col = create_column(
        word_grid_container, grid_width / 2 + 10, col_width, grid_height);

    for (int i = 0; i < total_words; i++) {
      lv_obj_t *parent_col = (i < 12) ? left_col : right_col;
      int col_idx = (i < 12) ? 0 : 1;
      int row_idx = (i < 12) ? i : i - 12;
      lv_color_t cell_bg =
          ((col_idx + row_idx) % 2 == 0) ? bg_color() : panel_color();
      create_word_button(parent_col, i, btn_height, cell_bg);
    }
  } else {
    int btn_height = grid_height / total_words;
    lv_obj_t *col =
        create_column(word_grid_container, 0, grid_width, grid_height);

    for (int i = 0; i < total_words; i++) {
      lv_color_t cell_bg = (i % 2 == 0) ? bg_color() : panel_color();
      create_word_button(col, i, btn_height, cell_bg);
    }
  }
}

static void create_ui(void) {
  header_container = theme_create_flex_row(mnemonic_editor_screen);
  lv_obj_set_style_pad_column(header_container, 15, 0);
  lv_obj_align(header_container, LV_ALIGN_TOP_MID, 0,
               theme_get_default_padding());

  lv_obj_t *title = lv_label_create(header_container);
  lv_label_set_text(title, "Review Mnemonic");
  lv_obj_set_style_text_font(title, theme_font_small(), 0);
  lv_obj_set_style_text_color(title, main_color(), 0);

  fingerprint_icon = lv_label_create(header_container);
  lv_label_set_text(fingerprint_icon, ICON_FINGERPRINT);
  lv_obj_set_style_text_font(fingerprint_icon, &icons_24, 0);
  lv_obj_set_style_text_color(fingerprint_icon, highlight_color(), 0);
  lv_obj_add_flag(fingerprint_icon, LV_OBJ_FLAG_HIDDEN);

  fingerprint_text = lv_label_create(header_container);
  lv_label_set_text(fingerprint_text, "--------");
  lv_obj_set_style_text_font(fingerprint_text, theme_font_small(), 0);
  lv_obj_set_style_text_color(fingerprint_text, highlight_color(), 0);
  lv_obj_add_flag(fingerprint_text, LV_OBJ_FLAG_HIDDEN);

  update_fingerprint_display();

  grid_back_btn = ui_create_back_button(mnemonic_editor_screen, back_btn_cb);
  create_word_grid();

  load_btn = lv_btn_create(mnemonic_editor_screen);
  lv_obj_set_size(load_btn, 140, 60);
  lv_obj_align(load_btn, LV_ALIGN_BOTTOM_RIGHT, -10, -10);
  theme_apply_touch_button(load_btn, true);
  lv_obj_add_event_cb(load_btn, load_btn_cb, LV_EVENT_CLICKED, NULL);

  load_label = lv_label_create(load_btn);
  lv_label_set_text(load_label, "Load");
  lv_obj_center(load_label);
  theme_apply_button_label(load_label, false);

  checksum_error_label = lv_label_create(mnemonic_editor_screen);
  lv_label_set_text(checksum_error_label, "Invalid checksum");
  lv_obj_set_style_text_color(checksum_error_label, error_color(), 0);
  lv_obj_set_style_text_font(checksum_error_label, theme_font_small(), 0);
  lv_obj_align_to(checksum_error_label, load_btn, LV_ALIGN_OUT_LEFT_MID, -10,
                  0);
  lv_obj_add_flag(checksum_error_label, LV_OBJ_FLAG_HIDDEN);

  if (!is_new_mnemonic)
    update_checksum_ui();
}

void mnemonic_editor_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                 void (*success_cb)(void), const char *mnemonic,
                                 bool new_mnemonic) {
  if (!parent)
    return;

  return_callback = return_cb;
  success_callback = success_cb;
  is_new_mnemonic = new_mnemonic;

  if (!bip39_filter_init()) {
    show_flash_error("Failed to load wordlist", return_cb, 0);
    return;
  }

  parse_mnemonic(mnemonic);

  if (total_words == 0) {
    show_flash_error("No words in mnemonic", return_cb, 0);
    return;
  }

  memset(word_labels, 0, sizeof(word_labels));
  editing_word_index = -1;
  prefix_len = 0;
  current_prefix[0] = '\0';
  filtered_count = 0;
  current_mode = MODE_WORD_GRID;

  mnemonic_editor_screen = theme_create_page_container(parent);
  create_ui();
}

void mnemonic_editor_page_show(void) {
  if (mnemonic_editor_screen)
    lv_obj_clear_flag(mnemonic_editor_screen, LV_OBJ_FLAG_HIDDEN);

  if (current_mode == MODE_WORD_GRID) {
    show_word_grid();
  } else if (current_mode == MODE_KEYBOARD_INPUT && keyboard) {
    ui_keyboard_show(keyboard);
  } else if (current_menu) {
    ui_menu_show(current_menu);
  }
}

void mnemonic_editor_page_hide(void) {
  if (mnemonic_editor_screen)
    lv_obj_add_flag(mnemonic_editor_screen, LV_OBJ_FLAG_HIDDEN);
  if (keyboard)
    ui_keyboard_hide(keyboard);
  if (current_menu)
    ui_menu_hide(current_menu);
}

void mnemonic_editor_page_destroy(void) {
  cleanup_editing_ui();

  if (mnemonic_editor_screen) {
    lv_obj_del(mnemonic_editor_screen);
    mnemonic_editor_screen = NULL;
  }

  grid_back_btn = NULL;
  word_grid_container = NULL;
  load_btn = NULL;
  load_label = NULL;
  header_container = NULL;
  fingerprint_icon = NULL;
  fingerprint_text = NULL;
  checksum_error_label = NULL;
  is_new_mnemonic = false;
  memset(word_labels, 0, sizeof(word_labels));
  memset(entered_words, 0, sizeof(entered_words));
  memset(original_words, 0, sizeof(original_words));
  memset(current_prefix, 0, sizeof(current_prefix));
  memset(pending_word, 0, sizeof(pending_word));

  return_callback = NULL;
  success_callback = NULL;
  total_words = 0;
  editing_word_index = -1;
  prefix_len = 0;
  filtered_count = 0;
  current_mode = MODE_WORD_GRID;
}

char *mnemonic_editor_get_mnemonic(void) {
  if (total_words == 0)
    return NULL;

  char *mnemonic = malloc(MAX_MNEMONIC_LEN);
  if (!mnemonic)
    return NULL;

  size_t pos = 0;
  for (int i = 0; i < total_words && pos < MAX_MNEMONIC_LEN - 1; i++) {
    if (i > 0 && pos < MAX_MNEMONIC_LEN - 1) {
      mnemonic[pos++] = ' ';
    }
    size_t word_len = strlen(entered_words[i]);
    size_t copy_len = (pos + word_len < MAX_MNEMONIC_LEN)
                          ? word_len
                          : MAX_MNEMONIC_LEN - 1 - pos;
    memcpy(mnemonic + pos, entered_words[i], copy_len);
    pos += copy_len;
  }
  mnemonic[pos] = '\0';

  return mnemonic;
}
