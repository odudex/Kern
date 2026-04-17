// PIN entry page — split-PIN unlock, setup, and change flows
//
// Uses ui_text_input (textarea + keyboard + eye toggle) for PIN entry,
// matching the KEF encrypt page pattern. PIN can contain letters, digits,
// and symbols.

#include "pin_page.h"
#include "../../core/pin.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/theme.h"
#include "../../utils/secure_mem.h"

#include <esp_system.h>
#include <lvgl.h>
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

typedef enum {
  // Unlock
  STATE_UNLOCK,
  // Setup
  STATE_SETUP_FULL_PIN,
  STATE_SETUP_CONFIRM_PIN,
  STATE_SETUP_SPLIT,
  STATE_SETUP_EFUSE,
  STATE_SETUP_SHOW_WORDS,
  // Delay / wipe
  STATE_DELAY,
} pin_flow_state_t;

// ---------------------------------------------------------------------------
// Static state
// ---------------------------------------------------------------------------

static lv_obj_t *page_screen = NULL;
static lv_obj_t *title_label = NULL;

// Text input (password-mode textarea + keyboard + eye toggle)
static ui_text_input_t text_input = {0};
static bool text_input_active = false;

// Content area for non-input states (words, split, delay)
static lv_obj_t *content_area = NULL;

// Delay countdown
static lv_timer_t *delay_timer = NULL;
// Reveal pause (anti-phishing keyboard hide)
static lv_timer_t *reveal_timer = NULL;
static lv_obj_t *delay_label = NULL;
static uint32_t delay_remaining_sec = 0;

// Split position picker
static lv_obj_t *split_display_label = NULL;
static lv_obj_t *left_btn = NULL;
static lv_obj_t *right_btn = NULL;
static lv_obj_t *split_eye_btn = NULL;
static lv_obj_t *split_eye_label = NULL;
static bool split_revealed = false;

static pin_page_mode_t current_mode;
static pin_flow_state_t current_state;
static pin_page_complete_cb_t on_complete = NULL;
static pin_page_cancel_cb_t on_cancel = NULL;

// Full PIN (for setup confirm + split)
static char setup_pin[PIN_MAX_LENGTH + 1];
static int setup_pin_len = 0;

// Prefix (for unlock: concatenate prefix + suffix)
static char prefix_buf[PIN_MAX_LENGTH + 1];
static int prefix_len = 0;

// Split position
static uint8_t split_pos = 1;

// Suffix (for deferred verification)
static char suffix_buf[PIN_MAX_LENGTH + 1];
static int suffix_len = 0;

// Inline anti-phishing words + identicon
static lv_obj_t *words_container = NULL; // flex row: identicon + words (unlock)
static lv_obj_t *identicon_canvas = NULL;
static lv_draw_buf_t *identicon_draw_buf = NULL;
static lv_draw_buf_t *setup_identicon_draw_buf = NULL; // setup words page
static lv_obj_t *words_label = NULL;
static lv_obj_t *words_warning = NULL;
static bool words_visible = false;
static char
    keystroke_cache[PIN_MAX_LENGTH + 1]; // prefix cache for change detection
static int keystroke_cache_len = 0;

// Processing overlay (shown during slow crypto operations)
static lv_obj_t *progress_dialog = NULL;

// Timer-compatible wrapper for esp_restart()
static void restart_cb(lv_timer_t *timer) {
  (void)timer;
  esp_restart();
}

// Forward declarations
static void transition_to(pin_flow_state_t state);
static void build_entry_state(const char *title_text);
static void build_unlock_entry_state(void);
static void build_split_state(void);
static void build_delay_state(void);
static void pin_mismatch_dismissed_cb(void);
static void wrong_pin_dismissed_cb(void);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Overwrite LVGL textarea content before clearing to prevent PIN plaintext
// from lingering in freed heap memory.
static void secure_clear_textarea(lv_obj_t *textarea) {
  if (!textarea)
    return;
  const char *text = lv_textarea_get_text(textarea);
  size_t len = text ? strlen(text) : 0;
  if (len > 0) {
    // Overwrite with spaces (same length forces LVGL to reuse the buffer)
    char dummy[PIN_MAX_LENGTH + 1];
    if (len > PIN_MAX_LENGTH)
      len = PIN_MAX_LENGTH;
    memset(dummy, ' ', len);
    dummy[len] = '\0';
    lv_textarea_set_text(textarea, dummy);
    secure_memzero(dummy, sizeof(dummy));
  }
  lv_textarea_set_text(textarea, "");
}

static void destroy_text_input(void) {
  if (text_input_active) {
    ui_text_input_destroy(&text_input);
    memset(&text_input, 0, sizeof(text_input));
    text_input_active = false;
  }
}

static void clear_state(void) {
  if (reveal_timer) {
    lv_timer_delete(reveal_timer);
    reveal_timer = NULL;
  }
  if (delay_timer) {
    lv_timer_delete(delay_timer);
    delay_timer = NULL;
  }
  // Destroy text input first (keyboard lives on lv_screen_active)
  destroy_text_input();
  // Free identicon draw buffers before cleaning page_screen
  if (identicon_draw_buf) {
    lv_draw_buf_destroy(identicon_draw_buf);
    identicon_draw_buf = NULL;
  }
  if (setup_identicon_draw_buf) {
    lv_draw_buf_destroy(setup_identicon_draw_buf);
    setup_identicon_draw_buf = NULL;
  }
  identicon_canvas = NULL;
  // Clean page_screen children (title, back btn, content_area)
  if (page_screen)
    lv_obj_clean(page_screen);
  title_label = NULL;
  content_area = NULL;
  delay_label = NULL;
  split_display_label = NULL;
  left_btn = NULL;
  right_btn = NULL;
  split_eye_btn = NULL;
  split_eye_label = NULL;
  split_revealed = false;
  words_container = NULL;
  words_label = NULL;
  words_warning = NULL;
  words_visible = false;
  secure_memzero(keystroke_cache, sizeof(keystroke_cache));
  keystroke_cache_len = 0;
}

static void clear_buffers(void) {
  secure_memzero(setup_pin, sizeof(setup_pin));
  setup_pin_len = 0;
  secure_memzero(prefix_buf, sizeof(prefix_buf));
  prefix_len = 0;
  secure_memzero(suffix_buf, sizeof(suffix_buf));
  suffix_len = 0;
}

// Create the centered flex-column content area (for non-input states)
static void create_content_area(void) {
  content_area = lv_obj_create(page_screen);
  lv_obj_remove_style_all(content_area);
  lv_obj_set_size(content_area, LV_PCT(100), LV_PCT(85));
  lv_obj_align(content_area, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_flex_flow(content_area, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(content_area, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_all(content_area, theme_get_default_padding(), 0);
  lv_obj_set_style_pad_gap(content_area, 8, 0);
}

// ---------------------------------------------------------------------------
// Deferred processing helpers
// ---------------------------------------------------------------------------
// Slow crypto (HMAC, PBKDF2) blocks the LVGL event loop. Show a progress
// overlay first, then defer the work via a one-shot timer so LVGL can render.

static void dismiss_processing(void) {
  if (progress_dialog) {
    lv_obj_delete(progress_dialog);
    progress_dialog = NULL;
  }
}

static void show_processing(lv_timer_cb_t callback) {
  progress_dialog =
      dialog_show_progress("PIN", "Processing...", DIALOG_STYLE_OVERLAY);
  lv_timer_t *t = lv_timer_create(callback, 50, NULL);
  lv_timer_set_repeat_count(t, 1);
}

// ---------------------------------------------------------------------------
// Text input ready callback (keyboard checkmark pressed)
// ---------------------------------------------------------------------------

static void deferred_verify_cb(lv_timer_t *timer) {
  (void)timer;

  // Concatenate prefix + suffix
  char full_pin[PIN_MAX_LENGTH * 2 + 1];
  int full_len = prefix_len + suffix_len;
  memcpy(full_pin, prefix_buf, prefix_len);
  memcpy(full_pin + prefix_len, suffix_buf, suffix_len);
  full_pin[full_len] = '\0';
  secure_memzero(suffix_buf, sizeof(suffix_buf));
  suffix_len = 0;

  pin_verify_result_t result = pin_verify(full_pin, full_len);
  secure_memzero(full_pin, sizeof(full_pin));

  dismiss_processing();

  switch (result) {
  case PIN_VERIFY_OK:
    clear_buffers();
    if (current_mode == PIN_PAGE_CHANGE)
      transition_to(STATE_SETUP_FULL_PIN);
    else if (on_complete)
      on_complete();
    break;
  case PIN_VERIFY_DELAY:
    transition_to(STATE_DELAY);
    break;
  case PIN_VERIFY_WIPED: {
    clear_buffers();
    dialog_show_error("Device wiped. All data erased.", NULL, 0);
    lv_timer_t *rt = lv_timer_create(restart_cb, 3000, NULL);
    lv_timer_set_repeat_count(rt, 1);
    break;
  }
  default:
    clear_buffers();
    // Defer the rebuild until the dialog dismisses; rebuilding now would
    // add the new keyboard above the error modal and hide the message.
    dialog_show_error("Wrong PIN", wrong_pin_dismissed_cb, 1500);
    break;
  }
}

static void pin_mismatch_dismissed_cb(void) {
  transition_to(STATE_SETUP_FULL_PIN);
}

static void wrong_pin_dismissed_cb(void) { transition_to(STATE_UNLOCK); }

static void input_ready_cb(lv_event_t *e) {
  (void)e;
  if (!text_input.textarea)
    return;
  const char *text = lv_textarea_get_text(text_input.textarea);
  if (!text || text[0] == '\0')
    return;

  size_t len = strlen(text);
  if (len > PIN_MAX_LENGTH)
    len = PIN_MAX_LENGTH;

  switch (current_state) {
  case STATE_UNLOCK: {
    memcpy(prefix_buf, text, len);
    prefix_buf[len] = '\0';
    prefix_len = (int)len;
    suffix_len = 0;
    suffix_buf[0] = '\0';
    secure_clear_textarea(text_input.textarea);
    show_processing(deferred_verify_cb);
    break;
  }

  case STATE_SETUP_FULL_PIN: {
    if (len < PIN_MIN_LENGTH) {
      dialog_show_error("PIN must be at least 6 characters", NULL, 1500);
      return;
    }
    memcpy(setup_pin, text, len);
    setup_pin[len] = '\0';
    setup_pin_len = (int)len;
    secure_clear_textarea(text_input.textarea);
    transition_to(STATE_SETUP_CONFIRM_PIN);
    break;
  }

  case STATE_SETUP_CONFIRM_PIN: {
    if ((int)len != setup_pin_len || secure_memcmp(text, setup_pin, len) != 0) {
      secure_memzero(setup_pin, sizeof(setup_pin));
      setup_pin_len = 0;
      secure_clear_textarea(text_input.textarea);
      // Defer the rebuild until the dialog dismisses; rebuilding now would
      // add the new keyboard above the error modal and hide the message.
      dialog_show_error("PINs don't match", pin_mismatch_dismissed_cb, 1500);
      return;
    }
    secure_clear_textarea(text_input.textarea);
    split_pos = setup_pin_len / 2;
    if (split_pos < 1)
      split_pos = 1;
    transition_to(STATE_SETUP_SPLIT);
    break;
  }

  default:
    break;
  }
}

// ---------------------------------------------------------------------------
// Text input entry state builder
// ---------------------------------------------------------------------------

static void back_btn_cb(lv_event_t *e);

// Back button (setup/change only) + title
static void build_chrome(const char *title_text) {
  if (current_mode != PIN_PAGE_UNLOCK)
    ui_create_back_button(page_screen, back_btn_cb);
  title_label = theme_create_page_title(page_screen, title_text);
}

static void build_entry_state(const char *title_text) {
  clear_state();
  build_chrome(title_text);

  // Text input: textarea + eye toggle + full keyboard
  ui_text_input_create(&text_input, page_screen, "", true, input_ready_cb);
  text_input_active = true;
}

// ---------------------------------------------------------------------------
// Identicon rendering
// ---------------------------------------------------------------------------

#define IDENTICON_SIZE 120
#define IDENTICON_CELLS 5
#define IDENTICON_CELL_PX (IDENTICON_SIZE / IDENTICON_CELLS) // 24px

static void render_identicon_to(lv_obj_t *canvas, lv_draw_buf_t *draw_buf,
                                uint8_t pattern[3]) {
  if (!canvas || !draw_buf)
    return;

  // Extract 15 cell bits from pattern[0..1] (3 independent cols x 5 rows)
  uint16_t bits = ((uint16_t)pattern[0] << 8) | pattern[1];

  // Convert hue byte to color: hue 0-255 → 0-359
  uint16_t hue = (uint16_t)pattern[2] * 359 / 255;
  lv_color_t fg = lv_color_hsv_to_rgb(hue, 70, 90);
  lv_color_t bg = lv_color_black();

  // Build 5x5 grid with vertical mirror:
  // col 0 = mirror of col 4, col 1 = mirror of col 3, col 2 = center
  // Independent columns: 0, 1, 2 → bits layout: row0col0, row0col1, row0col2,
  //                                              row1col0, row1col1, row1col2,
  //                                              ...
  bool cells[IDENTICON_CELLS][IDENTICON_CELLS];
  int bit_idx = 0;
  for (int row = 0; row < IDENTICON_CELLS; row++) {
    for (int col = 0; col < 3; col++) {
      bool on = (bits >> (14 - bit_idx)) & 1;
      bit_idx++;
      cells[row][col] = on;
      cells[row][IDENTICON_CELLS - 1 - col] = on; // mirror
    }
  }

  // Fill draw buffer pixel by pixel
  uint32_t stride = draw_buf->header.stride;
  uint8_t *buf = draw_buf->data;

  for (int y = 0; y < IDENTICON_SIZE; y++) {
    int row = y / IDENTICON_CELL_PX;
    uint16_t *row_ptr = (uint16_t *)(buf + y * stride);

    for (int x = 0; x < IDENTICON_SIZE; x++) {
      int col = x / IDENTICON_CELL_PX;
      bool on = cells[row][col];

      row_ptr[x] = lv_color_to_u16(on ? fg : bg);
    }
  }

  lv_obj_invalidate(canvas);
}

// ---------------------------------------------------------------------------
// Inline anti-phishing words (shown during unlock as user types)
// ---------------------------------------------------------------------------

static void reveal_restore_cb(lv_timer_t *timer) {
  (void)timer;
  reveal_timer = NULL;
  if (text_input.keyboard)
    lv_obj_clear_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
  if (text_input.textarea)
    lv_obj_clear_state(text_input.textarea, LV_STATE_DISABLED);
}

static void pin_keystroke_cb(lv_event_t *e) {
  (void)e;
  if (!text_input.textarea)
    return;

  const char *text = lv_textarea_get_text(text_input.textarea);
  size_t len = text ? strlen(text) : 0;

  if (len >= split_pos && split_pos > 0) {
    // Check if prefix portion changed since last computation
    bool prefix_changed = !words_visible ||
                          keystroke_cache_len != (int)split_pos ||
                          memcmp(keystroke_cache, text, split_pos) != 0;
    if (prefix_changed) {
      const char *word1 = NULL;
      const char *word2 = NULL;
      uint8_t identicon_data[3];
      esp_err_t err = pin_compute_anti_phishing(text, split_pos, &word1, &word2,
                                                identicon_data);
      if (err == ESP_OK && word1 && word2) {
        char words_buf[64];
        snprintf(words_buf, sizeof(words_buf), " %s %s", word1, word2);
        lv_label_set_text(words_label, words_buf);
        render_identicon_to(identicon_canvas, identicon_draw_buf,
                            identicon_data);
        lv_obj_clear_flag(words_container, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(words_warning, LV_OBJ_FLAG_HIDDEN);
        words_visible = true;
        // Pause: hide keyboard and disable textarea for 2s to draw attention
        lv_obj_add_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_state(text_input.textarea, LV_STATE_DISABLED);
        reveal_timer = lv_timer_create(reveal_restore_cb, 2000, NULL);
        lv_timer_set_repeat_count(reveal_timer, 1);
        // Cache prefix for change detection (separate from prefix_buf)
        memcpy(keystroke_cache, text, split_pos);
        keystroke_cache[split_pos] = '\0';
        keystroke_cache_len = (int)split_pos;
      }
    }
  } else if (words_visible) {
    lv_obj_add_flag(words_container, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(words_warning, LV_OBJ_FLAG_HIDDEN);
    words_visible = false;
    keystroke_cache_len = 0;
  }
}

static void build_unlock_entry_state(void) {
  clear_state();
  build_chrome("Enter PIN");

  // Text input: textarea + eye toggle + full keyboard
  ui_text_input_create(&text_input, page_screen, "", true, input_ready_cb);
  text_input_active = true;

  // Reposition textarea from default y=140 to y=60
  lv_obj_align(text_input.textarea, LV_ALIGN_TOP_LEFT, LV_HOR_RES * 5 / 100,
               60);
  // Re-align eye button to match
  if (text_input.eye_btn)
    lv_obj_align_to(text_input.eye_btn, text_input.textarea,
                    LV_ALIGN_OUT_RIGHT_MID, 5, 0);

  // Hidden flex row at y=115: identicon + words side-by-side
  words_container = lv_obj_create(page_screen);
  lv_obj_remove_style_all(words_container);
  lv_obj_set_flex_flow(words_container, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(words_container, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(words_container, 12, 0);
  lv_obj_set_size(words_container, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
  lv_obj_align(words_container, LV_ALIGN_TOP_MID, 0, 125);
  lv_obj_add_flag(words_container, LV_OBJ_FLAG_HIDDEN);

  // Identicon canvas (120x120 RGB565)
  identicon_draw_buf = lv_draw_buf_create(
      IDENTICON_SIZE, IDENTICON_SIZE, LV_COLOR_FORMAT_RGB565, LV_STRIDE_AUTO);
  if (identicon_draw_buf) {
    identicon_canvas = lv_canvas_create(words_container);
    lv_canvas_set_draw_buf(identicon_canvas, identicon_draw_buf);
    lv_obj_set_size(identicon_canvas, IDENTICON_SIZE, IDENTICON_SIZE);
  }

  // Words label (inside container)
  words_label = lv_label_create(words_container);
  lv_label_set_text(words_label, "");
  lv_obj_set_style_text_font(words_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(words_label, highlight_color(), 0);

  // Hidden warning label below identicon row (125 + 120 + 5 = 250)
  words_warning = lv_label_create(page_screen);
  lv_label_set_text(words_warning, "If image or words don't match, stop!");
  lv_obj_set_style_text_font(words_warning, theme_font_small(), 0);
  lv_obj_set_style_text_color(words_warning, error_color(), 0);
  lv_obj_set_style_text_align(words_warning, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(words_warning, LV_PCT(100));
  lv_obj_align(words_warning, LV_ALIGN_TOP_MID, 0, 260);
  lv_obj_add_flag(words_warning, LV_OBJ_FLAG_HIDDEN);

  // Attach keystroke callback if anti-phishing is available
  if (pin_has_anti_phishing()) {
    split_pos = pin_get_split_position();
    lv_obj_add_event_cb(text_input.keyboard, pin_keystroke_cb,
                        LV_EVENT_VALUE_CHANGED, NULL);
  }
}

// ---------------------------------------------------------------------------
// Split position picker
// ---------------------------------------------------------------------------

static void update_split_display(void) {
  if (!split_display_label)
    return;
  // Show PIN characters (or '*') with a | separator at split_pos
  char display[PIN_MAX_LENGTH * 2 + 4];
  int pos = 0;
  for (int i = 0; i < setup_pin_len; i++) {
    if (i == (int)split_pos) {
      display[pos++] = ' ';
      display[pos++] = '|';
      display[pos++] = ' ';
    } else if (i > 0) {
      display[pos++] = ' ';
    }
    display[pos++] = split_revealed ? setup_pin[i] : '*';
  }
  display[pos] = '\0';
  lv_label_set_text(split_display_label, display);

  if (left_btn) {
    if (split_pos <= 1)
      lv_obj_add_state(left_btn, LV_STATE_DISABLED);
    else
      lv_obj_remove_state(left_btn, LV_STATE_DISABLED);
  }
  if (right_btn) {
    if (split_pos >= setup_pin_len - 1)
      lv_obj_add_state(right_btn, LV_STATE_DISABLED);
    else
      lv_obj_remove_state(right_btn, LV_STATE_DISABLED);
  }
}

static void split_eye_cb(lv_event_t *e) {
  (void)e;
  split_revealed = !split_revealed;
  if (split_eye_label)
    lv_label_set_text(split_eye_label, split_revealed ? LV_SYMBOL_EYE_CLOSE
                                                      : LV_SYMBOL_EYE_OPEN);
  update_split_display();
}

static void split_left_cb(lv_event_t *e) {
  (void)e;
  if (split_pos > 1) {
    split_pos--;
    update_split_display();
  }
}

static void split_right_cb(lv_event_t *e) {
  (void)e;
  if (split_pos < setup_pin_len - 1) {
    split_pos++;
    update_split_display();
  }
}

static void deferred_pin_save(lv_timer_t *timer) {
  (void)timer;
  esp_err_t err = pin_setup(setup_pin, setup_pin_len, split_pos);
  clear_buffers();
  dismiss_processing();
  if (err != ESP_OK) {
    dialog_show_error("Failed to save PIN. Please try again.", NULL, 2000);
    transition_to(STATE_SETUP_FULL_PIN);
    return;
  }
  if (on_complete)
    on_complete();
}

static void split_confirm_cb(lv_event_t *e) {
  (void)e;
  pin_efuse_status_t status = pin_efuse_check();
  if (status == PIN_EFUSE_NOT_PROVISIONED)
    transition_to(STATE_SETUP_EFUSE);
  else if (status == PIN_EFUSE_PROVISIONED)
    transition_to(STATE_SETUP_SHOW_WORDS);
  else
    show_processing(deferred_pin_save);
}

static void build_split_state(void) {
  clear_state();
  build_chrome("Choose split position");
  create_content_area();

  // Description
  lv_obj_t *desc = lv_label_create(content_area);
  lv_label_set_text(desc, "Choose where to split your PIN.\n"
                          "After entering the first part, the device "
                          "will show an image and two words to verify "
                          "it hasn't been tampered with.\n"
                          "(prefix|suffix)");
  lv_obj_set_style_text_color(desc, secondary_color(), 0);
  lv_obj_set_style_text_align(desc, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(desc, LV_PCT(100));

  // PIN display row: label + eye toggle
  lv_obj_t *display_row = theme_create_flex_row(content_area);
  lv_obj_set_width(display_row, LV_PCT(80));
  lv_obj_set_flex_align(display_row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);

  split_display_label = lv_label_create(display_row);
  lv_obj_set_style_text_font(split_display_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(split_display_label, highlight_color(), 0);
  lv_obj_set_style_text_align(split_display_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_flex_grow(split_display_label, 1);

  split_eye_btn = lv_btn_create(display_row);
  lv_obj_set_size(split_eye_btn, theme_get_min_touch_size(),
                  theme_get_min_touch_size());
  lv_obj_set_style_bg_opa(split_eye_btn, LV_OPA_TRANSP, 0);
  lv_obj_set_style_shadow_width(split_eye_btn, 0, 0);
  lv_obj_set_style_border_width(split_eye_btn, 0, 0);
  lv_obj_add_event_cb(split_eye_btn, split_eye_cb, LV_EVENT_CLICKED, NULL);

  split_eye_label = lv_label_create(split_eye_btn);
  lv_label_set_text(split_eye_label, LV_SYMBOL_EYE_OPEN);
  lv_obj_set_style_text_color(split_eye_label, secondary_color(), 0);
  lv_obj_set_style_text_font(split_eye_label, theme_font_small(), 0);
  lv_obj_center(split_eye_label);

  // Arrow buttons row
  lv_obj_t *btn_row = theme_create_flex_row(content_area);
  lv_obj_set_width(btn_row, LV_PCT(60));
  lv_obj_set_flex_align(btn_row, LV_FLEX_ALIGN_SPACE_EVENLY,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

  left_btn = theme_create_button(btn_row, LV_SYMBOL_LEFT, false);
  lv_obj_set_size(left_btn, theme_get_button_width(),
                  theme_get_button_height());
  lv_obj_add_event_cb(left_btn, split_left_cb, LV_EVENT_CLICKED, NULL);

  right_btn = theme_create_button(btn_row, LV_SYMBOL_RIGHT, false);
  lv_obj_set_size(right_btn, theme_get_button_width(),
                  theme_get_button_height());
  lv_obj_add_event_cb(right_btn, split_right_cb, LV_EVENT_CLICKED, NULL);

  // Confirm button
  lv_obj_t *confirm = theme_create_button(content_area, "Confirm", true);
  lv_obj_set_size(confirm, LV_PCT(60), theme_get_button_height());
  lv_obj_add_event_cb(confirm, split_confirm_cb, LV_EVENT_CLICKED, NULL);

  update_split_display();
}

// ---------------------------------------------------------------------------
// eFuse provisioning dialog
// ---------------------------------------------------------------------------

static void efuse_confirm_result(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed) {
    lv_obj_t *progress = dialog_show_progress(
        "Provisioning", "Burning eFuse key...", DIALOG_STYLE_OVERLAY);
    esp_err_t err = pin_efuse_provision();
    if (progress)
      lv_obj_delete(progress);

    if (err != ESP_OK) {
      dialog_show_error("eFuse provisioning failed. "
                        "Anti-phishing will be unavailable.",
                        NULL, 3000);
    }
  }

  if (pin_efuse_check() == PIN_EFUSE_PROVISIONED) {
    transition_to(STATE_SETUP_SHOW_WORDS);
  } else {
    show_processing(deferred_pin_save);
  }
}

// ---------------------------------------------------------------------------
// Setup: show anti-phishing words after eFuse provisioning
// ---------------------------------------------------------------------------

static void setup_words_confirm_result(bool confirmed, void *user_data) {
  (void)user_data;
  if (confirmed)
    show_processing(deferred_pin_save);
  // "No" dismisses the dialog, revealing the words and Continue button
}

static void setup_words_continue_cb(lv_event_t *e) {
  (void)e;
  dialog_show_confirm("Have you recorded these words?",
                      setup_words_confirm_result, NULL, DIALOG_STYLE_OVERLAY);
}

static void build_setup_words_deferred(lv_timer_t *timer) {
  (void)timer;

  const char *word1 = NULL;
  const char *word2 = NULL;
  uint8_t identicon_data[3];
  esp_err_t err = pin_compute_anti_phishing(setup_pin, split_pos, &word1,
                                            &word2, identicon_data);

  if (err != ESP_OK || !word1 || !word2) {
    // HMAC failed — chain to deferred_pin_save (PBKDF2 is also slow)
    lv_timer_t *t = lv_timer_create(deferred_pin_save, 50, NULL);
    lv_timer_set_repeat_count(t, 1);
    return;
  }

  dismiss_processing();
  build_chrome("Record anti-phishing words");
  create_content_area();

  // Description
  lv_obj_t *desc = lv_label_create(content_area);
  lv_label_set_text(desc, "This icon and words will appear after you "
                          "enter your prefix during unlock. They prove "
                          "this is your device.");
  lv_obj_set_style_text_color(desc, secondary_color(), 0);
  lv_obj_set_style_text_align(desc, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(desc, LV_PCT(100));

  // Identicon + words row
  lv_obj_t *setup_row = lv_obj_create(content_area);
  lv_obj_remove_style_all(setup_row);
  lv_obj_set_flex_flow(setup_row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(setup_row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_gap(setup_row, 12, 0);
  lv_obj_set_size(setup_row, LV_SIZE_CONTENT, LV_SIZE_CONTENT);

  // Setup identicon
  setup_identicon_draw_buf = lv_draw_buf_create(
      IDENTICON_SIZE, IDENTICON_SIZE, LV_COLOR_FORMAT_RGB565, LV_STRIDE_AUTO);
  if (setup_identicon_draw_buf) {
    lv_obj_t *setup_canvas = lv_canvas_create(setup_row);
    lv_canvas_set_draw_buf(setup_canvas, setup_identicon_draw_buf);
    lv_obj_set_size(setup_canvas, IDENTICON_SIZE, IDENTICON_SIZE);
    render_identicon_to(setup_canvas, setup_identicon_draw_buf, identicon_data);
  }

  // Words column
  lv_obj_t *words_col = lv_obj_create(setup_row);
  lv_obj_remove_style_all(words_col);
  lv_obj_set_flex_flow(words_col, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(words_col, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_START,
                        LV_FLEX_ALIGN_START);
  lv_obj_set_style_pad_gap(words_col, 4, 0);
  lv_obj_set_size(words_col, LV_SIZE_CONTENT, LV_SIZE_CONTENT);

  lv_obj_t *w1 = lv_label_create(words_col);
  lv_label_set_text(w1, word1);
  lv_obj_set_style_text_font(w1, theme_font_medium(), 0);
  lv_obj_set_style_text_color(w1, highlight_color(), 0);

  lv_obj_t *w2 = lv_label_create(words_col);
  lv_label_set_text(w2, word2);
  lv_obj_set_style_text_font(w2, theme_font_medium(), 0);
  lv_obj_set_style_text_color(w2, highlight_color(), 0);

  // Continue button — let user read words before confirming
  lv_obj_t *btn = theme_create_button(content_area, "Continue", true);
  lv_obj_set_size(btn, LV_PCT(60), theme_get_button_height());
  lv_obj_add_event_cb(btn, setup_words_continue_cb, LV_EVENT_CLICKED, NULL);
}

static void build_setup_words_state(void) {
  clear_state();
  show_processing(build_setup_words_deferred);
}

// ---------------------------------------------------------------------------
// Delay countdown
// ---------------------------------------------------------------------------

static void delay_timer_cb(lv_timer_t *timer) {
  (void)timer;
  if (delay_remaining_sec == 0) {
    lv_timer_delete(delay_timer);
    delay_timer = NULL;
    transition_to(STATE_UNLOCK);
    return;
  }
  delay_remaining_sec--;
  if (delay_label) {
    char buf[48];
    snprintf(buf, sizeof(buf), "Try again in %lus",
             (unsigned long)delay_remaining_sec);
    lv_label_set_text(delay_label, buf);
  }
}

static void build_delay_state(void) {
  clear_state();

  uint32_t delay_ms = pin_get_delay_ms();
  delay_remaining_sec = (delay_ms + 999) / 1000;

  title_label = theme_create_page_title(page_screen, "Wrong PIN");
  lv_obj_set_style_text_color(title_label, error_color(), 0);

  create_content_area();

  // Attempts remaining
  lv_obj_t *attempts = lv_label_create(content_area);
  uint8_t fail = pin_get_fail_count();
  uint8_t max = pin_get_max_failures();
  char attempts_buf[48];
  snprintf(attempts_buf, sizeof(attempts_buf), "%u of %u attempts used", fail,
           max);
  lv_label_set_text(attempts, attempts_buf);
  lv_obj_set_style_text_color(attempts, secondary_color(), 0);
  lv_obj_set_style_text_align(attempts, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(attempts, LV_PCT(100));

  // Countdown label
  delay_label = lv_label_create(content_area);
  char buf[48];
  snprintf(buf, sizeof(buf), "Try again in %lus",
           (unsigned long)delay_remaining_sec);
  lv_label_set_text(delay_label, buf);
  lv_obj_set_style_text_font(delay_label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(delay_label, main_color(), 0);
  lv_obj_set_style_text_align(delay_label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_width(delay_label, LV_PCT(100));

  delay_timer = lv_timer_create(delay_timer_cb, 1000, NULL);
}

// ---------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------

static void transition_to(pin_flow_state_t state) {
  current_state = state;

  switch (state) {
  case STATE_UNLOCK:
    build_unlock_entry_state();
    break;
  case STATE_SETUP_FULL_PIN:
    build_entry_state("Choose your PIN");
    break;
  case STATE_SETUP_CONFIRM_PIN:
    build_entry_state("Confirm your PIN");
    break;
  case STATE_SETUP_SPLIT:
    build_split_state();
    break;
  case STATE_SETUP_EFUSE:
    dialog_show_confirm(
        "Enable anti-phishing protection?\n\n"
        "This will permanently burn a cryptographic key into the "
        "device hardware (eFuse).\n\n"
        "This is IRREVERSIBLE but enables anti-phishing words "
        "to detect device tampering.",
        efuse_confirm_result, NULL, DIALOG_STYLE_FULLSCREEN);
    break;
  case STATE_SETUP_SHOW_WORDS:
    build_setup_words_state();
    break;
  case STATE_DELAY:
    build_delay_state();
    break;
  }
}

// ---------------------------------------------------------------------------
// Back / cancel handler
// ---------------------------------------------------------------------------

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  if (current_mode == PIN_PAGE_UNLOCK)
    return;

  clear_buffers();
  if (on_cancel)
    on_cancel();
}

// ---------------------------------------------------------------------------
// Public lifecycle
// ---------------------------------------------------------------------------

void pin_page_create(lv_obj_t *parent, pin_page_mode_t mode,
                     pin_page_complete_cb_t complete_cb,
                     pin_page_cancel_cb_t cancel_cb) {
  if (!parent)
    return;

  current_mode = mode;
  on_complete = complete_cb;
  on_cancel = cancel_cb;
  clear_buffers();

  page_screen = lv_obj_create(parent);
  lv_obj_set_size(page_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(page_screen);
  lv_obj_clear_flag(page_screen, LV_OBJ_FLAG_SCROLLABLE);

  switch (mode) {
  case PIN_PAGE_UNLOCK:
  case PIN_PAGE_CHANGE:
    if (pin_get_delay_ms() > 0)
      transition_to(STATE_DELAY);
    else
      transition_to(STATE_UNLOCK);
    break;
  case PIN_PAGE_SETUP:
    transition_to(STATE_SETUP_FULL_PIN);
    break;
  }
}

void pin_page_show(void) {
  if (page_screen)
    lv_obj_clear_flag(page_screen, LV_OBJ_FLAG_HIDDEN);
}

void pin_page_hide(void) {
  if (page_screen)
    lv_obj_add_flag(page_screen, LV_OBJ_FLAG_HIDDEN);
}

void pin_page_destroy(void) {
  clear_buffers();
  dismiss_processing();
  clear_state();
  if (page_screen) {
    lv_obj_delete(page_screen);
    page_screen = NULL;
  }
  on_complete = NULL;
  on_cancel = NULL;
}
