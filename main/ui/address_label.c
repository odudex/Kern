#include "address_label.h"
#include "theme.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Block sizes a tap cycles through, 0 shows the plain address
static const size_t BLOCK_SIZES[] = {4, 6, 0};
#define BLOCK_SIZES_COUNT (sizeof(BLOCK_SIZES) / sizeof(BLOCK_SIZES[0]))

// Recolor markup around each block: separator space, "#RRGGBB " and "#"
#define BLOCK_MARKUP_LEN 10

typedef struct {
  size_t mode;
  char address[];
} address_label_t;

static uint32_t color_hex(lv_color_t color) {
  lv_color32_t c = lv_color_to_32(color, LV_OPA_COVER);
  return (c.red << 16) | (c.green << 8) | c.blue;
}

// Show `address` in `block_size`-char blocks with alternating primary and
// highlight colors, or plain when `block_size` is 0. Returns false when out of
// memory, the label then keeps its text.
static bool set_blocks_text(lv_obj_t *label, const char *address,
                            size_t block_size) {
  if (block_size == 0) {
    lv_label_set_text(label, address);
    return true;
  }

  size_t len = strlen(address);
  size_t blocks = (len + block_size - 1) / block_size;
  size_t size = len + blocks * BLOCK_MARKUP_LEN + 1;
  char *text = malloc(size);
  if (!text)
    return false;

  uint32_t hex1 = color_hex(primary_color());
  uint32_t hex2 = color_hex(highlight_color());
  size_t written = 0;
  text[0] = '\0';
  for (size_t pos = 0; pos < len; pos += block_size) {
    uint32_t color = ((pos / block_size) % 2 == 0) ? hex1 : hex2;
    size_t chunk = (len - pos < block_size) ? (len - pos) : block_size;
    written += snprintf(text + written, size - written, "%s#%06X %.*s#",
                        (pos > 0) ? " " : "", (unsigned)color, (int)chunk,
                        address + pos);
  }

  lv_label_set_text(label, text);
  free(text);
  return true;
}

static void address_label_clicked_cb(lv_event_t *e) {
  lv_obj_t *label = lv_event_get_target(e);
  address_label_t *state = lv_event_get_user_data(e);
  size_t next = (state->mode + 1) % BLOCK_SIZES_COUNT;
  if (set_blocks_text(label, state->address, BLOCK_SIZES[next]))
    state->mode = next;
}

static void address_label_delete_cb(lv_event_t *e) {
  free(lv_event_get_user_data(e));
}

lv_obj_t *address_label_create(lv_obj_t *parent, const char *address) {
  lv_obj_t *label = lv_label_create(parent);
  lv_label_set_recolor(label, true);
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(label, primary_color(), 0);
  lv_label_set_text(label, address);

  size_t len = strlen(address);
  address_label_t *state = malloc(sizeof(*state) + len + 1);
  if (!state)
    return label;
  state->mode = 0;
  memcpy(state->address, address, len + 1);
  set_blocks_text(label, state->address, BLOCK_SIZES[state->mode]);

  lv_obj_add_flag(label, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(label, address_label_clicked_cb, LV_EVENT_CLICKED, state);
  lv_obj_add_event_cb(label, address_label_delete_cb, LV_EVENT_DELETE, state);
  return label;
}
