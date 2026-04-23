// Registered Descriptors sub-page — list, view, and remove registry entries

#include "registered_descriptors.h"
#include "../../core/registry.h"
#include "../../ui/dialog.h"
#include "../../ui/menu.h"
#include "../../ui/theme.h"
#include <lvgl.h>
#include <stdlib.h>
#include <string.h>
#include <wally_descriptor.h>

static lv_obj_t *rd_screen = NULL;
static ui_menu_t *rd_menu = NULL;
static void (*return_callback)(void) = NULL;
static int pending_remove_index = -1;

// clang-format off
static const unsigned char rd_cksum_pos[] = {
  0x5f,0x3c,0x5d,0x5c,0x1d,0x1e,0x33,0x10,0x0b,0x0c,0x12,0x34,0x0f,0x35,0x36,0x11,
  0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x1c,0x37,0x38,0x39,0x3a,0x3b,
  0x1b,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
  0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x0d,0x5e,0x0e,0x3d,0x3e,
  0x5b,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
  0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x1f,0x3f,0x20,0x40
};
// clang-format on
static const char rd_cksum_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint64_t rd_polymod(uint64_t c, int val) {
  uint8_t c0 = c >> 35;
  c = ((c & 0x7ffffffff) << 5) ^ val;
  if (c0 & 1)
    c ^= 0xf5dee51989;
  if (c0 & 2)
    c ^= 0xa9fdca3312;
  if (c0 & 4)
    c ^= 0x1bab10e32d;
  if (c0 & 8)
    c ^= 0x3706b1677a;
  if (c0 & 16)
    c ^= 0x644d626ffd;
  return c;
}

static bool rd_compute_checksum(const char *str, size_t len, char out[9]) {
  uint64_t c = 1;
  int cls = 0, clscount = 0;
  for (size_t i = 0; i < len; i++) {
    char ch = str[i];
    if (ch < ' ' || ch > '~')
      return false;
    size_t pos = rd_cksum_pos[(unsigned char)(ch - ' ')];
    if (pos == 0)
      return false;
    --pos;
    c = rd_polymod(c, pos & 31);
    cls = cls * 3 + (int)(pos >> 5);
    if (++clscount == 3) {
      c = rd_polymod(c, cls);
      cls = 0;
      clscount = 0;
    }
  }
  if (clscount > 0)
    c = rd_polymod(c, cls);
  for (int i = 0; i < 8; i++)
    c = rd_polymod(c, 0);
  c ^= 1;
  for (int i = 0; i < 8; i++)
    out[i] = rd_cksum_charset[(c >> (5 * (7 - i))) & 31];
  out[8] = '\0';
  return true;
}

static const char *get_type_badge(const struct wally_descriptor *desc) {
  if (!desc)
    return "?";
  char *canon = NULL;
  if (wally_descriptor_canonicalize(desc, WALLY_MS_CANONICAL_NO_CHECKSUM,
                                    &canon) != WALLY_OK)
    return "?";
  const char *badge;
  if (strncmp(canon, "sh(wpkh(", 8) == 0)
    badge = "sh-wpkh";
  else if (strncmp(canon, "wpkh(", 5) == 0)
    badge = "wpkh";
  else if (strncmp(canon, "wsh(", 4) == 0)
    badge = "wsh-multi";
  else if (strncmp(canon, "tr(", 3) == 0)
    badge = "tr";
  else if (strncmp(canon, "pkh(", 4) == 0)
    badge = "pkh";
  else
    badge = "custom";
  wally_free_string(canon);
  return badge;
}

static bool entry_to_string(const registry_entry_t *entry, char **output) {
  if (!entry || !entry->desc || !output)
    return false;
  char *canon = NULL;
  if (wally_descriptor_canonicalize(entry->desc, WALLY_MS_CANONICAL_NO_CHECKSUM,
                                    &canon) != WALLY_OK)
    return false;
  size_t body_len = strlen(canon);
  for (char *p = canon; *p; p++)
    if (*p == '\'')
      *p = 'h';
  char cksum[9];
  if (!rd_compute_checksum(canon, body_len, cksum)) {
    wally_free_string(canon);
    return false;
  }
  char *result = malloc(body_len + 1 + 8 + 1);
  if (!result) {
    wally_free_string(canon);
    return false;
  }
  memcpy(result, canon, body_len);
  result[body_len] = '#';
  memcpy(result + body_len + 1, cksum, 8);
  result[body_len + 9] = '\0';
  wally_free_string(canon);
  *output = result;
  return true;
}

static void build_rd_menu(void);

static void view_descriptor_cb(void) {
  int idx = ui_menu_get_selected(rd_menu);
  if (idx < 0)
    return;
  const registry_entry_t *entry = registry_get((size_t)idx);
  if (!entry)
    return;
  char *desc_str = NULL;
  if (!entry_to_string(entry, &desc_str))
    return;
  dialog_show_info(entry->id, desc_str, NULL, NULL, DIALOG_STYLE_OVERLAY);
  free(desc_str);
}

static void remove_confirmed_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed || pending_remove_index < 0)
    return;
  const registry_entry_t *entry = registry_get((size_t)pending_remove_index);
  if (entry)
    registry_remove(entry->id);
  pending_remove_index = -1;
  build_rd_menu();
}

static void remove_action_cb(int index) {
  pending_remove_index = index;
  dialog_show_danger_confirm("Remove this descriptor from the registry?",
                             remove_confirmed_cb, NULL, DIALOG_STYLE_OVERLAY);
}

static void rd_back_cb(void) {
  if (return_callback)
    return_callback();
}

static void build_rd_menu(void) {
  if (rd_menu) {
    ui_menu_destroy(rd_menu);
    rd_menu = NULL;
  }
  rd_menu = ui_menu_create(rd_screen, "Registered Descriptors", rd_back_cb);
  if (!rd_menu)
    return;

  size_t count = registry_count();
  if (count == 0) {
    ui_menu_add_entry(rd_menu, "(no registered descriptors)", NULL);
    ui_menu_set_entry_enabled(rd_menu, 0, false);
  } else {
    for (size_t i = 0; i < count; i++) {
      const registry_entry_t *entry = registry_get(i);
      if (!entry)
        continue;
      char label[REGISTRY_ID_MAX_LEN + 16];
      snprintf(label, sizeof(label), "%s [%s]", entry->id,
               get_type_badge(entry->desc));
      ui_menu_add_entry_with_action(rd_menu, label, view_descriptor_cb,
                                    LV_SYMBOL_TRASH, remove_action_cb);
    }
  }
  ui_menu_show(rd_menu);
}

void registered_descriptors_page_create(lv_obj_t *parent,
                                        void (*return_cb)(void)) {
  if (!parent)
    return;
  return_callback = return_cb;
  rd_screen = theme_create_page_container(parent);
  build_rd_menu();
}

void registered_descriptors_page_show(void) {
  if (rd_screen)
    lv_obj_clear_flag(rd_screen, LV_OBJ_FLAG_HIDDEN);
  if (rd_menu)
    ui_menu_show(rd_menu);
}

void registered_descriptors_page_hide(void) {
  if (rd_screen)
    lv_obj_add_flag(rd_screen, LV_OBJ_FLAG_HIDDEN);
  if (rd_menu)
    ui_menu_hide(rd_menu);
}

void registered_descriptors_page_destroy(void) {
  if (rd_menu) {
    ui_menu_destroy(rd_menu);
    rd_menu = NULL;
  }
  if (rd_screen) {
    lv_obj_del(rd_screen);
    rd_screen = NULL;
  }
  pending_remove_index = -1;
  return_callback = NULL;
}
