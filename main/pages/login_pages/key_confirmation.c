#include "key_confirmation.h"
#include "../../key/key.h"
#include "../../ui_components/flash_error.h"
#include "../../ui_components/icons/icons_36.h"
#include "../../ui_components/theme.h"
#include "../../utils/memory_utils.h"
#include "../../utils/mnemonic_qr.h"
#include "../../wallet/wallet.h"
#include <lvgl.h>
#include <string.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>

#define LOADING_DELAY_MS 1000

static lv_obj_t *key_confirmation_screen = NULL;
static lv_timer_t *loading_timer = NULL;
static void (*return_callback)(void) = NULL;
static void (*success_callback)(void) = NULL;
static char *mnemonic_content = NULL;

static void loading_timer_cb(lv_timer_t *timer) {
  (void)timer;
  if (loading_timer) {
    lv_timer_del(loading_timer);
    loading_timer = NULL;
  }

  if (key_load_from_mnemonic(mnemonic_content, NULL, false)) {
    if (!wallet_init(WALLET_NETWORK_MAINNET)) {
      show_flash_error("Failed to initialize wallet", return_callback, 0);
      return;
    }
    if (success_callback)
      success_callback();
  } else {
    show_flash_error("Failed to load key", return_callback, 0);
  }
}

static void anim_size_cb(void *var, int32_t value) {
  lv_obj_t *obj = (lv_obj_t *)var;
  lv_obj_set_size(obj, value, value);
}

static void start_reveal_anim(lv_obj_t *obj, int32_t target_size,
                              uint32_t duration, uint32_t delay) {
  lv_obj_set_size(obj, 0, 0);
  lv_anim_t anim;
  lv_anim_init(&anim);
  lv_anim_set_var(&anim, obj);
  lv_anim_set_exec_cb(&anim, anim_size_cb);
  lv_anim_set_values(&anim, 0, target_size);
  lv_anim_set_duration(&anim, duration);
  lv_anim_set_delay(&anim, delay);
  lv_anim_set_path_cb(&anim, lv_anim_path_ease_out);
  lv_anim_start(&anim);
}

static void create_ui(const char *fingerprint_hex) {
  key_confirmation_screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(key_confirmation_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(key_confirmation_screen);
  lv_obj_clear_flag(key_confirmation_screen, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *center = theme_create_flex_column(key_confirmation_screen);
  lv_obj_set_style_pad_row(center, 20, 0);
  lv_obj_align(center, LV_ALIGN_TOP_MID, 0, 0);

    lv_obj_t *fp_row = theme_create_flex_row(center);
  lv_obj_set_style_pad_column(fp_row, 8, 0);

  // Circular clip container for reveal animation
  lv_obj_t *icon_clip = lv_obj_create(fp_row);
  lv_obj_remove_style_all(icon_clip);
  lv_obj_set_style_radius(icon_clip, LV_RADIUS_CIRCLE, 0);
  lv_obj_add_flag(icon_clip, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
  lv_obj_set_style_clip_corner(icon_clip, true, 0);

  lv_obj_t *icon = lv_label_create(icon_clip);
  lv_label_set_text(icon, ICON_FINGERPRINT_36);
  lv_obj_set_style_text_font(icon, &icons_36, 0);
  lv_obj_set_style_text_color(icon, highlight_color(), 0);
  lv_obj_center(icon);

  // Start circular reveal animation
  start_reveal_anim(icon_clip, 36, 700, 150);

  lv_obj_t *fp_text = lv_label_create(fp_row);
  lv_label_set_text(fp_text, fingerprint_hex);
  lv_obj_set_style_text_font(fp_text, theme_font_medium(), 0);
  lv_obj_set_style_text_color(fp_text, highlight_color(), 0);

  loading_timer = lv_timer_create(loading_timer_cb, LOADING_DELAY_MS, NULL);
  lv_timer_set_repeat_count(loading_timer, 1);
}

void key_confirmation_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                  void (*success_cb)(void), const char *content,
                                  size_t content_len) {
  (void)parent;
  return_callback = return_cb;
  success_callback = success_cb;

  SAFE_FREE_STATIC(mnemonic_content);
  mnemonic_content = mnemonic_qr_to_mnemonic(content, content_len, NULL);
  if (!mnemonic_content) {
    show_flash_error("Invalid mnemonic phrase", return_callback, 0);
    return;
  }

  unsigned char fingerprint[BIP32_KEY_FINGERPRINT_LEN];
  unsigned char seed[BIP39_SEED_LEN_512];
  struct ext_key *master_key = NULL;

  if (bip39_mnemonic_to_seed512(mnemonic_content, NULL, seed, sizeof(seed)) !=
          WALLY_OK ||
      bip32_key_from_seed_alloc(seed, sizeof(seed), BIP32_VER_MAIN_PRIVATE, 0,
                                &master_key) != WALLY_OK) {
    memset(seed, 0, sizeof(seed));
    show_flash_error("Failed to process mnemonic", return_callback, 0);
    return;
  }

  bip32_key_get_fingerprint(master_key, fingerprint, BIP32_KEY_FINGERPRINT_LEN);
  memset(seed, 0, sizeof(seed));
  bip32_key_free(master_key);

  char *fingerprint_hex = NULL;
  if (wally_hex_from_bytes(fingerprint, BIP32_KEY_FINGERPRINT_LEN,
                           &fingerprint_hex) != WALLY_OK) {
    show_flash_error("Failed to format fingerprint", return_callback, 0);
    return;
  }

  create_ui(fingerprint_hex);
  wally_free_string(fingerprint_hex);
}

void key_confirmation_page_show(void) {
  if (key_confirmation_screen)
    lv_obj_clear_flag(key_confirmation_screen, LV_OBJ_FLAG_HIDDEN);
}

void key_confirmation_page_hide(void) {
  if (key_confirmation_screen)
    lv_obj_add_flag(key_confirmation_screen, LV_OBJ_FLAG_HIDDEN);
}

void key_confirmation_page_destroy(void) {
  if (loading_timer) {
    lv_timer_del(loading_timer);
    loading_timer = NULL;
  }
  SAFE_FREE_STATIC(mnemonic_content);
  if (key_confirmation_screen) {
    lv_obj_del(key_confirmation_screen);
    key_confirmation_screen = NULL;
  }
  return_callback = NULL;
  success_callback = NULL;
}
