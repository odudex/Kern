/* Exercise real LVGL/page lifetimes with public BIP39 test data. Release
 * observations happen BEFORE libc free, never by reading freed storage. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <lvgl.h>
#include "esp_lvgl_port.h"
#include "core/key.h"
#include "core/kef.h"
#include "core/wallet.h"
#include "pages/home/home.h"
#include "pages/home/backup/mnemonic_qr.h"
#include "pages/shared/kef_encrypt_page.h"
#include "pages/shared/kef_decrypt_page.h"
#include "pages/shared/key_confirmation.h"
#include "pages/shared/mnemonic_editor.h"
#include "pages/session_lock.h"
#include "pages/screensaver.h"
#include "pages/pin/pin_page.h"
#include "pages/scan/scan.h"
#include "pages/scan/scan_internal.h"
#include "qr/viewer.h"
#include "qr/parser.h"
#include "ui/display_cleanup.h"
#include "ui/input_helpers.h"
#include "ui/theme_widgets.h"
#include "utils/session.h"
#include "utils/session_cleanup.h"
#include "utils/worker_task.h"
#include "deflate_codec.h"
#include <freertos/task.h>

static const char mnemonic[] =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about";
static void *copies[64];
static unsigned release_count, copy_count;
static pthread_mutex_t observer_lock = PTHREAD_MUTEX_INITIALIZER;

char *__real_strdup(const char *s);
static char *track_copy(const char *s, char *p) {
  if (p && !strcmp(s, mnemonic)) {
    pthread_mutex_lock(&observer_lock);
    unsigned i;
    for (i = 0; i < 64 && copies[i]; ++i) {}
    assert(i < 64);
    copies[i] = p;
    ++copy_count;
    pthread_mutex_unlock(&observer_lock);
  }
  return p;
}

char *__wrap_strdup(const char *s) { return track_copy(s, __real_strdup(s)); }
char *__real_kern_secret_strdup(const char *s);
char *__wrap_kern_secret_strdup(const char *s) {
  return track_copy(s, __real_kern_secret_strdup(s));
}

void kern_memory_test_observe_release(void *p, size_t size) {
  const unsigned char *bytes = p;
  for (size_t i = 0; i < size; ++i)
    assert(bytes[i] == 0);
  pthread_mutex_lock(&observer_lock);
  for (unsigned i = 0; i < 64; ++i)
    if (copies[i] == p) copies[i] = NULL;
  ++release_count;
  pthread_mutex_unlock(&observer_lock);
}

static void assert_no_copies(void) {
  for (unsigned i = 0; i < 64; ++i) assert(!copies[i]);
}
static void unexpected_callback(void) { assert(!"callback after teardown"); }
static void unexpected_timer(lv_timer_t *timer) {
  (void)timer;
  unexpected_callback();
}
static lv_obj_t *find_widget(lv_obj_t *root, const lv_obj_class_t *class) {
  if (lv_obj_check_type(root, class)) return root;
  for (unsigned i = 0; i < lv_obj_get_child_count(root); ++i) {
    lv_obj_t *found = find_widget(lv_obj_get_child(root, i), class);
    if (found) return found;
  }
  return NULL;
}
static lv_obj_t *find_textarea(lv_obj_t *root) {
  return find_widget(root, &lv_textarea_class);
}
static void unexpected_decryption(const uint8_t *data, size_t len) {
  (void)data;
  (void)len;
  unexpected_callback();
}
static void flush(lv_display_t *display, const lv_area_t *area, uint8_t *pixels) {
  (void)area;
  (void)pixels;
  lv_display_flush_ready(display);
}
static void worker(void) { vTaskDelay(10); }

int main(void) {
  lv_init();
  lv_display_t *display = lv_display_create(720, 720);
  assert(display);
  const size_t buffer_size = 720 * 40 * 4;
  unsigned char *buffers[2] = {malloc(buffer_size), malloc(buffer_size)};
  assert(buffers[0] && buffers[1]);
  lv_display_set_buffers(display, buffers[0], buffers[1], buffer_size,
                         LV_DISPLAY_RENDER_MODE_PARTIAL);
  lv_display_set_flush_cb(display, flush);
  assert(lvgl_port_lock(0));
  theme_init();
  theme_apply_screen(lv_screen_active());
  assert(key_init());

  ui_text_input_t input = {0};
  ui_text_input_create(&input, lv_screen_active(), "PIN", true, NULL);
  lv_textarea_set_text(input.textarea, "123456789");
  lv_textarea_add_text(input.textarea, "0");
  lv_textarea_set_password_mode(input.textarea, false);
  lv_textarea_set_password_mode(input.textarea, true);
  ui_secure_clear_textarea(input.textarea);
  assert(!*lv_textarea_get_text(input.textarea));
  ui_text_input_destroy(&input);
  lv_obj_clean(lv_screen_active());

  size_t compressed_len, plain_len;
  uint8_t *compressed = deflate_compress_raw_alloc(
      (const uint8_t *)mnemonic, strlen(mnemonic), &compressed_len, 11);
  assert(compressed);
  uint8_t *plain = deflate_decompress_raw_alloc(
      compressed, compressed_len, &plain_len, 11, 1024);
  assert(plain && plain_len == strlen(mnemonic));
  assert(!memcmp(plain, mnemonic, plain_len));
  free(plain);
  free(compressed);

  for (unsigned i = 0; i < 2; ++i) {
    volatile bool done = false;
    assert(worker_task_start("cleanup-test", 4096, worker, &done));
    worker_task_wait();
    assert(done);
    worker_task_wait();
  }

  /* Destroy a real compressed-KEF page immediately after starting crypto,
   * before its poll timer can publish decrypted data to the caller. */
  uint8_t *envelope = NULL;
  size_t envelope_len = 0;
  assert(kef_encrypt((const uint8_t *)"test", 4, KEF_V21_GCM_Z_E4,
                     (const uint8_t *)"password", 8, 10000,
                     (const uint8_t *)mnemonic, strlen(mnemonic),
                     &envelope, &envelope_len) == KEF_OK);
  kef_decrypt_page_create(lv_screen_active(), unexpected_callback,
                          unexpected_decryption, envelope, envelope_len);
  free(envelope);
  lv_obj_t *password = find_textarea(lv_screen_active());
  lv_obj_t *keyboard = find_widget(lv_screen_active(), &lv_keyboard_class);
  assert(password && keyboard);
  lv_textarea_set_text(password, "password");
  lv_obj_send_event(keyboard, LV_EVENT_READY, NULL);
  session_cleanup_run();
  lv_obj_clean(lv_screen_active());
  lv_tick_inc(200);
  lv_timer_handler();

  assert(key_load_from_mnemonic(mnemonic, NULL, false));
  assert(wallet_init(WALLET_NETWORK_MAINNET));
  home_page_create(lv_screen_active());
  mnemonic_qr_page_create(lv_screen_active(), unexpected_callback);
  kef_encrypt_page_create(lv_screen_active(), unexpected_callback, NULL,
                          (const uint8_t *)mnemonic, strlen(mnemonic), "test");
  session_lock_init();
  session_set_screensaver_timeout(0);
  session_set_timeout(1);
  lv_tick_inc(1100);
  lv_timer_handler();
  assert(!key_is_loaded());
  assert(screensaver_is_active());
  assert(copy_count >= 2);
  assert_no_copies();
  session_cleanup_run(); /* Repeat cleanup must be harmless. */
  screensaver_destroy();

  /* A second timeout while already locked must discard PIN entry too. */
  pin_page_create(lv_screen_active(), PIN_PAGE_UNLOCK, unexpected_callback, NULL);
  lv_obj_t *pin_text = find_textarea(lv_screen_active());
  assert(pin_text);
  lv_textarea_set_text(pin_text, "1234");
  lv_tick_inc(1000);
  lv_display_trigger_activity(display);
  lv_timer_handler();
  lv_tick_inc(1100);
  lv_timer_handler();
  assert(screensaver_is_active());
  assert(!find_textarea(lv_screen_active()));
  screensaver_destroy();

  /* Direct formatted viewer callers share the same cleanup registration. */
  assert(qr_viewer_page_create_with_format(lv_screen_active(), FORMAT_NONE,
                                          mnemonic, "Fixture", unexpected_callback));
  session_cleanup_run();
  assert_no_copies();
  scan_defer_with_progress("Test", "Pending", unexpected_timer);
  scan_page_destroy();

  mnemonic_editor_page_create(lv_screen_active(), unexpected_callback,
                              unexpected_callback, mnemonic, false);
  char *edited = mnemonic_editor_get_mnemonic();
  assert(edited && !strcmp(edited, mnemonic));
  free(edited);
  session_cleanup_run();
  assert(!mnemonic_editor_get_mnemonic());
  key_confirmation_page_create(lv_screen_active(), unexpected_callback,
                               unexpected_callback, mnemonic, strlen(mnemonic));
  session_cleanup_run();
  lv_obj_clean(lv_screen_active());
  lv_tick_inc(2100);
  lv_timer_handler();
  assert(!key_is_loaded());
  assert_no_copies();

  memset(buffers[0], 0xa5, buffer_size);
  memset(buffers[1], 0xa5, buffer_size);
  ui_display_scrub();
  for (unsigned j = 0; j < 2; ++j)
    for (size_t i = 0; i < buffer_size; ++i) assert(!buffers[j][i]);
  lvgl_port_unlock();
  printf("Sensitive cleanup passed (%u fully wiped releases observed).\n",
         release_count);
  return 0;
}
