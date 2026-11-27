/* Exercise key replacement through the real SD-content entry point and
 * confirmation dialog, with encrypted backups in a disposable flash store. */
#include "core/key.h"
#include "core/registry.h"
#include "core/storage.h"
#include "core/wallet.h"
#include "esp_lvgl_port.h"
#include "pages/scan/scan.h"
#include "sim_flash.h"
#include "ui/theme.h"
#include <assert.h>
#include <lvgl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wally_core.h>

static const char *mnemonics[] = {
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank "
    "yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage "
    "above",
};
static unsigned returns;
static char flash_root[] = "/tmp/kern-scan-registry-XXXXXX";

static void cleanup(void) {
  wallet_unload();
  assert(storage_wipe_flash() == ESP_OK);
  assert(rmdir(flash_root) == 0);
  sim_flash_set_data_dir(NULL);
}

static void returned(void) {
  ++returns;
  scan_page_destroy();
}

static void flush(lv_display_t *display, const lv_area_t *area,
                  uint8_t *pixels) {
  (void)area;
  (void)pixels;
  lv_display_flush_ready(display);
}

static lv_obj_t *find_button(lv_obj_t *root, const char *text) {
  if (lv_obj_check_type(root, &lv_label_class) &&
      strcmp(lv_label_get_text(root), text) == 0) {
    lv_obj_t *parent = lv_obj_get_parent(root);
    if (lv_obj_check_type(parent, &lv_button_class))
      return parent;
  }
  for (uint32_t i = 0; i < lv_obj_get_child_count(root); ++i) {
    lv_obj_t *found = find_button(lv_obj_get_child(root, i), text);
    if (found)
      return found;
  }
  return NULL;
}

static void load_key(unsigned seed, wallet_network_t network) {
  wallet_unload();
  assert(key_load_from_mnemonic(mnemonics[seed], NULL,
                                network == WALLET_NETWORK_TESTNET));
  assert(wallet_init(network));
  registry_init(network == WALLET_NETWORK_TESTNET);
}

static void add_descriptor(const char *id, unsigned account, bool persist) {
  char path[32], fp[9], descriptor[256];
  unsigned coin = wallet_get_network() == WALLET_NETWORK_TESTNET ? 1 : 0;
  snprintf(path, sizeof(path), "m/84'/%u'/%u'", coin, account);
  char *xpub = NULL;
  assert(key_get_fingerprint_hex(fp));
  assert(key_get_xpub(path, &xpub));
  int n = snprintf(descriptor, sizeof(descriptor), "wpkh([%s/%s]%s/<0;1>/*)",
                   fp, path + 2, xpub);
  assert(n > 0 && (size_t)n < sizeof(descriptor));
  wally_free_string(xpub);
  assert(registry_add_from_string(id, descriptor, STORAGE_FLASH, persist));
}

static void replace_key(unsigned seed, bool confirm) {
  unsigned before = returns;
  scan_load_content(lv_screen_active(), (const uint8_t *)mnemonics[seed],
                    strlen(mnemonics[seed]), NULL, NULL, returned, NULL);
  lv_obj_t *button = find_button(lv_screen_active(), confirm ? "Yes" : "No");
  assert(button);
  lv_obj_send_event(button, LV_EVENT_CLICKED, NULL);
  assert(returns == before + 1);
}

static void check_registry(const char *id, wallet_network_t network) {
  assert(wallet_is_initialized());
  assert(wallet_get_network() == network);
  assert(registry_count() == 1);
  const registry_entry_t *entry = registry_find_by_id(id);
  assert(entry && entry->persisted);
}

static void test_network(wallet_network_t network) {
  const char *a = network == WALLET_NETWORK_MAINNET ? "a-main" : "a-test";
  const char *b = network == WALLET_NETWORK_MAINNET ? "b-main" : "b-test";
  load_key(0, network);
  add_descriptor(a, 0, true);
  load_key(1, network);
  add_descriptor(b, 0, true);

  load_key(0, network);
  check_registry(a, network);
  add_descriptor("session-only", 1, false);
  char original_fp[9], current_fp[9];
  assert(key_get_fingerprint_hex(original_fp));
  replace_key(1, false);
  assert(key_get_fingerprint_hex(current_fp));
  assert(strcmp(original_fp, current_fp) == 0);
  assert(registry_count() == 2 && registry_find_by_id("session-only"));
  puts("PASS: cancellation preserves the key and session descriptors");

  replace_key(1, true);
  assert(key_get_fingerprint_hex(current_fp));
  assert(strcmp(original_fp, current_fp) != 0);
  check_registry(b, network);
  assert(!registry_find_by_id(a) && !registry_find_by_id("session-only"));
  puts("PASS: replacement restores only the new key's registered descriptor");

  replace_key(0, true);
  check_registry(a, network);
  puts(
      "PASS: switching back restores the original key's registered descriptor");

  add_descriptor("session-only", 1, false);
  replace_key(0, true);
  check_registry(a, network);
  assert(!registry_find_by_id("session-only"));
  puts("PASS: reloading the same key restores backups but drops session "
       "entries");

  replace_key(2, true);
  assert(wallet_is_initialized() && wallet_get_network() == network);
  assert(registry_count() == 0);
  assert(!registry_name_registered(a) && !registry_name_registered(b));
  puts("PASS: a key without backups loads with an empty registry, the other "
       "keys' names free");

  replace_key(1, true);
  check_registry(b, network);
  replace_key(0, true);
  check_registry(a, network);
  puts("PASS: the other keys' backups remain");
}

int main(void) {
  assert(mkdtemp(flash_root));
  sim_flash_set_data_dir(flash_root);
  assert(storage_init() == ESP_OK);
  assert(atexit(cleanup) == 0);
  lv_init();
  lv_display_t *display = lv_display_create(720, 720);
  assert(display);
  static uint8_t pixels[720 * 40 * 4];
  lv_display_set_buffers(display, pixels, NULL, sizeof(pixels),
                         LV_DISPLAY_RENDER_MODE_PARTIAL);
  lv_display_set_flush_cb(display, flush);
  assert(lvgl_port_lock(0));
  theme_init();
  puts("Mainnet:");
  test_network(WALLET_NETWORK_MAINNET);
  puts("Testnet (mainnet backups also present):");
  test_network(WALLET_NETWORK_TESTNET);
  lvgl_port_unlock();
  puts("Scan registry regression passed.");
  return 0;
}
