#include "power.h"

#include "../core/wallet.h"
#include "dialog.h"

#include <bsp/pmic.h>
#include <esp_system.h>

void ui_power_off_confirmed_cb(bool confirmed, void *user_data) {
  if (!confirmed)
    return;

  bool unload_key = (user_data != NULL);
  if (unload_key)
    wallet_unload();

  if (bsp_pmic_power_off() != ESP_OK) {
    if (unload_key) {
      esp_restart();
    } else {
      dialog_show_error_timeout("Power off failed", NULL, 2000);
    }
  }
}
