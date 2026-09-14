#include "power.h"

#include "../pages/session_lock.h"
#include "dialog.h"

#include <bsp/pmic.h>
#include <esp_system.h>

void ui_power_off_confirmed_cb(bool confirmed, void *user_data) {
  if (!confirmed)
    return;

  bool unload_key = (user_data != NULL);
  session_lock_now();

  if (bsp_pmic_power_off() != ESP_OK) {
    if (unload_key) {
      esp_restart();
    } else {
      // Nothing was loaded: put the user back on the gate page they came
      // from instead of leaving them on the lock face.
      session_lock_dismiss();
      dialog_show_error_timeout("Power off failed", NULL, 2000);
    }
  }
}
