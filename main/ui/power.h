#ifndef UI_POWER_H
#define UI_POWER_H

#include <stdbool.h>

// Dialog confirm callback: attempts PMIC power-off with fallback.
// If unload_key is true (passed as user_data), unloads wallet first and
// falls back to esp_restart(). Otherwise shows an error on failure.
void ui_power_off_confirmed_cb(bool confirmed, void *user_data);

#endif
