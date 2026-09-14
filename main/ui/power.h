#ifndef UI_POWER_H
#define UI_POWER_H

#include <stdbool.h>

// Dialog confirm callback: clears the session, then attempts PMIC power-off.
// Non-NULL user_data selects restart on failure; NULL returns to the gate
// page and shows an error instead.
void ui_power_off_confirmed_cb(bool confirmed, void *user_data);

#endif
