// Wallet Settings Page - Allows changing wallet attributes (passphrase,
// network)

#ifndef WALLET_SETTINGS_H
#define WALLET_SETTINGS_H

#include <lvgl.h>
#include <stdbool.h>

void wallet_settings_page_create(lv_obj_t *parent, void (*return_cb)(void));
void wallet_settings_page_show(void);
void wallet_settings_page_hide(void);
void wallet_settings_page_destroy(void);

// Returns true if settings were applied (and clears the flag)
bool wallet_settings_were_applied(void);

#endif // WALLET_SETTINGS_H
