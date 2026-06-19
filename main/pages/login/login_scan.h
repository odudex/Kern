#ifndef LOGIN_SCAN_H
#define LOGIN_SCAN_H

#include <lvgl.h>

/**
 * Start the login "Scan" flow: open the QR scanner and dispatch the result,
 * keyless. Tries to load a mnemonic (KEF / base43-wrapped KEF / plaintext or
 * SeedQR), else a watch-only descriptor (opens the addresses explorer directly
 * on it), else shows the raw content as unidentified. Mnemonic success proceeds
 * to home; every other path returns to login via return_to_login_cb.
 *
 * @param return_to_login_cb Called to restore the login menu on return.
 */
void login_scan_start(void (*return_to_login_cb)(void));

#endif // LOGIN_SCAN_H
