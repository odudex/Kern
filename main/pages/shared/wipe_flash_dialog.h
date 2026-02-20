/*
 * Wipe Flash Dialog
 *
 * Shared confirmation -> progress -> erase -> result flow for wiping
 * flash storage. Used by both mnemonic and descriptor load pages.
 */

#ifndef WIPE_FLASH_DIALOG_H
#define WIPE_FLASH_DIALOG_H

/**
 * Show the wipe flash confirmation dialog.
 * On confirm: shows progress, erases flash, shows result.
 * On success: calls complete_cb (typically navigates back).
 *
 * @param complete_cb Called after successful wipe
 */
void wipe_flash_dialog_start(void (*complete_cb)(void));

/**
 * Clean up any pending wipe timer/progress dialog.
 * Call from page destroy to avoid dangling references.
 */
void wipe_flash_dialog_cleanup(void);

#endif /* WIPE_FLASH_DIALOG_H */
