#ifndef DESCRIPTOR_LOADER_H
#define DESCRIPTOR_LOADER_H

#include "../../core/descriptor_validator.h"
#include <lvgl.h>
#include <stdbool.h>

/**
 * Show error dialog for descriptor validation failures.
 * Returns true if an error was shown, false for non-error results
 * (SUCCESS, USER_DECLINED).
 */
bool descriptor_loader_show_error(descriptor_validation_result_t result);

/**
 * Extract descriptor from QR scanner, normalize, and validate.
 * Cleans up scanner pages (hide + destroy). Calls validation_cb with result.
 * If extraction fails, shows an error dialog and optionally calls error_cb.
 */
void descriptor_loader_process_scanner(validation_complete_cb validation_cb,
                                       void *user_data, void (*error_cb)(void));

/**
 * Process a descriptor from a raw string (e.g. loaded from storage).
 * Runs normalization and validation, same pipeline as process_scanner.
 *
 * @param descriptor_str  The raw descriptor string
 * @param validation_cb   Called with validation result
 * @param user_data       Passed to validation_cb
 */
void descriptor_loader_process_string(const char *descriptor_str,
                                      validation_complete_cb validation_cb,
                                      void *user_data);

/**
 * Show a source selection menu for loading descriptors.
 * Presents QR / Flash / SD Card options.
 *
 * @param parent   Parent LVGL object for the menu
 * @param qr_cb    Called when "From QR Code" is selected
 * @param flash_cb Called when "From Flash" is selected
 * @param sd_cb    Called when "From SD Card" is selected
 * @param back_cb  Called when user dismisses the menu
 */
void descriptor_loader_show_source_menu(lv_obj_t *parent, void (*qr_cb)(void),
                                        void (*flash_cb)(void),
                                        void (*sd_cb)(void),
                                        void (*back_cb)(void));

/**
 * Destroy the source selection menu if it exists.
 */
void descriptor_loader_destroy_source_menu(void);

/**
 * Extract descriptor string from QR scanner results.
 * Handles UR format (crypto-output, crypto-account) and plain text.
 * Must be called after a successful QR scan while scanner state is valid.
 *
 * @return Descriptor string (caller must free), or NULL on failure
 */
char *descriptor_extract_from_scanner(void);

// Normalize a descriptor by appending derivation path suffixes to keys
// without them. Strips any existing checksum.
// Returns new normalized string (caller must free), or NULL if unchanged.
char *descriptor_to_unambiguous(const char *descriptor);

#endif // DESCRIPTOR_LOADER_H
