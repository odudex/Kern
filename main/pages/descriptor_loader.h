#ifndef DESCRIPTOR_LOADER_H
#define DESCRIPTOR_LOADER_H

#include "../core/descriptor_validator.h"
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
