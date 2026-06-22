/*
 * Persistent storage for mnemonics and descriptors
 *
 * Stores KEF-encrypted or plaintext data on SPIFFS (flash) or SD card.
 * Flash: raw binary (no encoding overhead on constrained SPIFFS).
 * SD card: base64-encoded for KEF, raw text for plaintext.
 *
 * Mnemonic paths:
 *   Flash:  /spiffs/m_<sanitized_id>.kef
 *   SD:     /sdcard/kern/mnemonics/<sanitized_id>.kef
 *
 * Descriptor paths:
 *   Flash:  /spiffs/d_<sanitized_id>.kef or .txt
 *   SD:     /sdcard/kern/descriptors/<sanitized_id>.kef or .txt
 */

#ifndef STORAGE_H
#define STORAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

typedef enum {
  STORAGE_FLASH,
  STORAGE_SD,
} storage_location_t;

#define STORAGE_FLASH_BASE_PATH "/spiffs"
#define STORAGE_SD_MNEMONICS_DIR "/sdcard/kern/mnemonics"
#define STORAGE_SD_DESCRIPTORS_DIR "/sdcard/kern/descriptors"

#define STORAGE_MAX_SANITIZED_ID_LEN 24
#define STORAGE_MNEMONIC_PREFIX "m_"
#define STORAGE_MNEMONIC_EXT ".kef"
#define STORAGE_DESCRIPTOR_PREFIX "d_"
#define STORAGE_DESCRIPTOR_EXT_KEF ".kef"
#define STORAGE_DESCRIPTOR_EXT_TXT ".txt"

/**
 * Initialize flash storage (mount SPIFFS). Safe to call multiple times.
 */
esp_err_t storage_init(void);

/**
 * Save a KEF envelope. Flash: raw binary. SD: base64-encoded.
 *
 * @param loc           Flash or SD card
 * @param id            Raw KEF ID (sanitized for the filename)
 * @param kef_envelope  Binary KEF envelope
 * @param len           Length of KEF envelope
 */
esp_err_t storage_save_mnemonic(storage_location_t loc, const char *id,
                                const uint8_t *kef_envelope, size_t len);

/**
 * Load a mnemonic file. Flash: raw binary. SD: base64-decoded.
 *
 * @param loc              Flash or SD card
 * @param filename         Filename (e.g. "m_73C5DA0A.kef")
 * @param kef_envelope_out Receives heap-allocated binary KEF envelope
 * @param len_out          Receives length
 */
esp_err_t storage_load_mnemonic(storage_location_t loc, const char *filename,
                                uint8_t **kef_envelope_out, size_t *len_out);

/**
 * List stored mnemonic files.
 *
 * @param loc            Flash or SD card
 * @param filenames_out  Receives array of filename strings (caller frees
 *                       with storage_free_file_list)
 * @param count_out      Receives count
 */
esp_err_t storage_list_mnemonics(storage_location_t loc, char ***filenames_out,
                                 int *count_out);

/**
 * Delete a stored mnemonic file.
 */
esp_err_t storage_delete_mnemonic(storage_location_t loc, const char *filename);

/**
 * Securely wipe flash storage.
 * Unmounts SPIFFS, erases the entire partition (all bytes -> 0xFF),
 * then remounts with a fresh filesystem.
 */
esp_err_t storage_wipe_flash(void);

/**
 * Check if a mnemonic with the given ID already exists.
 */
bool storage_mnemonic_exists(storage_location_t loc, const char *id);

/**
 * Sanitize a raw ID for use as a filename component.
 *
 * Rules:
 * 1. Replace \ / : * ? " < > | and spaces with _
 * 2. Strip leading/trailing whitespace and dots
 * 3. Collapse consecutive underscores
 * 4. Truncate to STORAGE_MAX_SANITIZED_ID_LEN
 * 5. Fallback to SHA-256 hex prefix if result is empty
 */
void storage_sanitize_id(const char *raw_id, char *out, size_t out_size);

/**
 * Free a file list returned by storage_list_mnemonics or
 * storage_list_descriptors.
 */
void storage_free_file_list(char **files, int count);

/**
 * Extract display name from a KEF envelope's header ID field.
 *
 * @param data  Raw KEF envelope data
 * @param len   Length of data
 * @return Heap-allocated ID string, or NULL on failure. Caller frees.
 */
char *storage_get_kef_display_name(const uint8_t *data, size_t len);

/* ---------- Descriptor storage ---------- */

/**
 * Save a descriptor. If encrypted, saves KEF envelope (raw on flash,
 * base64 on SD). If plaintext, saves raw text on both.
 *
 * @param loc       Flash or SD card
 * @param id        Raw ID (sanitized for the filename)
 * @param data      Descriptor data (KEF envelope or plaintext string)
 * @param len       Length of data
 * @param encrypted true for .kef, false for .txt
 */
esp_err_t storage_save_descriptor(storage_location_t loc, const char *id,
                                  const uint8_t *data, size_t len,
                                  bool encrypted);

/**
 * Load a descriptor file. Detects format by extension.
 * .kef on SD: base64-decoded. .txt: raw text. .kef on flash: raw binary.
 *
 * @param loc           Flash or SD card
 * @param filename      Filename (e.g. "d_MyWallet.kef" or "MyWallet.txt")
 * @param data_out      Receives heap-allocated data
 * @param len_out       Receives length
 * @param encrypted_out Receives true if file is .kef, false if .txt
 */
esp_err_t storage_load_descriptor(storage_location_t loc, const char *filename,
                                  uint8_t **data_out, size_t *len_out,
                                  bool *encrypted_out);

/**
 * List stored descriptor files (.kef and .txt).
 */
esp_err_t storage_list_descriptors(storage_location_t loc,
                                   char ***filenames_out, int *count_out);

/**
 * Delete a stored descriptor file.
 */
esp_err_t storage_delete_descriptor(storage_location_t loc,
                                    const char *filename);

/**
 * Check if a descriptor with the given ID already exists.
 */
bool storage_descriptor_exists(storage_location_t loc, const char *id,
                               bool encrypted);

/**
 * Build the full filesystem path a descriptor with the given ID would be saved
 * to, matching storage_save_descriptor's convention (flash: /spiffs/d_<id>.ext;
 * SD: /sdcard/kern/descriptors/<id>.ext). out is always NUL-terminated. No
 * filesystem access.
 */
void storage_descriptor_path(storage_location_t loc, const char *id,
                             bool encrypted, char *out, size_t out_size);

#endif /* STORAGE_H */
