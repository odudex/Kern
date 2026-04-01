#pragma once

/**
 * Override the NVS data directory at runtime.
 * Must be called before nvs_flash_init().
 * dir should be the full path (e.g. "<data-dir>/nvs").
 */
void sim_nvs_set_data_dir(const char *dir);
