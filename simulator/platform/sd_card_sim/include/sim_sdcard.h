#pragma once

/**
 * Override the SD card root directory at runtime.
 * Must be called before sd_card_init().
 * dir should be the simulated card root (e.g. "<data-dir>/sdcard"); subdirs
 * kern/mnemonics and kern/descriptors are created under it.
 */
void sim_sdcard_set_data_dir(const char *dir);
