#ifndef BOOTLOADER_RANDOM_H
#define BOOTLOADER_RANDOM_H

// Host stub: the SAR ADC noise source has no analogue on the simulator, where
// esp_fill_random() reads /dev/urandom instead.
static inline void bootloader_random_enable(void) {}
static inline void bootloader_random_disable(void) {}

#endif // BOOTLOADER_RANDOM_H
