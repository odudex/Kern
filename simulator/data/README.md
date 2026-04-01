# Simulator Data Directory

Runtime fixture data used by the desktop simulator. These
directories provide initial content and test assets; the
simulator's **persistent state** is written to `sim_data/`
(configurable via `--data-dir`), not here.

## Directory Layout

```
data/
├── nvs/          Non-volatile storage seed files
├── qr_images/    QR code images for camera simulation
├── sdcard/       Pre-populated SD card content
└── spiffs/       SPIFFS partition content (placeholder)
```

## nvs/

Seed files for the simulated NVS (Non-Volatile Storage)
partition. At runtime the NVS simulator
(`platform/esp_idf_stubs/nvs_sim.c`) stores persistent
key-value data under `sim_data/nvs/` using a binary format:

```
[key_len:1B][key:NB][type:1B]
[value_len_lo:1B][value_len_hi:1B][value:NB]...
```

Types: `0x01` = u8, `0x02` = u16, `0x03` = blob.

Each namespace is stored as a separate `<namespace>.nvs`
file. Currently empty; files placed here can be copied into
`sim_data/nvs/` to bootstrap state.

## qr_images/

QR code images loaded by the video simulator
(`platform/video_sim/video_sim.c`) to emulate the hardware
camera. Supports PNG and JPEG formats.

Usage:

```bash
# Load a single image (held as a static frame)
just sim --qr-image simulator/data/qr_images/test_qr.png

# Cycle through all images in a directory at ~30 fps
just sim --qr-dir simulator/data/qr_images/
```

Images are decoded via stb_image, converted from RGB888 to
RGB565, and delivered to the application through the same
callback interface as the real camera driver.

**test_qr.png** - 210x210 RGB test QR code used for basic
scanning validation.

## sdcard/

Pre-populated content for the simulated SD card. At runtime
the SD card simulator (`platform/sd_card_sim/sd_card_sim.c`)
mounts `sim_data/sdcard/` and automatically creates the
following subdirectories on init:

```
sim_data/sdcard/
└── kern/
    ├── mnemonics/      Mnemonic backup files
    └── descriptors/    Wallet descriptor files
```

Files placed in `data/sdcard/` can serve as test fixtures
(e.g. sample descriptors to import).

## spiffs/

Content for the simulated SPIFFS partition. The simulator
creates the SPIFFS mount point directory via
`esp_vfs_spiffs_register()` but does not currently use it
for active storage. Reserved for future use.
