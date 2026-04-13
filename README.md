<p align="center">
  <img src="branding/kern_logo_with_text_dark_bg.png" alt="Kern" width="400">
</p>

<p align="center">
  <a href="docs/screens/login.png"><img src="docs/screens/login.png" width="15%"></a>
  <a href="docs/screens/enter_key.png"><img src="docs/screens/enter_key.png" width="15%"></a>
  <a href="docs/screens/home.png"><img src="docs/screens/home.png" width="15%"></a>
  <a href="docs/screens/addresses.png"><img src="docs/screens/addresses.png" width="15%"></a>
</p>
<p align="center">
  <a href="docs/screens/mnemonic_edit.png"><img src="docs/screens/mnemonic_edit.png" width="15%"></a>
  <a href="docs/screens/transcript.png"><img src="docs/screens/transcript.png" width="15%"></a>
  <a href="docs/screens/xpub.png"><img src="docs/screens/xpub.png" width="15%"></a>
  <a href="docs/screens/tx.png"><img src="docs/screens/tx.png" width="15%"></a>
</p>

Kern is an experimental project that explores the capabilities of the ESP32-P4 as a platform to perform air-gapped Bitcoin signatures and cryptography.

## Hardware

Kern supports two Waveshare ESP32-P4 boards:

| Board | Display | Touch | Camera |
|-------|---------|-------|--------|
| [ESP32-P4-WiFi6-Touch-LCD-4B](https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-4b.htm) (`wave_4b`) | 720x720 MIPI DSI | GT911 | OV5647 + DW9714 autofocus |
| [ESP32-P4-WiFi6-Touch-LCD-3.5](https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-3.5.htm) (`wave_35`) | 320x480 SPI | FT5x06 | OV5647 (no autofocus) |

ESP32-P4 does not contain radio (WiFi, BLE), but these boards have a radio in a secondary chip (ESP32-C6 mini). Later the project will migrate to use radio-less, simpler and cheaper boards with ESP32-P4 only.

An OV5647 camera module is required for both boards.

## Prerequisites

- [esp-idf v6.0](https://docs.espressif.com/projects/esp-idf/en/v6.0/esp32p4/get-started/index.html)

### Checkout ESP-IDF to Commit

Checkout to an early 6.1 version which has bugfixes we need for Kern

```bash
cd <your ESP-IDF installation dir>
git checkout 44c77cbf46844cd056c923277ece745173cb270d
git submodule update --recursive
./install.sh esp32p4
```

## Build

### Cloning the Repository

This project uses git submodules. You have two options:

#### Option 1: Clone with submodules (Recommended)

When cloning the project for the first time, make sure to clone it recursively to include all submodules:

```bash
git clone --recursive https://github.com/odudex/Kern.git
```

#### Option 2: Initialize submodules after cloning

If you've already cloned the repository without the `--recursive` flag, you can initialize and update the submodules with:

```bash
git submodule update --init --recursive
```

### Building the Project

Build with [just](https://github.com/casey/just) (recommended) or `idf.py` directly. All `just` commands accept a board parameter — `wave_4b` (default) or `wave_35`:

```bash
just build              # Build for wave_4b (default)
just build wave_35      # Build for wave_35
just flash wave_35      # Flash for wave_35
just monitor            # Serial monitor
just clean              # Required when switching boards
```

Or using `idf.py` directly:

```bash
# wave_4b
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_4b' build

# wave_35
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_35' build
```

> **Note:** Switching between boards requires a clean build (`just clean`) because sdkconfig is board-specific.

### Desktop Simulator

The simulator renders the full LVGL UI in an SDL2 window, matching each board's resolution:

```bash
just sim                # Run simulator as wave_4b (720x720)
just sim wave_35        # Run simulator as wave_35 (320x480)
just sim-build wave_35  # Build only
just sim-clean          # Remove simulator build artifacts
just sim-reset          # Wipe simulator data (factory reset)
just sim-qr IMG         # Run with a QR image
just sim-webcam         # Run with real webcam (V4L2)
```

Switching simulator boards also requires `just sim-clean` first. See [simulator/README.md](simulator/README.md) for details.

### Full Clean

After updating ESP-IDF or switching branches with significant build changes, do a full clean to avoid stale artifacts:

```bash
idf.py fullclean
rm sdkconfig
idf.py set-target esp32p4
idf.py build
```

### Build Options

#### Enable/disable Auto-focus

To enable camera auto-focus, enable camera focus motor on menuconfig:

```
CONFIG_CAM_MOTOR_DW9714=y
CONFIG_CAMERA_OV5647_ENABLE_MOTOR_BY_GPIO0=y
```

## Flashing Pre-releases

Pre-release firmware is provided **for testing purposes only**. Do not use pre-release builds as a signer for real savings.

### Supported Devices

| Device | Board | Display |
|--------|-------|---------|
| `wave_4b` | Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | 720x720 MIPI DSI |
| `wave_35` | Waveshare ESP32-P4-WiFi6-Touch-LCD-3.5 | 320x480 SPI |

### Requirements

- Python 3
- USB cable connected to the board

### Steps

1. Download the zip for your device from the [Releases](https://github.com/odudex/Kern/releases) page (e.g. `kern-wave_4b-v0.0.3.zip`).

2. Unzip the package:

```bash
unzip kern-wave_4b-v0.0.3.zip
```

The zip contains:
- `bootloader.bin` — bootloader
- `partition-table.bin` — partition table
- `firmware.bin` — application firmware
- `kern-v0.0.3.bin` — merged binary (all of the above)

3. Create a Python virtual environment and install esptool:

```bash
python3 -m venv venv
source venv/bin/activate
pip install esptool
```

4. Flash the merged binary (clean install):

```bash
esptool --chip esp32p4 --baud 460800 write-flash 0x0 kern-v0.0.3.bin
```

> **Note:** Flashing the merged binary from offset `0x0` erases the entire flash range it covers, including the NVS partition where PIN and settings are stored. To preserve NVS data when updating, flash the individual binaries instead:
>
> ```bash
> esptool --chip esp32p4 --baud 460800 write-flash \
>   0x2000 bootloader.bin \
>   0x8000 partition-table.bin \
>   0x20000 firmware.bin
> ```

## References

Kern is strongly inspired by [Krux](https://github.com/selfcustody/krux), sharing similar but simplified UI elements and flow.

[Blockstream Jade](https://github.com/Blockstream/Jade) was a strong inspiration for the decision to use C language for efficient use of the hardware. Additionally, Kern uses the same core library Jade does, [libwally](https://github.com/ElementsProject/libwally-core/), is shared with Jade.

The simplicity and UI polish of [SeedSigner](https://github.com/SeedSigner/seedsigner) and the security focus of the pioneering [Specter-DIY](https://github.com/cryptoadvance/specter-diy) were also strong inspirations.

## [Roadmap](ROADMAP.md)

## [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE)
