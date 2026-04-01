# KERN

Kern is an experimental project that explores the capabilities of the ESP32-P4 as a platform to perform air-gapped Bitcoin signatures and cryptography.

## Hardware

Early development uses the [Waveshare ESP32-P4-WiFi6-Touch-LCD-4B](https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-4b.htm).

ESP32-P4 does not contain radio (WiFi, BLE), but this board has a radio in a secondary chip (ESP32-C6 mini). Later the project will migrate to use radio-less, simpler and cheaper boards with ESP32-P4 only.

An OV5647 camera module is also required.

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

Build the project from the root directory with:

```bash
idf.py build
```

or flash the project to the device with:

```bash
idf.py flash
```

and if you are debugging you may want to run monitor too:

```bash
idf.py monitor
```

#### Optional: Using `just`

If you have [just](https://github.com/casey/just) installed, you can use the provided `.justfile`:

```bash
just build   # Build the project
just flash   # Flash to device
just clean   # Clean build artifacts

# Desktop simulator
just sim-build  # Build the simulator
just sim        # Build and run the simulator
just sim-clean  # Remove simulator build artifacts
just sim-reset  # Wipe simulator data (factory reset)
just sim-qr IMG # Run simulator with a QR image
```

The simulator renders the full LVGL UI in an SDL2 window.
Pass extra flags after `just sim`, e.g.
`just sim --qr-dir path/to/images/ --verbose`.
See [simulator/README.md](simulator/README.md) for details.

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

### Requirements

- Python 3
- USB cable connected to the Waveshare board

### Steps

1. Download the firmware binary from the [Releases](https://github.com/odudex/Kern/releases) page.

2. Create a Python virtual environment and install esptool:

```bash
python3 -m venv venv
source venv/bin/activate
pip install esptool
```

3. Flash the firmware:

```bash
esptool --chip esp32p4 --baud 460800 write-flash 0x0 kern-<version>.bin
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
