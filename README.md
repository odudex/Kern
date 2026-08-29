<p align="center">
  <img src="branding/kern_logo_with_text_dark_bg.png" alt="Kern" width="400">
</p>

<p align="center">
  <a href="https://odudex.github.io/Kern/"><b>Website</b></a> ·
  <a href="https://odudex.github.io/Kern/flash/"><b>Web Flasher</b></a> ·
  <a href="https://t.me/kern_custody"><b>Telegram</b></a> ·
  <a href="ROADMAP.md"><b>Roadmap</b></a>
</p>

Kern is a research and development project exploring what new hardware can do for Bitcoin self-custody. It takes the form of an air-gapped signing device on the ESP32-P4: the chip has no radio, so keys are generated and used on hardware that physically cannot reach a network. Transactions cross the air gap as QR codes or over an SD card.

The goal is to explore ideas: new silicon, new interfaces, new backup and signing workflows. They get implemented, tested and documented in the open. Kern is a research platform and intends to stay one; it is not on a path to becoming a product.

It signs PSBTs for single-sig, multisig and miniscript policies on both native segwit and taproot, built on [libwally](https://github.com/ElementsProject/libwally-core/), the same core library used by Blockstream Jade.

> **Warning:** Kern is a research and development project, built for experimentation and testnet use. It has not been audited and secure boot is not enabled by default; builds are unvetted development snapshots. Any mainnet use is entirely at your own risk. The project makes no security guarantees.

## Hardware

Kern supports five Waveshare ESP32-P4 boards and one Elecrow CrowPanel board:

| Board | Display | Touch | Camera |
|-------|---------|-------|--------|
| [ESP32-P4-WiFi6-Touch-LCD-4B](https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-4b.htm) (`wave_4b`) | 720x720 MIPI DSI | GT911 | sold separately, OV5647 with autofocus recommended |
| [ESP32-P4-WiFi6-Touch-LCD-3.5](https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-3.5.htm) (`wave_35`) | 320x480 SPI | FT5x06 | OV5647, included |
| [ESP32-P4-WiFi6-Touch-LCD-5](https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-5.htm) (`wave_5`) | 720x1280 MIPI DSI | GT911 | OV5647, included |
| [ESP32-P4-WiFi6-Touch-LCD-4.3](https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-4.3.htm) (`wave_43`) | 480x800 MIPI DSI | GT911 | OV5647, included |
| [ESP32-P4-WiFi6-Touch-LCD-7B](https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-7b.htm) (`wave_7b`) | 1024x600 MIPI DSI | GT911 | OV5647, sold separately |
| [CrowPanel Advanced 10.1" ESP32-P4](https://github.com/Elecrow-RD/CrowPanel-Advanced-10.1inch-ESP32-P4-HMI-AI-Display-1024x600-IPS-Touch-Screen) and 7" siblings (`crowpanel`) | 1024x600 MIPI DSI | GT911 | SC2336, included |

ESP32-P4 does not contain radio (WiFi, BLE), but these boards have a radio in a secondary chip (ESP32-C6 mini). Exploring radio-less, simpler and cheaper ESP32-P4-only boards is part of the project's hardware research.

A MIPI CSI camera module is required for all boards. Kern ships drivers for the
OV5647 and SC2336 sensors and probes for whichever one is attached at boot, so
either sensor works on any board. The 4B is the one board sold without a camera:
pair it with an OV5647 module carrying a DW9714 voice coil motor, which is the
only combination that gets autofocus.

## Prerequisites

Kern targets [ESP-IDF v6.1](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32p4/get-started/index.html). Install it for the `esp32p4` target:

```bash
git clone --depth 1 --recurse-submodules --shallow-submodules -b v6.1 https://github.com/espressif/esp-idf.git ~/esp/esp-idf
~/esp/esp-idf/install.sh esp32p4
. ~/esp/esp-idf/export.sh
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

Build with [just](https://github.com/casey/just) (recommended) or `idf.py` directly. All `just` commands accept a board parameter, one of `wave_4b` (default), `wave_35`, `wave_5`, `wave_43`, `crowpanel`, or `wave_7b`:

```bash
just build              # Build for wave_4b (default)
just build wave_35      # Build for wave_35
just build wave_5       # Build for wave_5
just build wave_43      # Build for wave_43
just build crowpanel    # Build for CrowPanel 7" / 10.1"
just build wave_7b      # Build for wave_7b
just flash wave_5       # Flash for wave_5
just monitor            # Serial monitor
just clean              # Wipe all build_<board> dirs + sdkconfig
```

Or using `idf.py` directly:

```bash
# wave_4b
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_4b' build

# wave_35
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_35' build

# wave_5
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_5' build

# wave_43
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_43' build

# crowpanel (7" / 10.1")
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.crowpanel' build

# wave_7b
idf.py -D 'SDKCONFIG_DEFAULTS=sdkconfig.defaults;sdkconfig.defaults.wave_7b' build
```

> **Note:** `just` builds each board into its own `build_<board>/` directory, so switching boards needs no clean. The raw `idf.py` commands above share the default `build/` directory and `sdkconfig`: run `idf.py fullclean && rm sdkconfig` when switching boards that way.

> **Note:** The first build auto-generates `dev_signing_key.pem` (gitignored) and every build is signed with it. This is required to boot: the firmware refuses to run unsigned images. This key is a per-clone development key that carries no trust and never leaves your machine. Official releases are signed offline with the project's release key instead, so a self-built device only accepts SD-card updates built from the same clone; flash releases over USB.

### Desktop Simulator

The simulator renders the full LVGL UI in an SDL2 window, matching each board's resolution:

```bash
just sim                # Run simulator as wave_4b (720x720) with webcam (V4L2)
just sim wave_35        # Run simulator as wave_35 (320x480)
just sim wave_5         # Run simulator as wave_5 (720x1280)
just sim wave_43        # Run simulator as wave_43 (480x800)
just sim crowpanel      # Run simulator as crowpanel (1024x600)
just sim wave_7b        # Run simulator as wave_7b (1024x600)
just sim-build wave_35  # Build only
just sim-clean          # Remove simulator build artifacts
just sim-reset          # Wipe simulator data (factory reset)
just sim-qr IMG         # Run with a QR image
just sim-no-cam         # Run without camera
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

## Web Flasher

The easiest way to flash Kern is the browser-based flasher, which requires no local toolchain. It works in **Google Chrome** or **Microsoft Edge** (version 89+) via the Web Serial API.

**Live flasher:** https://odudex.github.io/Kern/flash/

The flasher offers two modes:
- **Latest CI Build**: fetches firmware built by the most recent `master` push directly from the site and flashes it to the selected board.
- **Custom ZIP Bundle**: accepts a `firmware-<board>.zip` artifact downloaded from the [Actions tab](../../actions) to flash any PR or older build.

> **Warning:** CI builds are unvetted development snapshots from a research project. Secure boot is not enabled. Flash them for experimentation and testnet use; any mainnet use is entirely at your own risk.

> **Note:** The project site and flasher are deployed automatically on every successful push to `master`, from `site/` in this repository. To enable it for your fork, go to **Settings → Pages** and set the source to **GitHub Actions**. To preview the site locally, run `just site` and open http://localhost:8000. Web Serial works on localhost, so you can flash a real board from the local copy.

## Flashing CI Build Artifacts

Every pull request and push to `master` produces a firmware artifact for each supported board via the **Test All Builds** workflow. These builds are useful for testing unreleased changes without setting up a local toolchain.

### Requirements

- Python 3
- USB cable connected to the board

### Steps

1. Open the **Actions** tab of the repository on GitHub and select the workflow run you want.

2. Scroll to the **Artifacts** section at the bottom of the run summary and download the zip for your board (e.g. `firmware-wave_4b`).

3. Unzip the package:

   ```bash
   unzip firmware-wave_4b.zip -d firmware-wave_4b
   cd firmware-wave_4b
   ```

   The zip contains, among other files:
   - `bootloader.bin`: bootloader
   - `partition-table.bin`: partition table
   - `ota_data_initial.bin`: OTA data partition
   - `kern.bin`: application firmware
   - `flasher_args.json` / `flash_args`: pre-computed flash offsets

4. Create a Python virtual environment and install esptool:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install esptool
   ```

5. Flash using the pre-computed offsets from `flash_args`:

   ```bash
   esptool --chip esp32p4 --baud 460800 write_flash $(cat flash_args)
   ```

## Flashing Pre-releases

Pre-release firmware is provided **for research and testing purposes only**. Any mainnet use is entirely at your own risk.

### Supported Devices

| Device | Board | Display |
|--------|-------|---------|
| `wave_4b` | Waveshare ESP32-P4-WiFi6-Touch-LCD-4B | 720x720 MIPI DSI |
| `wave_35` | Waveshare ESP32-P4-WiFi6-Touch-LCD-3.5 | 320x480 SPI |
| `wave_5` | Waveshare ESP32-P4-WiFi6-Touch-LCD-5 | 720x1280 MIPI DSI |
| `wave_43` | Waveshare ESP32-P4-WiFi6-Touch-LCD-4.3 | 480x800 MIPI DSI |
| `crowpanel` | CrowPanel Advanced 7" / 10.1" ESP32-P4 | 1024x600 MIPI DSI |
| `wave_7b` | Waveshare ESP32-P4-WiFi6-Touch-LCD-7B | 1024x600 MIPI DSI |

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
- `bootloader.bin`: bootloader
- `partition-table.bin`: partition table
- `firmware-signed.bin`: application firmware (signed; also the file for SD-card updates)
- `kern-v0.0.3.hex`: single-file image (all of the above, Intel HEX)

3. Create a Python virtual environment and install esptool:

```bash
python3 -m venv venv
source venv/bin/activate
pip install esptool
```

4. Flash the single-file image:

```bash
esptool --chip esp32p4 --baud 460800 write-flash 0x0 kern-v0.0.3.hex
```

> **Note:** The `.hex` image is sparse: it writes only the regions it contains, so the NVS partition (PIN, settings) and stored data survive reflashing. For a factory-clean install, erase everything first: `esptool --chip esp32p4 erase-flash`, then flash the image.

### Updating via SD card

A device already running signed firmware updates without any computer: copy `firmware-signed.bin` from the zip onto a SD card, insert it, and go to **Settings → Firmware Update**. The device verifies the signature before installing and keeps the previous firmware as an automatic fallback.

## Community

Development chat, testing reports and questions happen in the Telegram group: [t.me/kern_custody](https://t.me/kern_custody).

Bug reports and pull requests are welcome on [GitHub](https://github.com/odudex/Kern/issues).

## References

Kern is strongly inspired by [Krux](https://github.com/selfcustody/krux), sharing similar but simplified UI elements and flow.

[Blockstream Jade](https://github.com/Blockstream/Jade) was a strong inspiration for the decision to use C language for efficient use of the hardware. Additionally, Kern uses the same core library Jade does, [libwally](https://github.com/ElementsProject/libwally-core/), is shared with Jade.

The simplicity and UI polish of [SeedSigner](https://github.com/SeedSigner/seedsigner) and the security focus of the pioneering [Specter-DIY](https://github.com/cryptoadvance/specter-diy) were also strong inspirations.

## [Roadmap](ROADMAP.md)

## [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE)
