# KERN

Kern is an experimental project that explores the capabilities of the ESP32-P4 as a platform to perform air-gapped Bitcoin signatures and cryptography.

## Hardware

Early development uses the [Waveshare ESP32-P4-WiFi6-Touch-LCD-4B](https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-4b.htm).

ESP32-P4 does not contain radio (WiFi, BLE), but this board has a radio in a secondary chip (ESP32-C6 mini). Later the project will migrate to use radio-less, simpler and cheaper boards with ESP32-P4 only.

An OV5647 camera module is also required.

## Prerequisites

- [esp-idf v5.5.1](https://docs.espressif.com/projects/esp-idf/en/v5.5.1/esp32p4/get-started/index.html)

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
```

### Build Options

#### Enable/disable Auto-focus

To enable camera auto-focus, enable camera focus motor on menuconfig:

```
CONFIG_CAM_MOTOR_DW9714=y
CONFIG_CAMERA_OV5647_ENABLE_MOTOR_BY_GPIO0=y
```

# References
Kern is strongly inspired by [Krux](https://github.com/selfcustody/krux), sharing similar but simplified UI elements and flow.

[Blockstream Jade](https://github.com/Blockstream/Jade) was a strong inspiration for the decision to use C language for efficient use of the hardware. Additionally, Kern's core library, [libwally](https://github.com/ElementsProject/libwally-core/), is shared with Jade.

The simplicity and UI polish of [SeedSigner](https://github.com/SeedSigner/seedsigner) and the security focus of the pioneering [Specter-DIY](https://github.com/cryptoadvance/specter-diy) were also strong inspirations.

## Roadmap

- ✅ Basic UI
- ✅ Camera video pipeline
- ✅ Static QR codes
  - ✅ Scan
  - ✅ Display
- Animated QR Codes
  - Scan, parse and export
    - ✅ UR
    - ✅ pMofN
    - ✅ BBQr
- New Mnemonic
  - ✅ From dice rolls
  - ✅ From words
  - ❌ From camera
- Load Mnemonic
  - ✅ From manual input (typing words)
  - From QR codes
    - ✅ Plain
    - ✅ SeedQR
    - ✅ Compact SeedQR
  - ❌ Encrypted
- Back up
  - ✅ Words
  - ❌ QR codes
  - ❌ Encrypted
- ✅ Passphrases
- Networks
  - ✅ Mainnet
  - ✅ Testnet
- Policy types
  - ✅ Single-sig
  - ❌ Multisig
  - ❌ Miniscript
- Descriptors
  - ❌ Loading
  - ❌ Exporting, saving
  - ❌ Encrypting/Decrypting
- Script type
  - ✅ Native Segwit
  - ❌ Nested Segwit
  - ❌ Taproot

- ❌ OTP based secure boot

- ❌ KEF encryption

## License

[MIT](LICENSE)
