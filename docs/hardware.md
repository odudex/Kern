# Hardware Compatibility

Kern targets the ESP32-P4 SoC. This document lists validated hardware
configurations — boards, displays, and cameras — that are known to work.

> **Air-gap note:** For a production signing device, prefer boards that have
> no integrated Wi-Fi / Bluetooth radio.  The ESP32-P4 SoC itself contains no
> radio; it is only the surrounding module or companion chip that may add one.

---

## Validated Configurations

### Finished Devices (all-in-one)

| Device | Display | Camera | Radio | Status | Notes |
|--------|---------|--------|-------|--------|-------|
| [Waveshare ESP32-P4-WiFi6-Touch-LCD-4B](https://www.waveshare.com/esp32-p4-wifi6-touch-lcd-4b.htm) | 4" 720×720 ST7703 (MIPI-DSI) | OV5647 (MIPI-CSI) |  ESP32-C6 |  Working | Primary development board. Radio is on a separate ESP32-C6 chip — can be left unprogrammed. |

### DIY Kits (assemble your own)

| Board | Display | Camera | Radio | Status | Notes |
|-------|---------|--------|-------|--------|-------|
| [Waveshare ESP32-P4-Pico](https://www.waveshare.com/esp32-p4-pico.htm) | TBD | TBD |  None |  In progress | Compact, radio-free. Requires external display and camera via MIPI or SPI. Good starting point for a clean DIY build. |

> **Legend:** Working · In progress / untested ·  Not working ·  Has radio

---

## Interface Requirements

The ESP32-P4 exposes the following peripherals used by Kern:

| Peripheral | Interface | Used for |
|------------|-----------|----------|
| Display | MIPI-DSI (2-lane) | Main UI |
| Camera | MIPI-CSI (2-lane) | QR scanning |
| Touch | I2C (GT911) | Touch input |
| SD Card | SDMMC / SPI | Encrypted key storage |

When selecting components for a DIY build, confirm that your display and
camera modules are electrically compatible with the ESP32-P4's MIPI lanes
and that the connector pitch matches the board's FPC connectors.

---

## Adding a New Configuration

If you have tested a board + display + camera combination that is not listed
above, please open a Pull Request adding a row to the relevant table.  Include:

1. **Board** — full name and a link to the product page.
2. **Display** — controller, resolution, and interface type.
3. **Camera** — sensor model and interface type.
4. **Radio** — whether the board has integrated Wi-Fi / Bluetooth.
5. **Status** — working / partial / not working.
6. **Notes** — anything relevant (wiring, sdkconfig changes, caveats).

If you had to modify `sdkconfig.defaults` or the BSP to make a configuration
work, include those changes in the same PR so others can reproduce your setup.

---

## The Radio Problem

For a true air-gapped signing device, having an integrated Wi-Fi / Bluetooth
chip is undesirable even when disabled in software — it increases the attack
surface and undermines the physical security model.

The ESP32-P4 SoC itself has **no radio**.  Some boards add a companion chip
(e.g. ESP32-C6 on the Waveshare WiFi6 board).  Preferred options:

- **Radio-free boards** such as the Waveshare ESP32-P4-Pico (~$11).
- A custom or community group-buy board based on ESP32-P4 only.

If you know of a finished device (display + camera + ESP32-P4, no radio)
please open an issue or PR so it can be evaluated and added to the list.
