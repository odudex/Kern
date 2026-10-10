# Threat model

## What this project does and where untrusted input enters

Kern is firmware for an air-gapped Bitcoin signing device (ESP32-P4, no radio). It is a research and development project whose goal is to raise the bar for reliability, security and user experience in self-custody signers, so security findings matter regardless of which network a device is used on. It holds a BIP39 mnemonic in RAM for the session, derives keys, and signs PSBTs for single-sig, multisig and miniscript policies (segwit v0 and taproot) with libwally-core. Data crosses the air gap only as QR codes read by the camera or as files on an SD card, so those two channels are the attack surface. Everything arriving over them is attacker-controlled, including inputs that look like they came from the user's own wallet software.

Untrusted inputs, in order of importance:

- **QR payloads** (`main/qr/`): raw bytes from the QR decoder (`components/k_quirc`) are assembled by `main/qr/parser.c` from UR (`components/cUR`: CBOR, fountain codes), BBQr (`components/bbqr` + `components/deflate_codec`), pMofN and plaintext parts, then handed to the consumers below.
- **PSBTs** (`main/core/psbt.c`, `psbt_parse.c`): parsed by libwally, then classified and verified against the loaded descriptor before signing. Outputs are shown to the user as change or spend; the fee and amounts come from the PSBT's UTXO data.
- **Output descriptors / miniscript** (`main/core/descriptor_validator.c`, `wallet.c`, `miniscript_policy.c`, `registry.c`, `script_templates.c`): parsed by libwally's descriptor parser, validated for the device's own key, stored, and later used to derive addresses and to decide which PSBT outputs are change.
- **Mnemonics and key material**: SeedQR, Compact SeedQR, mnemonic text (`main/qr/encoder.c` is the encoder; `main/pages/load_mnemonic/` the loaders); KEF-encrypted envelopes (`main/core/kef.c`), BIP138 encrypted backups (`main/core/bip138_*.c`, `components/bip138`); BIP322 message-signing requests (`main/core/bip322.c`, `message_sign.c`).
- **SD card files** (`components/sd_card`, `main/pages/shared/sd_file_browser.c`, `main/core/storage.c`): the same PSBT, descriptor and KEF payloads as files, plus firmware update images (`main/core/fw_update.c`), on a FAT filesystem that an attacker can write at will.
- **Internal flash** (SPIFFS `storage` partition, NVS): written by the device itself. Treat it as attacker-controlled too: the flash chip is external and the "evil maid" rewriting it is a threat we care about.
- **Camera frames**: the ISP output fed to the QR locator (`main/qr/scanner.c`, `components/video`). Lower priority than the decoded bytes, still in scope.

## Components that matter most / least

Most important, roughly in order:

1. `main/core/` (UI-free Bitcoin logic): `psbt*.c`, `descriptor_validator.c`, `wallet.c`, `key.c`, `miniscript_policy.c`, `registry.c`, `ss_whitelist.c`, `bip322.c`, `message_sign.c`, `kef.c`, `pin.c`, `pbkdf2.c`, `crypto_utils.c`, `entropy_pool.c`, `storage.c`, `nvs_secure.c`, `fw_update.c`, `bip138_*.c`.
2. `main/qr/` and the parsing components `components/cUR`, `components/bbqr`, `components/deflate_codec`, `components/bip138`, `components/k_quirc`.
3. `components/libwally-core`: vendored fork of libwally-core (upstream submodule plus Kern's wrapper). Bugs in the descriptor parser, PSBT code or secp256k1 wrappers that Kern's inputs can reach are in scope; please say so if a finding is an upstream bug.
4. `components/secure_memory`: secret allocation and heap-release wiping. Secrets must live only in internal SRAM and be wiped on unload, lock, power-off and reboot.
5. `main/pages/`: the UI flows. In scope where a flow can let the user confirm something other than what is signed, skip a confirmation, or leak key material to the display or storage.

Less important or out of scope:

- `components/wave_*`, `components/crowpanel`, `components/bsp_common`, `components/bus_timeout`, `components/video`: board support and camera pipeline. Out of scope unless an input-controlled bug lives there.
- `managed_components/` (Espressif registry packages fetched at build time), ESP-IDF itself, LVGL: third-party, out of scope. Report bugs there to their projects.
- `simulator/platform/`: host stubs standing in for ESP-IDF; not shipped. `simulator/src/` only wires the real code to SDL. Bugs that exist only under the stubs are out of scope.
- `site/` (static website and the web flasher), `tools/`, `scripts/`, `enclosures/`, `docs/`: not on the device.

## How to exercise it

Everything is prebuilt in the image, at `/src`. Interactive shells have ESP-IDF on PATH; otherwise run `. $IDF_PATH/export.sh` first.

- **Host tests** (`scripts/test.sh`): plain-C test programs built with the host compiler against the real sources. `main/core/test/` (PSBT parsing and classification, descriptor validation, KEF, PIN attempts, BIP32 paths, BIP322, BIP138, firmware-update pre-flight, storage), `main/qr/test/` (parsers, progress, frame pool, YUV), `components/bbqr/test`, `components/deflate_codec/test`, `components/secure_memory/test`, `components/bip138`, `components/k_quirc/test` (cmake/ctest). Each directory has a Makefile; `make -C <dir> run`. The `.c` files are the quickest way to drive a parser with crafted input: copy one, change the fixture, rebuild.
- **Simulator** (`simulator/build/kern_simulator`): the real core, QR and page code as a native debug binary. `SDL_VIDEODRIVER=dummy SDL_RENDER_DRIVER=software` runs it headless (no X server needed). `--qr-image <png>` or `--qr-dir <dir>` feeds QR images as if scanned; `--data-dir <dir>` selects the simulated NVS, SPIFFS and SD card (`<dir>/sdcard/kern/...`), so SD inputs are plain files. `ctest --test-dir simulator/build` runs the lifecycle regressions (sensitive-data cleanup, scan registry, storage smoke).
- **Firmware** (`build_wave_4b/`): the ESP32-P4 image, ELF and map, with `compile_commands.json` at the root. Cross-compiled only; there is no emulator for the P4 here. Use it to see what actually ships (compile flags, Kconfig in `build_wave_4b/sdkconfig`) and to check the layering rule: `main/core/` must never include UI headers.
- `docs/security-plan.md` is the security design and the status of each hardening phase. On master today: KEF encryption, split PIN with anti-phishing words, NVS encryption and signed SD-card updates are implemented; flash encryption, secure boot and release lockdown are not. `docs/design-guidelines.md` covers the UI.

## How you rate severity

- **Critical**: anything that discloses the mnemonic, a private key, the PIN or a KEF/BIP138 passphrase to an attacker-controlled output (QR, SD file, flash, display without the user asking), or lets a crafted PSBT, descriptor or QR produce a signature over something other than what the user confirmed: a changed recipient or amount, an output shown as change that the device does not control, an understated fee, a hidden output. Bypassing the firmware-update signature or downgrade checks on the SD path is critical too.
- **High**: attacker-controlled memory corruption (overflow, use-after-free, double free, uninitialized read of secret memory) reachable from a QR or SD input; descriptor validation accepting a policy that does not actually contain the device's key or that differs from what was displayed; PIN-attempt or backoff logic that can be bypassed in software; secrets left in memory, PSRAM or storage after unload, lock or reboot; weaknesses in KEF, PBKDF2 or the entropy pool that make brute force materially easier.
- **Medium**: crashes, hangs or reboots from malformed input (the device is air-gapped and reboots to a locked state, so denial of service is not critical); leaks of xpubs, descriptors or wallet structure that the design does not already accept; logic bugs that make the device reject valid inputs it should sign.
- **Low**: anything else, including UI inconsistencies without a security consequence.

Please include a proof of concept where possible: a PSBT, descriptor, QR payload (base64 or hex is fine, a PNG is nice) or SD file, and the host test or simulator invocation that triggers it. One report per root cause, not per call site.

## Anything to leave alone

- Physical attacks the design accepts and documents in `docs/security-plan.md`: fault injection / glitching, PIN-counter rewind by snapshotting and restoring the external flash, plaintext metadata on the SPIFFS partition (file names, KEF headers, unencrypted descriptor `.txt` files), and anything that needs serial or JTAG access while secure boot and flash encryption are not enabled. These are known.
- Serial flashing of arbitrary firmware. There is no secure boot on master yet, so it is the status quo, not a finding.
- The legacy `C-Krux` salt tags in `main/core/pin.c`. They are intentional for compatibility with existing PIN hashes.
- `scripts/`, `tools/` and the GitHub workflows run only on maintainers' machines and CI.
- Vendored third-party code reached only through code paths Kern does not use.
