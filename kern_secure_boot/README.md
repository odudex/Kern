# Kern Secure Boot Public Keys

This folder holds the **public** key material for Kern's Secure Boot v2 (**RSA-3072 / RSA-PSS**). These files are safe to distribute — they contain no private key material.

The firmware build reads the three digest files from this folder and embeds them, so they are what the on-device Secure Boot menu checks against and burns. Verify `SHA256SUMS.sig` against the developer's published GPG key before trusting anything here (see [Verifying These Files](#verifying-these-files)).

## Why RSA-3072 (not ECDSA)

ECDSA-based Secure Boot v2 is **not functional on ESP32-P4 silicon** (chip errata — enabling it would require `CONFIG_SECURE_BOOT_INSECURE`). Kern therefore signs with RSA-3072, which on ESP32-P4 is also the faster verifier. See [docs/secure-boot.md §2](../docs/secure-boot.md#2-algorithm-choice).

## Three keys, two rotations

Kern burns **three** signing-key digests into eFuse (KEY0/KEY1/KEY2), so a compromised or lost key can be rotated out up to twice. Released firmware is signed with the primary key only. Keys 1 and 2 stay in cold storage.

## The frozen bootloader

A device with secure boot enabled keeps its second-stage bootloader: SD updates never write it, and the chip accepts a replacement only if a non-revoked key signed it. To survive any future rotation the bootloader must carry signatures from all three keys. It is therefore built and signed with all three once, in a key ceremony, and committed here; every release ships those same bytes instead of a freshly built bootloader. A new one is produced only when the bootloader itself has to change, through the same ceremony.

The bootloader does not depend on the display or camera, so boards share it. There is one per chip revision range and flash mode, listed in `bootloaders/BOOTLOADERS` with the git tag and ESP-IDF version it was built from and the SHA-256 of its unsigned image. Building that tag reproduces the image byte for byte up to the signature sector.

**Freeze 1** is published here, built from the tag `bootloader-1` with ESP-IDF v6.1.1:

| Variant | Chip revision | Flash mode | Boards |
|---------|---------------|------------|--------|
| `v1-qio` | v0.x / v1.x | QIO | wave_4b, wave_5, wave_43, wave_7b, crowpanel, p4_pico |
| `v1-dio` | v0.x / v1.x | DIO | wave_35 |
| `v3-qio` | v3.x | QIO | the `_v3` builds of the `v1-qio` boards |
| `v3-dio` | v3.x | DIO | wave_35_v3 |

A release can enable secure boot when its zip carries one of these as `bootloader.bin`. Releases up to v0.0.21 ship a plain bootloader and cannot. Procedure: [docs/secure-boot.md §4a](../docs/secure-boot.md#4a-the-frozen-bootloader).

## Contents

| File | Description |
|------|-------------|
| `kern-sb-key0-pub.pem` | Public key 0 (primary signing key) |
| `kern-sb-key1-pub.pem` | Public key 1 (rotation #1) |
| `kern-sb-key2-pub.pem` | Public key 2 (rotation #2) |
| `kern-sb-digest0.bin` | SHA-256 digest of public key 0 (32 bytes, burned into eFuse KEY0) |
| `kern-sb-digest1.bin` | SHA-256 digest of public key 1 (32 bytes, burned into eFuse KEY1) |
| `kern-sb-digest2.bin` | SHA-256 digest of public key 2 (32 bytes, burned into eFuse KEY2) |
| `bootloaders/BOOTLOADERS` | Manifest of the frozen bootloaders |
| `bootloaders/<variant>/bootloader-signed.bin` | Frozen bootloader, signed by all three keys |
| `SHA256SUMS` | SHA-256 checksums of all files above |
| `SHA256SUMS.sig` | GPG detached signature of `SHA256SUMS` |

## Expected Digest Values

These are the hex representations of the digest files. When activating secure boot on-device via **Settings > Security > Secure Boot**, the device displays these values for visual verification.

```
Digest 0: 2c812b5806eb81730e29364b874ded9b14de275d6bbfa66a4dc5e60146dfe264
Digest 1: 808a94e9537be0b506ecf7fb02c3c82cab3c21922af7d5212088c035940a78b9
Digest 2: 71b3a7ba22a4fb8289ee1286bae66a0b1674c3bb679a800118309514138de609
```

Compare the digests shown on screen against the values above (and against those published in the release notes) before confirming the lockdown.

## Verifying These Files

Before trusting these keys, verify the GPG signature and checksums:

```bash
# 1. Verify the GPG signature on SHA256SUMS
gpg --verify SHA256SUMS.sig SHA256SUMS

# 2. Verify all file checksums match
sha256sum -c SHA256SUMS
```

You can also compute the hex representation of the `.bin` digest files to compare against the expected values above:

```bash
for n in 0 1 2; do xxd -p kern-sb-digest${n}.bin | tr -d '\n' && echo; done
```

Each frozen bootloader can be checked against the three public keys (`espsecure` comes with `esptool`):

```bash
for n in 0 1 2; do
    espsecure verify-signature --version 2 \
        --keyfile kern-sb-key${n}-pub.pem bootloaders/v1-qio/bootloader-signed.bin
done
```

From the repository root, one command checks every variant against the three keys and against the unsigned hash in the manifest:

```bash
bash scripts/freeze_bootloader.sh --verify kern_secure_boot/bootloaders kern_secure_boot
```

## On-Device Secure Boot Activation

The device must have been installed **over USB** from a release that ships the frozen bootloader. A device installed from an older release and updated over SD since then still has its old bootloader; one USB install of a current release zip replaces it and keeps the device's data.

**Settings → Security → Secure Boot** then:

1. Shows the three key digests embedded in the firmware.
2. Checks, before offering anything, that the chip revision is one that can still be flashed over USB once locked (below v3.1 for now), that the PIN keys are sealed, that the running app is signed by one of the three keys, and that the bootloader on flash is signed by **all three**. These are signature verifications against the embedded keys. If one fails, the page names it and offers no way to proceed.
3. Warns that the action is **irreversible** and asks for the PIN.
4. Burns the three digests into eFuse KEY0/KEY1/KEY2, reads them back, then burns the hardening eFuses (direct-boot disable, JTAG disable, secure download mode), `SECURE_BOOT_EN`, and the `RD_DIS` write-protect.

**Before confirming**, compare the digests on screen with the values in this README and in the release notes. The device checks the images against the keys its firmware embeds; this comparison is what tells you that firmware embeds the authentic ones.

After lockdown, only firmware signed with one of the corresponding private keys will boot on the device.

## Your Own Keys

To lock a device to keys you control, replace the three `kern-sb-digestN.bin` files with the digests of your own public keys, build, and sign the app and the bootloader yourself (the bootloader with all three of your keys). The menu then checks and burns your digests. The frozen bootloaders here are signed by the developer keys and will be refused by such a build. Steps: [docs/secure-boot.md §5b](../docs/secure-boot.md#5b-user-builds-from-source-self-sovereign).

## More Information

See [docs/secure-boot.md](../docs/secure-boot.md) for the full secure boot guide, including the frozen bootloader, key rotation, anti-rollback, and manual lockdown via `espefuse`.
