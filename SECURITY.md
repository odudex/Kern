# Security Policy

Kern is a research and development project. It has not been audited and makes no security guarantees (see the warning in the [README](README.md)). Security reports are welcome all the same: finding these problems and fixing them is part of what the project is for.

## Supported Versions

Fixes land on `master` and ship in the next [release](https://github.com/odudex/Kern/releases). Older releases are not patched. Please reproduce a finding on the latest release or on `master` before reporting it.

## Reporting a Vulnerability

Please do not open a public issue or post in the Telegram group. Report privately through **Security → Report a vulnerability** on this repository, or by email to odudex@proton.me, optionally encrypted to the key below.

A useful report says which firmware version or commit and which board, what an attacker gains, and how to reproduce it: a PSBT, descriptor, QR payload or SD card file. The host tests (`just test`) and the desktop simulator run most of the code without hardware.

Expect an acknowledgement within a week. A fix is prepared privately, released, and then disclosed, with credit to the reporter unless they prefer otherwise.

## Scope

In scope:

- Anything that lets an input to the device (a QR code, a PSBT, a descriptor, an SD card file, a firmware update image, the contents of the external flash) disclose a mnemonic, private key, PIN or passphrase, produce a signature over something other than what the user confirmed, corrupt memory, or bypass the PIN.
- Secrets that outlive the session in RAM or reach storage unencrypted.
- The path from source to device: the CI workflows, release signing, the frozen bootloaders and the web flasher.

Out of scope:

- The physical attacks the design accepts, listed under [Accepted Residual Risks](docs/security-plan.md#accepted-residual-risks): fault injection, PIN-counter rewind by restoring the external flash, and the plaintext metadata on flash and in PSRAM.

The security design and the status of each hardening phase are in [docs/security-plan.md](docs/security-plan.md).

## Release Signing Key

Releases and `kern_secure_boot/SHA256SUMS` are signed with the GPG key published at https://github.com/odudex.gpg:

```
CD48 298A 386C E34F 3A9F  EE3E B9AA 47C3 E81D D14C
```

The README explains how to [verify a release](README.md#verifying-a-release).
