# Contributing to Kern

Thank you for your interest in contributing to Kern! This document outlines the guidelines for contributing to the project.

## Getting Started

1. Fork the repository and clone it locally.
2. Initialize submodules: `git submodule update --init --recursive`
3. Set up ESP-IDF v5.5.3 and source the environment: `source ~/esp/esp-idf/export.sh`
4. Build the project: `idf.py build` (or `just build`)

## Development Guidelines

### Architecture

Kern follows a strict layer separation:

- **`main/core/`** — Bitcoin logic. Must never depend on UI headers. Use callbacks for any user interaction.
- **`main/pages/`** — UI pages with create/show/hide/destroy lifecycle.
- **`main/ui/`** — Reusable LVGL UI primitives.
- **`main/qr/`** — QR scanning, parsing, and encoding.

Do not introduce UI dependencies into core modules. If a core function needs user confirmation, accept a callback parameter.

### Code Style

- Follow the existing style in the file you are modifying.
- Keep changes focused, one logical change per commit.
- Format your code before submitting:
  ```bash
  ./scripts/format.sh
  ```
  This runs `clang-format` (provided by ESP-IDF) on all `.c` and `.h` files in `main/` and first-party components.

### Static Analysis

The project uses two static analysis tools to catch bugs early. Both are available after sourcing ESP-IDF (`source ~/esp/esp-idf/export.sh`), except `cppcheck` which is installed separately.

Both tools cover `main/` and first-party components (`bbqr`, `cUR`, `k_quirc`, `sd_card`, `video`, `wave_4b`, `wave_35`, `wave_43`). `libwally-core` and `wave_5` are excluded (third-party upstream code: libwally-core is the original; wave_5 ships a vendored ST-style HX8394 driver).

**clang-tidy** (recommended — catches real bugs):
```bash
# Requires a build first (for compile_commands.json)
idf.py build

# Run on a single file
clang-tidy -p build/compile_commands.json main/core/wallet.c

# Run on all project source files (excluding libwally-core)
find main components/bbqr components/cUR components/k_quirc \
     components/sd_card components/video \
     components/wave_4b components/wave_35 components/wave_43 \
     -name '*.c' -not -path '*/build/*' 2>/dev/null | \
  xargs -P$(nproc) -I{} clang-tidy -p build/compile_commands.json {}
```

The project `.clang-tidy` config enables bug-finding and security checks tuned for embedded C. Warnings about unknown GCC flags (`-fno-tree-switch-conversion`, `-fstrict-volatile-bitfields`) are expected and harmless — they come from clang analyzing GCC-compiled code.

**cppcheck**:
```bash
# Install: sudo apt install cppcheck

# Run on project source directories
cppcheck main/ components/bbqr components/cUR components/k_quirc \
  components/sd_card components/video \
  components/wave_4b components/wave_35 components/wave_43 \
  --enable=warning,style,performance \
  --suppress=missingIncludeSystem \
  --suppress=missingInclude \
  -I main/ -I main/core -I main/ui -I main/pages -I main/qr -I main/utils \
  --std=c11
```

Note: `cppcheck` does not understand secure memory wipe patterns (zeroing variables before return) and will flag them as dead stores — these are intentional and should be ignored.

### Security

Kern is a Bitcoin signing firmware. Security is not optional.

- Never introduce network or radio functionality. The air-gap is by design.
- Use secure memory wipe (`WIPE` macros from `utils/`) for sensitive data.
- Use the existing `crypto_utils` wrappers around mbedtls rather than rolling custom crypto.
- Be mindful of stack usage on ESP32-P4, especially in deep call chains.

## Objectivity

We value focused, purposeful contributions. Every PR should clearly state **what problem it solves** — this helps reviewers understand your intent and keeps the project lean.

Whenever possible, link to a previously discussed **Issue** where the problem has been described and agreed upon. If no issue exists yet, consider opening one first to give the community a chance to weigh in. For small, self-evident fixes (typos, obvious bugs), describing the problem directly in the PR is perfectly fine.

## Submitting Changes

1. Create a branch from `master` with a descriptive name.
2. Make your changes in focused, well-described commits.
3. Ensure the project builds cleanly with `idf.py build`.
4. Open a Pull Request that:
   - References the related Issue (preferred), or clearly describes the problem being solved.
   - Explains **what** changed and **why**.
   - Notes any impact on security, memory usage, or the air-gap model.

## Reporting Issues

Open an Issue describing:

- **The problem** — what is wrong or missing, and why it matters.
- **Steps to reproduce** (for bugs).
- **Hardware and firmware version** (if relevant).

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
