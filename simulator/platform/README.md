# Simulator Platform Layer

Hardware abstraction layer that replaces ESP32-P4 APIs with
desktop-compatible implementations. This allows the full Kern
firmware UI and logic to run on Linux using SDL2 for display,
POSIX threads for FreeRTOS primitives, and the local filesystem
for storage.

## Architecture

```
┌──────────────────────────────────────────────┐
│          Kern Application Code               │
├──────────────┬────────────┬──────────────────┤
│  bsp_sim     │ esp_idf    │  sd_card_sim     │
│  (display,   │ _stubs     │  (filesystem)    │
│   input)     │ (RTOS,     │                  │
│              │  NVS,      ├──────────────────┤
│              │  crypto,   │  video_sim       │
│              │  system)   │  (camera/QR)     │
├──────────────┴────────────┴──────────────────┤
│  SDL2 / POSIX / mbedTLS / stb_image          │
└──────────────────────────────────────────────┘
```

All modules use standard Linux APIs (pthread, stdio, dirent,
stat) with two external dependencies: **mbedTLS** (HMAC-SHA256)
and **stb_image** (PNG/JPEG decoding, header-only).

## Modules

### sdkconfig.h

Provides ESP-IDF Kconfig defines that application code expects
from menuconfig.

| Define                               | Value | Purpose                    |
|--------------------------------------|-------|----------------------------|
| `CONFIG_BSP_LCD_COLOR_FORMAT_RGB565` | 1     | Display uses 16-bit RGB565 |
| `CONFIG_FREERTOS_HZ`                 | 1000  | Tick rate (1 tick = 1 ms)  |
| `CONFIG_CACHE_L2_CACHE_LINE_SIZE`    | 64    | PPA buffer alignment       |
| `CONFIG_BSP_I2C_NUM`                 | 0     | I2C controller index       |

---

### bsp_sim/ - Board Support Package

Implements the BSP display and input APIs using LVGL's SDL2
backend.

**Display (720x720 default):**
- `bsp_display_start()` - Creates an SDL2 window via
  `lv_sdl_window_create()` and registers an `lv_sdl_mouse`
  input device
- Brightness/backlight functions are no-ops

**LVGL Port:**
- `lvgl_port_lock(timeout_ms)` - Thread-safe LVGL access
  via `pthread_mutex_timedlock()`
- `lvgl_port_unlock()` - Releases the LVGL mutex
- `lvgl_port_init()` / `lvgl_port_deinit()` - Lifecycle
  stubs

**Stubs (no-ops):**
- I2C init/deinit/get_handle
- GPIO configuration

**GPIO Mapping (matches real hardware):**
- I2C: SCL=GPIO8, SDA=GPIO7
- LCD: Backlight=GPIO26, Reset=GPIO27
- Touch: Reset=GPIO23

---

### esp_idf_stubs/ - ESP-IDF API Simulation

The largest module, providing Linux-compatible replacements
for core ESP32 APIs.

#### stubs.c - System APIs

| Function                       | Simulation                        |
|--------------------------------|-----------------------------------|
| `esp_random()`                 | Reads `/dev/urandom`              |
|                                | (fallback: `rand()`)              |
| `esp_fill_random(buf, len)`    | Fills buffer from `/dev/urandom`  |
| `esp_restart()`                | Calls `exit(1)`                   |
| `esp_chip_info()`              | Hardcoded ESP32P4, 2 cores, rev 0 |
| `esp_get_free_heap_size()`     | Returns 4 MB (fixed)              |
| `esp_timer_get_time()`         | `CLOCK_MONOTONIC` in usec         |
| `esp_timer_create/start/`      | Allocates timer struct;           |
| `stop/delete()`                | callbacks never fire              |
| `esp_vfs_spiffs_register()`    | Creates dir at `conf->base_path`  |
| `esp_app_get_description()`    | Version "sim-dev",                |
|                                | project "kern_simulator"          |
| `ppa_do_scale_rotate_mirror()` | Simple `memcpy()` (no transform)  |

#### freertos_sim.c - FreeRTOS on POSIX

Maps the FreeRTOS kernel to pthreads, condition variables,
and mutexes.

**Tasks:**
- `xTaskCreate()` / `xTaskCreatePinnedToCore()` - Spawns
  a pthread (ignores priority, stack size, core affinity)
- `vTaskDelete()` - `pthread_cancel()` + `pthread_join()`
- `vTaskDelay(ticks)` - `usleep(ticks * 1000)`
- `xTaskGetTickCount()` - Milliseconds since boot via
  `CLOCK_MONOTONIC`

**Semaphores** (`sem_impl_t`):
- Binary: starts at 0, `xSemaphoreGive()` sets to 1
- Mutex: starts at 1, used as counting semaphore
- Blocking via `pthread_cond_timedwait()`

**Queues** (`queue_impl_t`):
- Circular buffer with `not_empty` / `not_full` condition
  variables
- `xQueueSend()` appends to tail
- `xQueueReceive()` reads from head

**Event Groups** (`eg_impl_t`):
- Bit field with `pthread_cond_broadcast()` on set
- `xEventGroupWaitBits()` supports `waitForAll` and
  `clearOnExit`

#### nvs_sim.c - Non-Volatile Storage

File-backed key-value store. Each NVS namespace is persisted
as a binary file under `sim_data/nvs/<namespace>.nvs`.

**Binary format:**
```
[key_len:1B][key:NB][type:1B]
[value_len_lo:1B][value_len_hi:1B][value:NB]...
```

Types: `0x01` = u8, `0x02` = u16, `0x03` = blob.

**API:** `nvs_open()`, `nvs_close()`, `nvs_commit()`,
`nvs_set_*()`, `nvs_get_*()`, `nvs_erase_key()`,
`nvs_erase_all()`.

**Limits:** 16 concurrent handles, 15-char max key length.

**Control:** `sim_nvs_set_data_dir(path)` overrides the
default `sim_data/nvs` directory.

#### efuse_hmac_sim.c - eFuse & HMAC

Simulates hardware eFuse key storage and HMAC computation.

- KEY5 starts provisioned with purpose `HMAC_UP`
- HMAC computed via mbedTLS `mbedtls_md_hmac()` (SHA-256)
- Uses a **deterministic test key**: 32 bytes of `0x42`
- `esp_efuse_write_key()` / `esp_efuse_set_key_dis_read()`
  / `set_key_dis_write()` are stubs

#### bip39_filter_stub.c

Placeholder stubs for BIP39 word filtering:
- `bip39_filter_init()` returns true
- `bip39_filter_get_valid_letters()` returns `0x03FFFFFF`
  (all 26 letters valid)
- Word matching functions return 0 / empty

#### storage_stub.c

Placeholder for secure storage APIs. All operations return
`ESP_ERR_NOT_SUPPORTED` except `storage_init()` and
`storage_wipe_flash()`.

---

### sd_card_sim/ - SD Card Simulator

Maps the SD card API to POSIX filesystem operations under
`sim_data/sdcard/`.

**Auto-created on init:**
```
sim_data/sdcard/kern/mnemonics/
sim_data/sdcard/kern/descriptors/
```

| Function                   | Implementation                    |
|----------------------------|-----------------------------------|
| `sd_card_init()`           | `mkdir -p` dir tree, sets mounted |
| `sd_card_deinit()`         | Clears mounted flag               |
| `sd_card_is_mounted()`     | Returns mount status              |
| `sd_card_write_file()`     | `fopen()` + `fwrite()` binary     |
| `sd_card_read_file()`      | Reads file into `malloc`'d buf    |
| `sd_card_file_exists()`    | `access(path, F_OK)`              |
| `sd_card_delete_file()`    | `remove()`                        |
| `sd_card_list_files()`     | `opendir()` + `readdir()`         |
| `sd_card_free_file_list()` | Frees allocated filename array    |

**Control:** `sim_sdcard_set_data_dir(dir)` overrides the
root directory. Paths starting with `SD_CARD_MOUNT_POINT`
are rewritten to use the override.

---

### video_sim/ - Camera / QR Simulator

Simulates the hardware camera by loading QR code images from
disk and delivering RGB565 frames via a callback at ~30 fps.

**Image loading:**
- Uses `stb_image.h` (header-only) to decode PNG/JPEG
- Converts RGB888 to RGB565:
  `(R>>3<<11) | (G>>2<<5) | (B>>3)`
- Falls back to a blank 800x640 frame if no image is
  configured

**Frame delivery:**
- Background pthread delivers frames every ~33 ms
- Calls `s_frame_cb(buffer, 0, width, height, frame_size)`
- Supports up to 4 user-provided frame buffers

**Application API** (matches real camera driver):
- `app_video_open()` - Loads QR image, returns fake fd=42
- `app_video_stream_task_start()` - Starts delivery thread
- `app_video_stream_task_stop()` - Joins thread
- `app_video_register_frame_operation_cb()` - Registers
  frame callback
- `app_video_get_resolution()` /
  `app_video_get_buf_size()` - Frame metadata
- Focus/AE/AF functions are no-ops
- `app_video_has_focus_motor()` returns false

**Simulator control:**
- `sim_video_set_qr_image(path)` - Load a single static
  QR image
- `sim_video_set_qr_dir(dir)` - Cycle through all images
  in a directory

**Files:**
- `video_sim.c` - Main implementation
- `stb_image.h` - Third-party header-only image decoder
- `stb_image_impl.c` - Compilation unit that includes
  `stb_image.h` with `STB_IMAGE_IMPLEMENTATION`
