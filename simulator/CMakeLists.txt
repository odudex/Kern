cmake_minimum_required(VERSION 3.16)
project(kern_simulator C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Configurable display resolution (default 720x720)
if(NOT DEFINED SIM_LCD_H_RES)
  set(SIM_LCD_H_RES 720)
endif()
if(NOT DEFINED SIM_LCD_V_RES)
  set(SIM_LCD_V_RES 720)
endif()

find_package(SDL2 REQUIRED)
find_package(Threads REQUIRED)

# --- mbedTLS (required for crypto_utils.c, pin.c, kef.c, efuse_hmac_sim.c) ---
find_library(MBEDTLS_LIB    mbedtls)
find_library(MBEDCRYPTO_LIB mbedcrypto)
find_library(MBEDX509_LIB   mbedx509)
if(NOT MBEDTLS_LIB OR NOT MBEDCRYPTO_LIB)
  message(FATAL_ERROR
    "mbedTLS not found. Install with: sudo apt install libmbedtls-dev")
endif()

# --- libwally-core (native desktop build) ---
set(WALLY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../components/libwally-core)

add_library(wally STATIC
    ${WALLY_DIR}/upstream/src/amalgamation/combined.c
)

target_include_directories(wally PUBLIC
    ${WALLY_DIR}/upstream/include
)

target_include_directories(wally PRIVATE
    ${WALLY_DIR}
    ${WALLY_DIR}/upstream
    ${WALLY_DIR}/upstream/src
    ${WALLY_DIR}/upstream/src/ccan
    ${WALLY_DIR}/upstream/src/secp256k1
    ${WALLY_DIR}/upstream/src/secp256k1/src
    ${WALLY_DIR}/upstream/src/secp256k1/include
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/ecdh
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/ecdsa_adaptor
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/ecdsa_s2c
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/extrakeys
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/generator
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/musig
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/rangeproof
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/recovery
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/schnorrsig
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/surjection
    ${WALLY_DIR}/upstream/src/secp256k1/src/modules/whitelist
)

target_compile_definitions(wally PRIVATE
    BUILD_ELEMENTS=0
    BUILD_MINIMAL=1
    ECMULT_WINDOW_SIZE=8
    ENABLE_MODULE_ECDH=1
    ENABLE_MODULE_ECDSA_S2C=1
    ENABLE_MODULE_EXTRAKEYS=1
    ENABLE_MODULE_GENERATOR=1
    ENABLE_MODULE_RANGEPROOF=1
    ENABLE_MODULE_RECOVERY=1
    ENABLE_MODULE_SCHNORRSIG=1
    ENABLE_MODULE_SURJECTIONPROOF=1
    ENABLE_MODULE_WHITELIST=1
    HAVE_BUILTIN_POPCOUNT=1
    NDEBUG=1
)

target_compile_options(wally PRIVATE
    -w  # suppress all warnings (third-party code)
    -fstack-protector-strong
)

target_link_libraries(wally PUBLIC
    ${MBEDCRYPTO_LIB}
)

# --- LVGL ---
set(LVGL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../managed_components/lvgl__lvgl)
file(GLOB_RECURSE LVGL_SOURCES ${LVGL_DIR}/src/*.c)

set(APP_UI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../main/ui)

# --- Simulator entry point and theme ---
set(SIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/esp_idf_stubs/stubs.c
    ${APP_UI_DIR}/theme.c
    ${APP_UI_DIR}/assets/kern_logo_lvgl.c
    ${APP_UI_DIR}/assets/kern_logo_font.c
    ${APP_UI_DIR}/assets/icons_24.c
    ${APP_UI_DIR}/assets/icons_36.c
)

# --- ESP-IDF stubs (NVS, FreeRTOS, eFuse, storage) ---
set(STUB_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/esp_idf_stubs/nvs_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/esp_idf_stubs/efuse_hmac_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/esp_idf_stubs/freertos_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/esp_idf_stubs/storage_stub.c
)

# --- Application utilities ---
set(APP_UTIL_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/utils/bip39_filter.c
)

# --- Core application modules ---
set(APP_CORE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/settings.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/pin.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/crypto_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/session.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/kef.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/error.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/wallet.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/base43.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/descriptor_validator.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/key.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/message_sign.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/psbt.c
    # miniz (used by kef.c for raw-deflate compression)
    ${CMAKE_CURRENT_SOURCE_DIR}/../components/bbqr/src/miniz.c
    # bbqr (multi-part QR encoding)
    ${CMAKE_CURRENT_SOURCE_DIR}/../components/bbqr/src/bbqr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../components/bbqr/src/base32.c
)

# --- UI components ---
set(APP_UI_SOURCES
    ${APP_UI_DIR}/dialog.c
    ${APP_UI_DIR}/input_helpers.c
    ${APP_UI_DIR}/keyboard.c
    ${APP_UI_DIR}/menu.c
    ${APP_UI_DIR}/nav.c
    ${APP_UI_DIR}/word_selector.c
    ${APP_UI_DIR}/key_info.c
    ${APP_UI_DIR}/sankey.c
)

# --- PIN pages ---
set(PIN_PAGE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/pages/pin/pin_page.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/pages/pin/pin_settings.c
)

# --- Platform simulators (BSP, SD card, video/camera) ---
set(PLATFORM_SIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/bsp_sim/bsp_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/sd_card_sim/sd_card_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/video_sim/video_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/video_sim/stb_image_impl.c
)

# --- Application pages ---
set(APP_PAGES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../main/pages)
set(APP_PAGE_SOURCES
    # Login flow
    ${APP_PAGES_DIR}/login/login.c
    ${APP_PAGES_DIR}/login/login_settings.c
    ${APP_PAGES_DIR}/login/about.c
    # Load mnemonic
    ${APP_PAGES_DIR}/load_mnemonic/load_menu.c
    ${APP_PAGES_DIR}/load_mnemonic/load_storage.c
    ${APP_PAGES_DIR}/load_mnemonic/manual_input.c
    # New mnemonic
    ${APP_PAGES_DIR}/new_mnemonic/new_mnemonic_menu.c
    ${APP_PAGES_DIR}/new_mnemonic/dice_rolls.c
    ${APP_PAGES_DIR}/new_mnemonic/entropy_from_camera.c
    # Home
    ${APP_PAGES_DIR}/home/home.c
    ${APP_PAGES_DIR}/home/addresses.c
    ${APP_PAGES_DIR}/home/public_key.c
    ${APP_PAGES_DIR}/home/backup/backup_menu.c
    ${APP_PAGES_DIR}/home/backup/mnemonic_qr.c
    ${APP_PAGES_DIR}/home/backup/mnemonic_words.c
    # Settings
    ${APP_PAGES_DIR}/settings/descriptor_manager.c
    ${APP_PAGES_DIR}/settings/wallet_settings.c
    # Shared pages
    ${APP_PAGES_DIR}/shared/address_checker.c
    ${APP_PAGES_DIR}/shared/descriptor_loader.c
    ${APP_PAGES_DIR}/shared/kef_decrypt_page.c
    ${APP_PAGES_DIR}/shared/kef_encrypt_page.c
    ${APP_PAGES_DIR}/shared/key_confirmation.c
    ${APP_PAGES_DIR}/shared/mnemonic_editor.c
    ${APP_PAGES_DIR}/shared/storage_browser.c
    ${APP_PAGES_DIR}/shared/wipe_flash_dialog.c
    # Top-level pages
    ${APP_PAGES_DIR}/capture_entropy.c
    ${APP_PAGES_DIR}/load_descriptor_storage.c
    ${APP_PAGES_DIR}/passphrase.c
    ${APP_PAGES_DIR}/screensaver.c
    ${APP_PAGES_DIR}/store_descriptor.c
    ${APP_PAGES_DIR}/store_mnemonic.c
    # Scan page
    ${APP_PAGES_DIR}/scan/scan.c
    # Dev tools
    ${APP_PAGES_DIR}/dev_tools/dev_menu.c
    ${APP_PAGES_DIR}/dev_tools/snapshot.c
    ${APP_PAGES_DIR}/dev_tools/decode_snapshots.c
)

# --- QR + k_quirc + cUR ---
set(QR_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/qr/encoder.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/qr/parser.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/qr/viewer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/qr/scanner.c
)

file(GLOB KQUIRC_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../components/k_quirc/src/*.c)
file(GLOB_RECURSE CUR_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../components/cUR/src/*.c)

add_executable(kern_simulator
    ${SIM_SOURCES}
    ${STUB_SOURCES}
    ${APP_UTIL_SOURCES}
    ${APP_CORE_SOURCES}
    ${APP_UI_SOURCES}
    ${PIN_PAGE_SOURCES}
    ${APP_PAGE_SOURCES}
    ${QR_SOURCES}
    ${PLATFORM_SIM_SOURCES}
    ${KQUIRC_SOURCES}
    ${CUR_SOURCES}
    ${LVGL_SOURCES}
)

# Include paths — order matters: simulator headers shadow ESP-IDF
target_include_directories(kern_simulator PRIVATE
    # Simulator stubs (highest priority — shadow ESP-IDF headers)
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/esp_idf_stubs/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/bsp_sim/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/video_sim/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/sd_card_sim/include
    ${CMAKE_CURRENT_SOURCE_DIR}/platform               # sdkconfig.h
    ${CMAKE_CURRENT_SOURCE_DIR}                         # lv_conf.h
    # Application source tree
    ${CMAKE_CURRENT_SOURCE_DIR}/../main                 # ui/theme.h, core/, utils/, pages/
    # Component headers (for kef.c -> bbqr/miniz, cUR, k_quirc, video)
    ${CMAKE_CURRENT_SOURCE_DIR}/../components
    ${CMAKE_CURRENT_SOURCE_DIR}/../components/bbqr/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../components/k_quirc/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../components/k_quirc/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../components/cUR/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../components/video
    # LVGL
    ${LVGL_DIR}
    ${LVGL_DIR}/src
)

target_compile_definitions(kern_simulator PRIVATE
    SIMULATOR=1
    LV_CONF_INCLUDE_SIMPLE
    SIM_LCD_H_RES=${SIM_LCD_H_RES}
    SIM_LCD_V_RES=${SIM_LCD_V_RES}
    K_QUIRC_ADAPTIVE_THRESHOLD
    K_QUIRC_BILINEAR_THRESHOLD
)

target_compile_options(kern_simulator PRIVATE
    -Wall -Wextra
    -Wno-unused-parameter
    -Wno-unused-function
    -Wno-sign-compare
    -Wno-missing-field-initializers
    -Wno-type-limits
)

# keyboard.c uses snprintf without including stdio.h (GCC 14 makes this an error)
set_source_files_properties(${APP_UI_DIR}/keyboard.c PROPERTIES COMPILE_OPTIONS "-Wno-implicit-function-declaration")

target_link_libraries(kern_simulator PRIVATE
    SDL2
    Threads::Threads
    m
    wally
    ${MBEDTLS_LIB}
    ${MBEDCRYPTO_LIB}
    ${MBEDX509_LIB}
)
