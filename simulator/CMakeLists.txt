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

# Board identity (passed from justfile, default wave_4b)
if(NOT DEFINED SIM_BOARD)
  set(SIM_BOARD "wave_4b")
endif()

# Board feature flags
if(SIM_BOARD STREQUAL "wave_35")
  set(BSP_HAS_PMIC TRUE)
endif()

find_package(SDL2 REQUIRED)
find_package(Threads REQUIRED)

# --- mbedTLS (required for crypto_utils.c, pin.c, kef.c, efuse_hmac_sim.c) ---
find_library(MBEDTLS_LIB    mbedtls)
find_library(MBEDCRYPTO_LIB mbedcrypto)
find_library(MBEDX509_LIB   mbedx509)
find_path(MBEDTLS_INCLUDE_DIR NAMES mbedtls/pkcs5.h mbedtls/private/pkcs5.h)
if(NOT MBEDTLS_LIB OR NOT MBEDCRYPTO_LIB)
  message(FATAL_ERROR
    "mbedTLS not found. Install with: sudo apt install libmbedtls-dev")
endif()
if(NOT MBEDTLS_INCLUDE_DIR AND MBEDTLS_LIB)
  get_filename_component(_mbedtls_lib_dir "${MBEDTLS_LIB}" DIRECTORY)
  get_filename_component(_mbedtls_prefix "${_mbedtls_lib_dir}" DIRECTORY)
  set(MBEDTLS_INCLUDE_DIR "${_mbedtls_prefix}/include")
endif()

set(MBEDTLS_COMPAT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../components/mbedtls_compat)
set(MBEDTLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
if(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/private/pkcs5.h"
   AND NOT EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/pkcs5.h")
  list(PREPEND MBEDTLS_INCLUDE_DIRS ${MBEDTLS_COMPAT_DIR})
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
include(FetchContent)
set(LVGL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../managed_components/lvgl__lvgl)
if(NOT EXISTS "${LVGL_DIR}/src/lvgl.h")
  FetchContent_Declare(
    lvgl_upstream
    GIT_REPOSITORY https://github.com/lvgl/lvgl.git
    GIT_TAG        v9.3.0
  )
  FetchContent_GetProperties(lvgl_upstream)
  if(NOT lvgl_upstream_POPULATED)
    FetchContent_Populate(lvgl_upstream)
  endif()
  set(LVGL_DIR ${lvgl_upstream_SOURCE_DIR})
endif()
file(GLOB_RECURSE LVGL_SOURCES ${LVGL_DIR}/src/*.c)

set(APP_UI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../main/ui)

# --- Simulator entry point and theme ---
set(SIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/esp_idf_stubs/stubs.c
    ${APP_UI_DIR}/theme.c
    ${APP_UI_DIR}/assets/kern_logo_lvgl.c
    ${APP_UI_DIR}/assets/kern_logo_font.c
    ${APP_UI_DIR}/assets/icons_16.c
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
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/ss_whitelist.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/core/registry.c
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
    ${APP_UI_DIR}/battery.c
    ${APP_UI_DIR}/key_info.c
    ${APP_UI_DIR}/sankey.c
    ${APP_UI_DIR}/settings_row.c
)

# --- PIN pages ---
set(PIN_PAGE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/pages/pin/pin_page.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../main/pages/pin/pin_settings.c
)

# --- Platform simulators (BSP, SD card, video/camera) ---
option(SIM_WEBCAM "Enable webcam capture" OFF)

set(PLATFORM_SIM_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/bsp_sim/bsp_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/bsp_sim/pmic_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/sd_card_sim/sd_card_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/video_sim/video_sim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/platform/video_sim/stb_image_impl.c
)

if(SIM_WEBCAM)
    # v4l2_capture uses real kernel V4L2 headers (not the ESP-IDF stubs),
    # so it is compiled as a separate library without the stubs include path.
    if(APPLE)
        enable_language(OBJCXX)
        add_library(v4l2_capture STATIC
            ${CMAKE_CURRENT_SOURCE_DIR}/platform/video_sim/v4l2_capture_macos.mm
        )
        find_library(AVFOUNDATION_FRAMEWORK AVFoundation)
        find_library(COREMEDIA_FRAMEWORK CoreMedia)
        find_library(COREVIDEO_FRAMEWORK CoreVideo)
        find_library(FOUNDATION_FRAMEWORK Foundation)
        target_link_libraries(v4l2_capture PRIVATE
            ${AVFOUNDATION_FRAMEWORK}
            ${COREMEDIA_FRAMEWORK}
            ${COREVIDEO_FRAMEWORK}
            ${FOUNDATION_FRAMEWORK}
        )
        set_source_files_properties(
            ${CMAKE_CURRENT_SOURCE_DIR}/platform/video_sim/v4l2_capture_macos.mm
            PROPERTIES COMPILE_FLAGS "-fobjc-arc"
        )
    else()
        add_library(v4l2_capture STATIC
            ${CMAKE_CURRENT_SOURCE_DIR}/platform/video_sim/v4l2_capture.c
        )
    endif()
    target_include_directories(v4l2_capture PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/video_sim/include
        ${CMAKE_CURRENT_SOURCE_DIR}/platform/video_sim
    )
    target_compile_options(v4l2_capture PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

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
    ${APP_PAGES_DIR}/settings/registered_descriptors.c
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

add_library(lvgl STATIC
    ${LVGL_SOURCES}
)
target_include_directories(lvgl PUBLIC
    ${LVGL_DIR}
    ${LVGL_DIR}/src
)
target_include_directories(lvgl PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(lvgl PRIVATE
    LV_CONF_INCLUDE_SIMPLE
    SIM_LCD_H_RES=${SIM_LCD_H_RES}
    SIM_LCD_V_RES=${SIM_LCD_V_RES}
    lv_refr_now=kern_lv_refr_now_real
)
target_link_libraries(lvgl PUBLIC
    SDL2
)

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
    ${MBEDTLS_INCLUDE_DIRS}
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
    $<$<BOOL:${SIM_WEBCAM}>:SIM_WEBCAM=1>
    $<$<BOOL:${BSP_HAS_PMIC}>:BSP_HAS_PMIC=1>
    $<$<STREQUAL:${SIM_BOARD},wave_4b>:CONFIG_KERN_BOARD_WAVE_4B=1>
    $<$<STREQUAL:${SIM_BOARD},wave_35>:CONFIG_KERN_BOARD_WAVE_35=1>
    $<$<STREQUAL:${SIM_BOARD},wave_5>:CONFIG_KERN_BOARD_WAVE_5=1>
)

target_compile_options(kern_simulator PRIVATE
    -Wall -Wextra
    -Wno-unused-parameter
    -Wno-unused-function
    -Wno-sign-compare
    -Wno-missing-field-initializers
    -Wno-type-limits
    -include mbedtls_compat.h
    # Hardening — the simulator parses untrusted input (image files, NVS
    # files, V4L2 frames). These flags are cheap and standard for any host
    # binary in that situation.
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fPIE
)
set_target_properties(kern_simulator PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(APPLE)
else()
    target_link_options(kern_simulator PRIVATE
        # Hardening linker flags
        -pie
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack
    )
endif()

target_link_libraries(kern_simulator PRIVATE
    lvgl
    SDL2
    Threads::Threads
    m
    wally
    ${MBEDTLS_LIB}
    ${MBEDCRYPTO_LIB}
    ${MBEDX509_LIB}
    $<$<BOOL:${SIM_WEBCAM}>:v4l2_capture>
)
