# IDF also runs this file in script mode, which rejects CONFIGURE_DEPENDS.
if(CMAKE_SCRIPT_MODE_FILE)
  file(GLOB_RECURSE SOURCES "*.c")
else()
  file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "*.c")
endif()
list(FILTER SOURCES EXCLUDE REGEX ".*/core/test/.*")
list(FILTER SOURCES EXCLUDE REGEX ".*/qr/test/.*")

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/boards.cmake)
kern_board_detect_from_kconfig()

idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS .
    PRIV_REQUIRES lvgl ${KERN_BOARD_TOUCH} k_quirc esp_timer ${KERN_BOARD_REQUIRES}
                  libwally-core cUR sd_card bbqr deflate_codec video spiffs
                  nvs_flash efuse esp_hw_support esp_app_format mbedtls bip138
                  esp_driver_ppa app_update bootloader_support secure_memory bsp_common
                  bus_timeout spi_flash
)

# Ignoring a warn_unused_result return is a build error, not a warning. The
# k_quirc and cUR entry points carry the attribute and report failure that way
# and nothing else.
target_compile_options(${COMPONENT_LIB} PRIVATE -Werror=unused-result
                                              -Werror=vla)

include(${CMAKE_CURRENT_LIST_DIR}/core/sb_digests.cmake)
kern_generate_sb_digests(${CMAKE_CURRENT_BINARY_DIR}/generated)
target_include_directories(${COMPONENT_LIB} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)

if(DEFINED KERN_BOARD_WIDTH AND DEFINED KERN_BOARD_HEIGHT)
    find_program(PYTHON3_EXECUTABLE python3 REQUIRED)
    execute_process(
        COMMAND ${PYTHON3_EXECUTABLE}
                ${CMAKE_CURRENT_LIST_DIR}/../tools/ui_font_policy.py
                --width ${KERN_BOARD_WIDTH}
                --height ${KERN_BOARD_HEIGHT}
                --emit cmake-icon-defs
        OUTPUT_VARIABLE ICON_FONT_DEFINITIONS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY
    )
    if(ICON_FONT_DEFINITIONS)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE ${ICON_FONT_DEFINITIONS})
    endif()
endif()
