file(GLOB_RECURSE SOURCES "*.c")
list(FILTER SOURCES EXCLUDE REGEX ".*/core/test/.*")

# Select touch driver based on board
if(CONFIG_KERN_BOARD_WAVE_4B)
    set(TOUCH_DRIVER esp_lcd_touch_gt911)
    set(FONT_POLICY_WIDTH 720)
    set(FONT_POLICY_HEIGHT 720)
elseif(CONFIG_KERN_BOARD_WAVE_35)
    set(TOUCH_DRIVER esp_lcd_touch_ft5x06)
    set(FONT_POLICY_WIDTH 320)
    set(FONT_POLICY_HEIGHT 480)
elseif(CONFIG_KERN_BOARD_WAVE_5)
    set(TOUCH_DRIVER esp_lcd_touch_gt911)
    set(FONT_POLICY_WIDTH 720)
    set(FONT_POLICY_HEIGHT 1280)
elseif(CONFIG_KERN_BOARD_WAVE_43)
    set(TOUCH_DRIVER esp_lcd_touch_gt911)
    set(FONT_POLICY_WIDTH 480)
    set(FONT_POLICY_HEIGHT 800)
elseif(CONFIG_KERN_BOARD_CROWPANEL_101)
    set(TOUCH_DRIVER esp_lcd_touch_gt911)
    set(FONT_POLICY_WIDTH 1024)
    set(FONT_POLICY_HEIGHT 600)
endif()

idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS .
    PRIV_REQUIRES lvgl ${TOUCH_DRIVER} k_quirc esp_timer wave_4b wave_35 wave_5 wave_43
                  crowpanel_101 libwally-core cUR sd_card bbqr video spiffs nvs_flash efuse
                  esp_hw_support esp_app_format mbedtls_compat esp_driver_ppa
)

if(DEFINED FONT_POLICY_WIDTH AND DEFINED FONT_POLICY_HEIGHT)
    find_program(PYTHON3_EXECUTABLE python3 REQUIRED)
    execute_process(
        COMMAND ${PYTHON3_EXECUTABLE}
                ${CMAKE_CURRENT_LIST_DIR}/../tools/ui_font_policy.py
                --width ${FONT_POLICY_WIDTH}
                --height ${FONT_POLICY_HEIGHT}
                --emit cmake-icon-defs
        OUTPUT_VARIABLE ICON_FONT_DEFINITIONS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY
    )
    if(ICON_FONT_DEFINITIONS)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE ${ICON_FONT_DEFINITIONS})
    endif()
endif()

# Uncomment to enable Developer Tools menu (snapshot capture, decode testing)
# target_compile_definitions(${COMPONENT_LIB} PRIVATE DEV_TOOLS_ENABLED)
