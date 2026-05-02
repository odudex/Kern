file(GLOB_RECURSE SOURCES "*.c")

# Select touch driver based on board
if(CONFIG_KERN_BOARD_WAVE_4B)
    set(TOUCH_DRIVER esp_lcd_touch_gt911)
elseif(CONFIG_KERN_BOARD_WAVE_35)
    set(TOUCH_DRIVER esp_lcd_touch_ft5x06)
elseif(CONFIG_KERN_BOARD_WAVE_5)
    set(TOUCH_DRIVER esp_lcd_touch_gt911)
elseif(CONFIG_KERN_BOARD_WAVE_43)
    set(TOUCH_DRIVER esp_lcd_touch_gt911)
endif()

idf_component_register(
    SRCS ${SOURCES}
    INCLUDE_DIRS .
    PRIV_REQUIRES lvgl ${TOUCH_DRIVER} k_quirc esp_timer wave_4b wave_35 wave_5 wave_43
                  libwally-core cUR sd_card bbqr spiffs nvs_flash efuse
                  esp_hw_support esp_app_format mbedtls_compat esp_driver_ppa
)

# Uncomment to enable Developer Tools menu (snapshot capture, decode testing)
# target_compile_definitions(${COMPONENT_LIB} PRIVATE DEV_TOOLS_ENABLED)
