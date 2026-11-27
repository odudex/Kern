# Shared BSP headers, shared board bringup helpers, and default PMIC implementations.
# Each board's BSP REQUIRES this component and only ships board-specific panel/pin config.

include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/boards.cmake)
kern_board_detect_from_kconfig()

set(srcs "bsp_common.c" "display_security.c")

# Boards without a dedicated PMIC chip read the battery over an ADC divider,
# or get the no-op stub if they cannot read it at all.
if(KERN_BOARD_PMIC STREQUAL "adc")
    list(APPEND srcs "pmic_adc.c")
elseif(NOT KERN_BOARD_PMIC STREQUAL "custom")
    list(APPEND srcs "pmic_stub.c")
endif()

if(KERN_BOARD_TOUCH STREQUAL "esp_lcd_touch_gt911")
    list(APPEND srcs "bsp_touch_gt911.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES driver esp_adc esp_driver_ledc esp_hw_support esp_lcd esp_lvgl_adapter secure_memory
    PRIV_REQUIRES esp_lcd_touch_gt911
)
