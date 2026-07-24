if(CONFIG_KERN_BOARD_TDISPLAY_P4)
    idf_component_register(
        SRCS "tdisplay_p4.c" "xl9535.c" "gt9895_touch.c" "pmic.c"
        INCLUDE_DIRS "include"
        REQUIRES driver esp_lcd bsp_common esp_lcd_touch
    )
else()
    idf_component_register(
        REQUIRES driver esp_lcd bsp_common esp_lcd_touch
    )
endif()
