if(CONFIG_KERN_BOARD_P4_PICO)
    idf_component_register(
        SRCS "p4_pico.c"
        INCLUDE_DIRS "include"
        REQUIRES driver esp_lcd bsp_common
        PRIV_REQUIRES esp_lcd_touch_gt911 esp_lcd_hx8394
    )
else()
    idf_component_register(
        REQUIRES driver esp_lcd bsp_common
        PRIV_REQUIRES esp_lcd_hx8394
    )
endif()
