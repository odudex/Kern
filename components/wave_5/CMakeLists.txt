if(CONFIG_KERN_BOARD_WAVE_5)
    idf_component_register(
        SRCS "wave_5.c"
        INCLUDE_DIRS "include"
        REQUIRES driver esp_lcd esp_driver_ledc bsp_common
        PRIV_REQUIRES esp_lcd_touch_gt911 esp_lcd_hx8394
    )
else()
    idf_component_register(
        REQUIRES driver esp_lcd esp_driver_ledc bsp_common
        PRIV_REQUIRES esp_lcd_hx8394
    )
endif()
