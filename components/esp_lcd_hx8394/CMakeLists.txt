if(CONFIG_KERN_BOARD_WAVE_5 OR CONFIG_KERN_BOARD_P4_PICO)
    idf_component_register(
        SRCS "esp_lcd_hx8394.c"
        INCLUDE_DIRS "include"
        REQUIRES esp_lcd
        PRIV_REQUIRES driver
    )
else()
    idf_component_register(
        REQUIRES esp_lcd
        PRIV_REQUIRES driver
    )
endif()
