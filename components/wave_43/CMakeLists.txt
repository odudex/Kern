if(CONFIG_KERN_BOARD_WAVE_43)
    idf_component_register(
        SRCS "wave_43.c" "pmic.c"
        INCLUDE_DIRS "include"
        REQUIRES driver esp_lcd esp_driver_ledc bsp_common esp_adc esp_timer
        PRIV_REQUIRES esp_lcd_touch_gt911
    )
else()
    idf_component_register(
        REQUIRES driver esp_lcd esp_driver_ledc bsp_common
    )
endif()
