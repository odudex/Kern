if(CONFIG_KERN_BOARD_CROWPANEL_101)
    idf_component_register(
        SRCS "crowpanel_101.c" "pmic.c"
        INCLUDE_DIRS "include"
        REQUIRES driver esp_lcd esp_driver_ledc bsp_common
        PRIV_REQUIRES esp_lcd_touch_gt911
    )
else()
    idf_component_register(
        REQUIRES driver esp_lcd esp_driver_ledc bsp_common
    )
endif()
