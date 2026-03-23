idf_component_register(
    SRCS "waveshare_bsp.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "priv_include"
    REQUIRES driver esp_lcd esp_lvgl_port esp_driver_ledc
    PRIV_REQUIRES esp_lcd_touch_gt911
)
