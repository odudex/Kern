idf_component_register(
    SRCS "video.c"
    INCLUDE_DIRS "."
    REQUIRES esp_cam_sensor esp_video esp_sccb_intf wave_4b wave_35 wave_5
)