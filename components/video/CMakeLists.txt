include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/boards.cmake)
kern_board_detect_from_kconfig()

idf_component_register(
    SRCS "video.c"
    INCLUDE_DIRS "."
    REQUIRES esp_cam_sensor esp_video esp_sccb_intf ${KERN_BOARD_REQUIRES} secure_memory
)
