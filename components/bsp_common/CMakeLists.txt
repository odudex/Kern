# Shared BSP headers and the default no-op PMIC implementation.
# Each board's BSP REQUIRES this component and only ships board-specific code.

set(srcs "")
# Boards without a dedicated PMIC chip get the no-op stub.
if(NOT CONFIG_KERN_BOARD_WAVE_35 AND NOT CONFIG_KERN_BOARD_CROWPANEL)
    list(APPEND srcs "pmic_stub.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
)
