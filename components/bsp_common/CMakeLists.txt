# Shared BSP headers and the default no-op PMIC implementation.
# Each board's BSP REQUIRES this component and only ships board-specific code.

set(srcs "")
# Boards without a dedicated PMIC chip read the battery over an ADC divider,
# or get the no-op stub if they cannot read it at all.
if(CONFIG_KERN_BOARD_WAVE_43 OR CONFIG_KERN_BOARD_WAVE_5
   OR CONFIG_KERN_BOARD_WAVE_7B)
    list(APPEND srcs "pmic_adc.c")
elseif(NOT CONFIG_KERN_BOARD_WAVE_35 AND NOT CONFIG_KERN_BOARD_CROWPANEL)
    list(APPEND srcs "pmic_stub.c")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES esp_adc
)
