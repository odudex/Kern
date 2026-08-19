# Shared BSP headers and the bsp_pmic backends that are not board-specific.
# Each board's BSP REQUIRES this component and only ships board-specific code.
#
# Which backend a board gets is declared in Kconfig, not listed here, so adding
# a board is a default line there rather than an edit to this condition:
#   BSP_BATTERY_PMIC  the board's own component provides the implementation
#   BSP_BATTERY_ADC   the shared divider-on-ADC driver below
#   neither           the no-op stub, and the UI reports no battery

set(srcs "")

if(CONFIG_BSP_BATTERY_ADC)
    list(APPEND srcs "pmic_adc.c")
elseif(NOT CONFIG_BSP_BATTERY_PMIC)
    list(APPEND srcs "pmic_stub.c")
endif()

# REQUIRES is deliberately unconditional. IDF collects requirements in an early
# pass that builds the dependency graph before sdkconfig is regenerated, so a
# CONFIG_-guarded REQUIRES silently resolves to nothing on the build that first
# introduces the symbol. SRCS is evaluated later and can be guarded. The two
# extra dependencies cost boards without an ADC battery nothing: no source here
# references them and --gc-sections drops the rest.
idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    REQUIRES esp_adc esp_timer
)
