# A stock CONFIG_SECURE_BOOT bootloader burns secure boot on its first boot,
# from the digests of its own signature blocks. Kern burns it from the app
# instead, once the user opts in (main/core/secure_boot.c), so this component
# keeps the bootloader from touching eFuses until SECURE_BOOT_EN is set.
set(srcs "")
if(CONFIG_SECURE_BOOT_V2_ENABLED)
    list(APPEND srcs "secure_boot_opt_in.c")
endif()

idf_component_register(SRCS ${srcs}
                       PRIV_REQUIRES bootloader_support efuse log)

if(CONFIG_SECURE_BOOT_V2_ENABLED)
    target_link_libraries(${COMPONENT_LIB} INTERFACE
        "-Wl,--wrap=esp_secure_boot_v2_permanently_enable"
        "-u __wrap_esp_secure_boot_v2_permanently_enable")
endif()
