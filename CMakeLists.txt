# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.22)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

add_compile_options(-Wno-format)
add_compile_options(-Wno-ignored-qualifiers)
add_compile_options(-Wno-attributes)
add_compile_options(-Wno-unused-function)
# Per-clone throwaway key so dev builds carry the signature block that
# SECURE_SIGNED_ON_UPDATE requires at boot; releases are re-signed offline.
# Must exist before project() — IDF checks the key during configure. Path
# must match CONFIG_SECURE_BOOT_SIGNING_KEY in sdkconfig.defaults.
set(dev_signing_key "${CMAKE_CURRENT_LIST_DIR}/dev_signing_key.pem")
if(NOT EXISTS "${dev_signing_key}")
    message(STATUS "Generating dev signing key ${dev_signing_key}")
    execute_process(
        COMMAND python -m espsecure generate-signing-key
            --version 2 --scheme rsa3072 "${dev_signing_key}"
        RESULT_VARIABLE keygen_result)
    if(NOT keygen_result EQUAL 0)
        message(FATAL_ERROR "Failed to generate ${dev_signing_key}")
    endif()
endif()

project(kern)
