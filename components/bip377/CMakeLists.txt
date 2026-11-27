set(BIP377_SRCS
    src/bip377_common.c
    src/bip377_decode.c
    src/bip377_encode.c)

if(ESP_PLATFORM)
    idf_component_register(
        SRCS ${BIP377_SRCS}
        INCLUDE_DIRS "include"
        PRIV_INCLUDE_DIRS "src")
else()
    cmake_minimum_required(VERSION 3.16)
    project(bip377 C)
    add_library(bip377 STATIC ${BIP377_SRCS})
    target_include_directories(bip377 PUBLIC include PRIVATE src)
    set_target_properties(bip377 PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_compile_options(bip377 PRIVATE -Wall -Wextra)
endif()
