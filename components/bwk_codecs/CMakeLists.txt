set(RUST_TARGET riscv32imafc-unknown-none-elf)
set(RUST_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/target)
set(RUST_LIB ${RUST_TARGET_DIR}/${RUST_TARGET}/release/libkern_bwk_codecs.a)

idf_component_register(
    SRCS "dummy.c"
    INCLUDE_DIRS
        "../bwk/qr-protocol/include"
        "../bip138/bip138-ll/include"
)

find_program(CARGO_EXECUTABLE cargo REQUIRED)

add_custom_command(
    OUTPUT ${RUST_LIB}
    COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${RUST_TARGET_DIR}
            ${CARGO_EXECUTABLE} build --manifest-path ${CMAKE_CURRENT_LIST_DIR}/Cargo.toml
            --release --target ${RUST_TARGET}
    DEPENDS
        ${CMAKE_CURRENT_LIST_DIR}/Cargo.toml
        ${CMAKE_CURRENT_LIST_DIR}/src/lib.rs
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMENT "Building bwk codec Rust staticlib"
    VERBATIM
)

add_custom_target(bwk_codecs_rust DEPENDS ${RUST_LIB})
add_library(bwk_codecs_static STATIC IMPORTED GLOBAL)
set_target_properties(bwk_codecs_static PROPERTIES IMPORTED_LOCATION ${RUST_LIB})
add_dependencies(bwk_codecs_static bwk_codecs_rust)
add_dependencies(${COMPONENT_LIB} bwk_codecs_static)
target_link_libraries(${COMPONENT_LIB} INTERFACE bwk_codecs_static)
