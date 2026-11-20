set(RUST_TARGET riscv32imafc-unknown-none-elf)
set(RUST_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/target)
set(RUST_LIB ${RUST_TARGET_DIR}/${RUST_TARGET}/release/libkern_bip377.a)

idf_component_register(
    SRCS "dummy.c"
    INCLUDE_DIRS
        "upstream/bip377-ll/include"
        "../bip_nonces_cache/upstream/bip-nonces-cache-ll/include"
)

find_program(CARGO_EXECUTABLE cargo REQUIRED)

# Always runs: cargo tracks the bip377 sources and only relinks on a change
add_custom_target(bip377_rust
    COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${RUST_TARGET_DIR}
            ${CARGO_EXECUTABLE} build --manifest-path ${CMAKE_CURRENT_LIST_DIR}/Cargo.toml
            --release --target ${RUST_TARGET}
    # The prebuilt compiler_builtins C objects are soft-float; libgcc's are not
    COMMAND ${CMAKE_COMMAND} -DAR=${CMAKE_AR} -DLIB=${RUST_LIB}
            -P ${CMAKE_CURRENT_LIST_DIR}/strip_c_builtins.cmake
    BYPRODUCTS ${RUST_LIB}
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMENT "Building bip377 Rust staticlib"
    VERBATIM
)
add_library(bip377_static STATIC IMPORTED GLOBAL)
set_target_properties(bip377_static PROPERTIES IMPORTED_LOCATION ${RUST_LIB})
add_dependencies(bip377_static bip377_rust)
add_dependencies(${COMPONENT_LIB} bip377_static)
target_link_libraries(${COMPONENT_LIB} INTERFACE bip377_static)
