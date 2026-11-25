set(RUST_TARGET riscv32imafc-unknown-none-elf)
set(RUST_TARGET_DIR ${CMAKE_CURRENT_BINARY_DIR}/target)
set(RUST_LIB ${RUST_TARGET_DIR}/${RUST_TARGET}/release/libkern_bipqr.a)

idf_component_register(
    SRCS "dummy.c"
    INCLUDE_DIRS
        "upstream/bipqr-ll/include"
)

find_program(CARGO_EXECUTABLE cargo REQUIRED)

# Always runs: cargo tracks the bipqr sources and only relinks on a change
add_custom_target(bipqr_rust
    COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${RUST_TARGET_DIR}
            ${CARGO_EXECUTABLE} build --manifest-path ${CMAKE_CURRENT_LIST_DIR}/Cargo.toml
            --release --target ${RUST_TARGET}
    # The prebuilt compiler_builtins C objects are soft-float; libgcc's are not
    COMMAND ${CMAKE_COMMAND} -DAR=${CMAKE_AR} -DLIB=${RUST_LIB}
            -P ${CMAKE_CURRENT_LIST_DIR}/strip_c_builtins.cmake
    BYPRODUCTS ${RUST_LIB}
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMENT "Building bipqr Rust staticlib"
    VERBATIM
)
add_library(bipqr_static STATIC IMPORTED GLOBAL)
set_target_properties(bipqr_static PROPERTIES IMPORTED_LOCATION ${RUST_LIB})
add_dependencies(bipqr_static bipqr_rust)
add_dependencies(${COMPONENT_LIB} bipqr_static)
target_link_libraries(${COMPONENT_LIB} INTERFACE bipqr_static)
