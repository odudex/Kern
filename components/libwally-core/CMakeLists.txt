idf_component_register(SRCS
                       "kern_wally.c"
                       "upstream/src/amalgamation/combined.c"
                       INCLUDE_DIRS
                       "."
                       "upstream/include"
                       PRIV_INCLUDE_DIRS
                       "."
                       "upstream"
                       "upstream/src"
                       "upstream/src/ccan"
                       "upstream/src/secp256k1/include"
                       PRIV_REQUIRES mbedtls secure_memory)

set_source_files_properties(
    upstream/src/amalgamation/combined.c
    PROPERTIES COMPILE_FLAGS
    "-Wno-error=maybe-uninitialized -Wno-error=array-parameter"
    )

target_compile_definitions(${COMPONENT_TARGET} PRIVATE _FORTIFY_SOURCE=2)

# libwally tests BUILD_ELEMENTS with #ifdef: defining it, even as 0, enables Elements.
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DBUILD_MINIMAL=1")
# Standard libsecp256k1: drops MuSig2 + ecdsa-s2c/anti-exfil (unused by Kern).
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DBUILD_STANDARD_SECP=1")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DHAVE_PSA_CRYPTO_H")
# The secp256k1 module set is combined.c's.
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DECMULT_WINDOW_SIZE=8")
