idf_component_register(SRCS
                       "kern_wally.c"
                       "kern_combined.c"
                       INCLUDE_DIRS
                       "."
                       "upstream/include"
                       "upstream/src/secp256k1/include"
                       PRIV_INCLUDE_DIRS
                       "."
                       "upstream"
                       "upstream/src"
                       "upstream/src/ccan"
                       "upstream/src/secp256k1/include"
                       PRIV_REQUIRES mbedtls secure_memory)

set_source_files_properties(
    kern_combined.c
    PROPERTIES COMPILE_FLAGS
    "-Wno-error=maybe-uninitialized -Wno-error=array-parameter"
    )

target_compile_definitions(${COMPONENT_TARGET} PRIVATE _FORTIFY_SOURCE=2)

# libwally tests BUILD_ELEMENTS with #ifdef: defining it, even as 0, enables Elements.
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DBUILD_MINIMAL=1")
# Drops the Elements fields from the public structs. It changes their layout,
# so it is PUBLIC: every user of the headers must see it.
target_compile_definitions(${COMPONENT_TARGET} PUBLIC "-DWALLY_ABI_NO_ELEMENTS")
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DHAVE_PSA_CRYPTO_H")
# The secp256k1 module set is combined.c's, MuSig2 included, plus the BIP352
# silentpayments module kern_combined.c enables.
target_compile_definitions(${COMPONENT_TARGET} PRIVATE "-DECMULT_WINDOW_SIZE=8")
