# Compatibility shims for mbedTLS v4 (ESP-IDF 6.1)
# mbedTLS v4 moved crypto headers (sha256.h, aes.h, etc.) from mbedtls/ to mbedtls/private/
# These shims redirect #include <mbedtls/sha256.h> to <mbedtls/private/sha256.h>
# Also provides legacy mbedtls_sha512_* symbols removed by PSA hardware acceleration.
idf_component_register(
    SRCS "sha512_compat.c"
    INCLUDE_DIRS "."
    REQUIRES mbedtls
)
