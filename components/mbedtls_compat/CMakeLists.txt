# Compatibility shims for mbedTLS v4 (ESP-IDF 6.0)
# mbedTLS v4 moved crypto headers (sha256.h, aes.h, etc.) from mbedtls/ to mbedtls/private/
# These shims redirect #include <mbedtls/sha256.h> to <mbedtls/private/sha256.h>
idf_component_register(
    INCLUDE_DIRS "."
    REQUIRES mbedtls
)
