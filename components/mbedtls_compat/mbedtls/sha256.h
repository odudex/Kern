// Compatibility shim: mbedTLS v4 moved sha256.h to private/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/private/sha256.h"
