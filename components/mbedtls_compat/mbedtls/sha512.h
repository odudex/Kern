// Compatibility shim: mbedTLS v4 moved sha512.h to private/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/private/sha512.h"
