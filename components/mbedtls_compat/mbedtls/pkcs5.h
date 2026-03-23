// Compatibility shim: mbedTLS v4 moved pkcs5.h to private/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/private/pkcs5.h"
