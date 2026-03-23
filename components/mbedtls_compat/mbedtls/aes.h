// Compatibility shim: mbedTLS v4 moved aes.h to private/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/private/aes.h"
