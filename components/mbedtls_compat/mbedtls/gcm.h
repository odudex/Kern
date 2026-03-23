// Compatibility shim: mbedTLS v4 moved gcm.h to private/
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/private/gcm.h"
