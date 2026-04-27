/*
 * Simulator compatibility shim — force-included via -include in CMakeLists.txt.
 *
 * 1. Provides standard C headers that ESP-IDF pulls in transitively but
 *    host GCC does not.
 * 2. Maps mbedTLS 3.x/4.x API names used by ESP-IDF to the 2.x API
 *    available on the host system.
 */
#pragma once

#include <stdio.h>
#include <string.h>

#if defined(__has_include)
#if __has_include(<mbedtls/private_access.h>)
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#endif

#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/sha256.h>
#include <mbedtls/version.h>

#if MBEDTLS_VERSION_MAJOR < 3

/* mbedtls_sha256() returns void in 2.x; use mbedtls_sha256_ret() instead */
#define mbedtls_sha256(data, len, out, is224) \
    mbedtls_sha256_ret((data), (len), (out), (is224))

/* mbedtls_pkcs5_pbkdf2_hmac_ext() doesn't exist in 2.x; wrap the ctx-based API */
static inline int mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t md_type,
                                                 const unsigned char *password,
                                                 size_t plen,
                                                 const unsigned char *salt,
                                                 size_t slen,
                                                 unsigned int iterations,
                                                 uint32_t key_length,
                                                 unsigned char *output) {
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md_type);
    if (!info)
        return -1;
    int ret = mbedtls_md_setup(&ctx, info, 1);
    if (ret != 0) {
        mbedtls_md_free(&ctx);
        return ret;
    }
    ret = mbedtls_pkcs5_pbkdf2_hmac(&ctx, password, plen, salt, slen,
                                     iterations, key_length, output);
    mbedtls_md_free(&ctx);
    return ret;
}

#endif /* MBEDTLS_VERSION_MAJOR < 3 */
