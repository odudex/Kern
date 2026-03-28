/**
 * Compatibility shim: provides legacy mbedtls_sha512_* functions using PSA crypto API.
 *
 * When CONFIG_MBEDTLS_HARDWARE_SHA is enabled on ESP32-P4, ESP-IDF v6.x undefines
 * MBEDTLS_SHA512_C (replacing it with PSA hardware acceleration). This removes the
 * legacy mbedtls_sha512_init/starts/update/finish/free symbols that libwally-core
 * calls directly. This file re-implements them on top of psa_hash_*.
 */

#include "sdkconfig.h"

/* Only needed when hardware SHA is enabled (which removes MBEDTLS_SHA512_C) */
#if defined(CONFIG_MBEDTLS_HARDWARE_SHA) && defined(CONFIG_SOC_SHA_SUPPORT_SHA512)

/* Must be defined before any mbedtls header to access private struct members */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include <string.h>
#include "mbedtls/private/sha512.h"
#include "psa/crypto.h"

/**
 * We store a psa_hash_operation_t inside the legacy context's buffer area,
 * which is 128 bytes — more than enough for the PSA operation struct.
 */
_Static_assert(sizeof(psa_hash_operation_t) <= sizeof(((mbedtls_sha512_context *)0)->buffer),
               "psa_hash_operation_t does not fit in sha512_context buffer");

static inline psa_hash_operation_t *get_op(mbedtls_sha512_context *ctx)
{
    return (psa_hash_operation_t *)ctx->buffer;
}

void mbedtls_sha512_init(mbedtls_sha512_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    *get_op(ctx) = psa_hash_operation_init();
}

void mbedtls_sha512_free(mbedtls_sha512_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    psa_hash_abort(get_op(ctx));
    memset(ctx, 0, sizeof(*ctx));
}

void mbedtls_sha512_clone(mbedtls_sha512_context *dst,
                           const mbedtls_sha512_context *src)
{
    *dst = *src;
    *get_op(dst) = psa_hash_operation_init();
    psa_hash_clone(get_op((mbedtls_sha512_context *)src), get_op(dst));
}

int mbedtls_sha512_starts(mbedtls_sha512_context *ctx, int is384)
{
#if defined(MBEDTLS_SHA384_C)
    ctx->is384 = is384;
#endif
    psa_algorithm_t alg = is384 ? PSA_ALG_SHA_384 : PSA_ALG_SHA_512;
    *get_op(ctx) = psa_hash_operation_init();
    psa_status_t status = psa_hash_setup(get_op(ctx), alg);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                           const unsigned char *input, size_t ilen)
{
    psa_status_t status = psa_hash_update(get_op(ctx), input, ilen);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx,
                           unsigned char *output)
{
#if defined(MBEDTLS_SHA384_C)
    size_t hash_len = ctx->is384 ? 48 : 64;
#else
    size_t hash_len = 64;
#endif
    size_t actual_len = 0;
    psa_status_t status = psa_hash_finish(get_op(ctx), output, hash_len, &actual_len);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

#endif /* CONFIG_MBEDTLS_HARDWARE_SHA && CONFIG_SOC_SHA_SUPPORT_SHA512 */
