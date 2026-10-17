#ifndef LIBWALLYCORE_CONFIG_H
#define LIBWALLYCORE_CONFIG_H

/* Kern's libwally build configuration, replacing the autoconf-generated one.
 * Without a wipe backend wally_bzero() falls back to a plain memset() the
 * compiler may elide, including bip32_key_free()'s private-key wipe. */
#define HAVE_EXPLICIT_BZERO 1

#ifndef HAVE_UNALIGNED_ACCESS
#define HAVE_UNALIGNED_ACCESS 1
#endif

#include "ccan_config.h"
#endif /*LIBWALLYCORE_CONFIG_H*/
