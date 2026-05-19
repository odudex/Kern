/*
 * Build the production storage module unchanged, with simulator-only POSIX
 * file hooks applied before storage.c is parsed.
 */

#include "sim_storage_hooks.h"

#include "../../../main/core/storage.c"
