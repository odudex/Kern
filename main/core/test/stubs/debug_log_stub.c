/* The on-device debug log writes to storage, which does not link on the host,
 * so every host test that pulls in descriptor_validator.c takes this. */

void debug_logf(const char *fmt, ...) { (void)fmt; }
