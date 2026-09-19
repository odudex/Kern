#ifndef QR_EXPORT_H
#define QR_EXPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Content is borrowed and must remain valid until qr_export_free().
typedef struct qr_export qr_export_t;
qr_export_t *qr_export_create(int format, const char *content, size_t density);
void qr_export_free(qr_export_t *export);
size_t qr_export_part_count(const qr_export_t *export);
bool qr_export_is_fountain(const qr_export_t *export);
// Zero-based frame index. Fountain frames must be requested sequentially;
// repeating the latest request returns the cached frame (e.g. after draw OOM).
// The returned string belongs to the export and survives until the next
// request.
const char *qr_export_frame(qr_export_t *export, uint32_t index);

#endif
