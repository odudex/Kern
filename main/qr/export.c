#include "export.h"
#include "../../components/bbqr/src/bbqr.h"
#include "../../components/cUR/src/types/psbt.h"
#include "../../components/cUR/src/ur_encoder.h"
#include "parser.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_core.h>

#define UR_HEADER_OVERHEAD 30

struct qr_export {
  const char *content;
  size_t content_len;
  size_t chunk_size;
  size_t count;
  BBQrParts *bbqr;
  ur_encoder_t *ur;
  char *frame;
  uint32_t frame_index;
  bool failed;
};

void qr_export_free(qr_export_t *export) {
  if (!export)
    return;
  bbqr_parts_free(export->bbqr);
  ur_encoder_free(export->ur);
  free(export->frame);
  free(export);
}

static bool prepare_pmofn(qr_export_t *export, size_t density) {
  if (export->content_len > QR_PARSER_MAX_STORED_BYTES)
    return false;
  export->chunk_size = density;
  export->count = 1;
  if (export->content_len <= density)
    return true;

  size_t count = export->content_len / density + 1;
  for (;;) {
    // The longest header is the last index. Iterate across digit boundaries
    // until the payload size and total frame count agree.
    int header = snprintf(NULL, 0, "p%zuof%zu ", count, count);
    if (header < 0 || (size_t)header >= density)
      return false;
    size_t chunk = density - (size_t)header;
    size_t needed = (export->content_len + chunk - 1) / chunk;
    if (needed > QR_PARSER_MAX_MULTIPART_PARTS)
      return false;
    if (needed == count) {
      export->chunk_size = chunk;
      export->count = count;
      return true;
    }
    count = needed;
  }
}

qr_export_t *qr_export_create(int format, const char *content, size_t density) {
  if (!content || !*content || density < 100 || density > 600)
    return NULL;
  qr_export_t *export = calloc(1, sizeof(*export));
  if (!export)
    return NULL;
  export->content = content;
  export->content_len = strlen(content);
  if (format != FORMAT_BBQR && format != FORMAT_UR) {
    if (prepare_pmofn(export, density))
      return export;
    goto fail;
  }

  size_t capacity = export->content_len / 4 * 3 + 3;
  uint8_t *bytes = malloc(capacity);
  if (!bytes)
    goto fail;
  size_t len = 0;
  if (wally_base64_to_bytes(content, 0, bytes, capacity, &len) != WALLY_OK) {
    free(bytes);
    goto fail;
  }
  if (format == FORMAT_BBQR) {
    export->bbqr = bbqr_encode(bytes, len, BBQR_TYPE_PSBT, (int)density);
    free(bytes);
    if (!export->bbqr)
      goto fail;
    export->count = export->bbqr->count;
    return export;
  }

  psbt_data_t *psbt = psbt_new(bytes, len);
  free(bytes);
  if (!psbt)
    goto fail;
  size_t cbor_len = 0;
  uint8_t *cbor = psbt_to_cbor(psbt, &cbor_len);
  psbt_free(psbt);
  if (!cbor)
    goto fail;
  export->ur = ur_encoder_new("crypto-psbt", cbor, cbor_len,
                              (density - UR_HEADER_OVERHEAD) / 2, 0, 10);
  free(cbor);
  if (!export->ur)
    goto fail;
  export->count = ur_encoder_seq_len(export->ur);
  if (!export->count || export->count > UINT32_MAX)
    goto fail;
  return export;

fail:
  qr_export_free(export);
  return NULL;
}

size_t qr_export_part_count(const qr_export_t *export) { return export->count; }

bool qr_export_is_fountain(const qr_export_t *export) {
  return export->ur && export->count > 1;
}

const char *qr_export_frame(qr_export_t *export, uint32_t index) {
  if (export->frame && export->frame_index == index)
    return export->frame;
  if (export->failed || index == UINT32_MAX)
    return NULL;
  if (export->ur) {
    if (index != (export->frame ? export->frame_index + 1 : 0) ||
        (export->count == 1 && index != 0))
      return NULL;
    char *frame = NULL;
    if (!ur_encoder_next_part(export->ur, &frame)) {
      // The fountain encoder may have advanced before failing. Never silently
      // skip a fragment; keep the last displayed frame and require a restart.
      export->failed = true;
      return NULL;
    }
    free(export->frame);
    export->frame = frame;
  } else {
    if (index >= export->count)
      return NULL;
    if (export->bbqr)
      return export->bbqr->parts[index];
    if (export->count == 1)
      return export->content;
    size_t offset = index * export->chunk_size;
    size_t len = export->content_len - offset;
    if (len > export->chunk_size)
      len = export->chunk_size;
    int header =
        snprintf(NULL, 0, "p%uof%zu ", (unsigned)index + 1, export->count);
    char *frame = malloc((size_t)header + len + 1);
    if (!frame)
      return NULL;
    snprintf(frame, (size_t)header + 1, "p%uof%zu ", (unsigned)index + 1,
             export->count);
    memcpy(frame + header, export->content + offset, len);
    frame[header + len] = '\0';
    free(export->frame);
    export->frame = frame;
  }
  export->frame_index = index;
  return export->frame;
}
