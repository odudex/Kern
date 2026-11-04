#ifndef QR_ENCODER_H
#define QR_ENCODER_H

#include "../utils/attributes.h"
#include "seedqr.h"
#include <lvgl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Bytes a qrcodegen output buffer needs (== qrcodegen_BUFFER_LEN_MAX for
 * version 40). Defined here so callers can allocate a qr_buf without pulling in
 * the qrcodegen header; a _Static_assert in encoder.c keeps them in sync.
 */
#define QR_CODE_BUF_LEN 3918

/**
 * @brief Result from QR encoding with module information
 */
typedef struct {
  int modules; /**< QR module count (side length) */
  int scale;   /**< Pixels per module */
} qr_encode_result_t;

/**
 * @brief Update QR code with optimal encoding
 *
 * Automatically selects best encoding mode (numeric/alphanumeric/byte)
 * using qrcodegen_encodeText() and uses LOW ECC with boost for maximum
 * data efficiency while maintaining good error correction.
 *
 * @param qr_obj LVGL QR code object (canvas)
 * @param text Text to encode
 * @param result Optional pointer to receive encoding result info
 * @return LV_RESULT_OK on success, LV_RESULT_INVALID on failure
 */
lv_result_t qr_update_optimal(lv_obj_t *qr_obj, const char *text,
                              qr_encode_result_t *result);

/**
 * @brief Create a QR widget with optimal encoding
 *
 * Creates an lv_qrcode widget of the given size, centers it in the
 * parent and, if text is non-NULL, encodes it via qr_update_optimal().
 * Pass NULL text to fill the widget later.
 *
 * @param parent Parent object
 * @param size Widget size in pixels
 * @param text Text to encode, or NULL to defer
 * The widget parents itself to `parent`, so discarding the handle leaks
 * nothing and carries no KERN_WARN_UNUSED_RESULT: callers that only want the
 * code drawn may ignore it, and on failure the container simply stays empty.
 *
 * @return QR widget on success, NULL on failure
 */
lv_obj_t *qr_create_optimal(lv_obj_t *parent, int32_t size, const char *text);

/**
 * @brief Resize an existing QR widget's canvas.
 *
 * Reallocates the draw buffer and clears it, so the caller must re-encode
 * (qr_update_optimal/qr_update_binary) afterwards to repaint.
 *
 * @param qr_obj QR widget created by qr_create_optimal()
 * @param size New widget size in pixels
 */
void qr_resize(lv_obj_t *qr_obj, int32_t size);

/**
 * @brief Override the light-module (background) color of a QR widget.
 *
 * The blit step resets the palette to pure white on every encode, so this
 * must be re-applied after each qr_update_optimal/qr_update_binary call.
 *
 * @param qr_obj QR widget (canvas)
 * @param color Color for the light modules
 */
void qr_set_light_color(lv_obj_t *qr_obj, lv_color_t color);

/**
 * @brief Encode text/binary into a module buffer without drawing.
 *
 * Mirrors the encode step of qr_update_optimal/qr_update_binary (LOW ECC, auto
 * version/mask, boost). The buffer must hold at least QR_CODE_BUF_LEN bytes.
 * Module bits can then be read with the qrcodegen API or drawn via
 * qr_draw_region(). Returns the module count (side length), or 0 on failure.
 *
 * @param text/data Source to encode
 * @param qr_buf Output buffer (>= QR_CODE_BUF_LEN bytes)
 * @return Module count on success, 0 on failure
 */
KERN_WARN_UNUSED_RESULT int qr_encode_optimal(const char *text,
                                              uint8_t *qr_buf);
KERN_WARN_UNUSED_RESULT int qr_encode_binary(const uint8_t *data, size_t len,
                                             uint8_t *qr_buf);

/**
 * @brief Pixels one module takes when `cell` of them fill a widget's canvas.
 *
 * The size qr_draw_region() will draw at, read from the canvas rather than the
 * widget, so it holds before LVGL has laid the widget out too. Returns 0 when
 * there is no canvas to measure.
 *
 * @param qr_obj QR widget (canvas)
 * @param cell Module span filling the canvas (>= 1)
 */
int32_t qr_module_scale(lv_obj_t *qr_obj, int cell);

/**
 * @brief Draw a sub-rectangle of an encoded QR onto a widget's canvas.
 *
 * Draws modules [x0,x0+w) x [y0,y0+h) of qr_buf, scaled so a span of `cell`
 * modules fills the canvas, centered, then slid by (ofs_x, ofs_y) pixels.
 * Pass cell == w == h == modules to draw the whole QR, or cell == grid
 * interval to magnify one region at a constant module size. Modules landing
 * outside the canvas are clipped, so an offset draw may hand over the
 * neighbouring regions and let them slide into view. The caller retains
 * ownership of qr_buf.
 *
 * @param qr_obj QR widget (canvas)
 * @param qr_buf Buffer previously filled by qr_encode_optimal/binary
 * @param x0,y0 Top-left module of the region
 * @param w,h Module extent to draw
 * @param cell Module span used to compute scale/centering (>= 1)
 * @param ofs_x,ofs_y Pixels to slide the drawing by, 0 for none
 */
void qr_draw_region(lv_obj_t *qr_obj, const uint8_t *qr_buf, int x0, int y0,
                    int w, int h, int cell, int32_t ofs_x, int32_t ofs_y);

/**
 * @brief Uppercase a bech32 string for QR alphanumeric mode
 *
 * Bech32 is case-insensitive (BIP-173) and its uppercase form fits the
 * QR alphanumeric charset, yielding a sparser QR. Only converts strings
 * with a known bech32 HRP prefix (bc1/tb1/bcrt1) that are entirely
 * lowercase alphanumeric; case-sensitive data (base58) never matches.
 *
 * @param text Candidate string
 * @return Allocated uppercased copy (caller must free), or NULL if the
 *         string is not a lowercase bech32 string
 */
KERN_WARN_UNUSED_RESULT char *qr_bech32_to_upper(const char *text);

/**
 * @brief Update QR code with binary data encoding
 *
 * Encodes binary data using byte mode QR encoding.
 *
 * @param qr_obj LVGL QR code object (canvas)
 * @param data Binary data to encode
 * @param len Length of the data
 * @param result Optional pointer to receive encoding result info
 * @return LV_RESULT_OK on success, LV_RESULT_INVALID on failure
 */
lv_result_t qr_update_binary(lv_obj_t *qr_obj, const unsigned char *data,
                             size_t len, qr_encode_result_t *result);

#endif
