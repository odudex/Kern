#ifndef TEXT_FILE_H
#define TEXT_FILE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* True when `data` starts like a descriptor Kern loads. */
bool text_is_descriptor_prefix(const char *data);

/* Normalizes a text file's contents into the single string a QR would carry
 * (see text_file.c). Returns a heap string, or NULL when the file has no
 * content line. */
char *text_file_normalize(const uint8_t *data, size_t len);

#endif // TEXT_FILE_H
