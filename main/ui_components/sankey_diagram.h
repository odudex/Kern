#ifndef SANKEY_DIAGRAM_H
#define SANKEY_DIAGRAM_H

#include <lvgl.h>
#include <stdint.h>

typedef struct sankey_diagram sankey_diagram_t;

sankey_diagram_t *sankey_diagram_create(lv_obj_t *parent, int32_t width,
                                        int32_t height);
void sankey_diagram_destroy(sankey_diagram_t *diagram);
void sankey_diagram_set_inputs(sankey_diagram_t *diagram,
                               const uint64_t *amounts, size_t count);
void sankey_diagram_set_outputs(sankey_diagram_t *diagram,
                                const uint64_t *amounts, size_t count,
                                const lv_color_t *colors);
void sankey_diagram_render(sankey_diagram_t *diagram);
lv_obj_t *sankey_diagram_get_obj(sankey_diagram_t *diagram);
size_t sankey_diagram_get_input_overflow(sankey_diagram_t *diagram);
size_t sankey_diagram_get_output_overflow(sankey_diagram_t *diagram);

#endif
