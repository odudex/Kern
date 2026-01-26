#include "sankey_diagram.h"
#include "theme.h"
#include <stdlib.h>
#include <string.h>

#define MAX_FLOWS 16
#define MIN_THICKNESS 4
#define CURVE_SAMPLES 32
#define THICKNESS_BUDGET_PCT 30

typedef struct {
  uint64_t amount;
  float thickness;
  float y_center;
  lv_color_t color;
} sankey_flow_t;

struct sankey_diagram {
  lv_obj_t *canvas;
  lv_draw_buf_t *draw_buf;
  int32_t width;
  int32_t height;

  sankey_flow_t inputs[MAX_FLOWS];
  size_t input_count;
  uint64_t total_input;
  size_t input_overflow;

  sankey_flow_t outputs[MAX_FLOWS];
  size_t output_count;
  uint64_t total_output;
  size_t output_overflow;
};

static float bezier_eval(float p0, float p1, float p2, float p3, float t) {
  float mt = 1.0f - t;
  float mt2 = mt * mt;
  float t2 = t * t;
  return mt2 * mt * p0 + 3.0f * mt2 * t * p1 + 3.0f * mt * t2 * p2 +
         t2 * t * p3;
}

static lv_color_t color_lerp(lv_color_t c1, lv_color_t c2, float t) {
  if (t <= 0.0f)
    return c1;
  if (t >= 1.0f)
    return c2;
  return lv_color_make((uint8_t)(c1.red + t * (c2.red - c1.red)),
                       (uint8_t)(c1.green + t * (c2.green - c1.green)),
                       (uint8_t)(c1.blue + t * (c2.blue - c1.blue)));
}

static inline void set_pixel(sankey_diagram_t *diagram, int32_t x, int32_t y,
                             uint16_t color16) {
  if (x < 0 || x >= diagram->width || y < 0 || y >= diagram->height)
    return;
  uint16_t *row = (uint16_t *)((uint8_t *)diagram->draw_buf->data +
                               y * diagram->draw_buf->header.stride);
  row[x] = color16;
}

static void draw_gradient_rect(sankey_diagram_t *diagram, int32_t x_start,
                               int32_t x_end, int32_t y_top, int32_t y_bot,
                               lv_color_t left_color, lv_color_t right_color) {
  if (x_start > x_end) {
    int32_t tmp = x_start;
    x_start = x_end;
    x_end = tmp;
    lv_color_t tmp_c = left_color;
    left_color = right_color;
    right_color = tmp_c;
  }
  if (y_top > y_bot) {
    int32_t tmp = y_top;
    y_top = y_bot;
    y_bot = tmp;
  }

  int32_t width = x_end - x_start;
  if (width <= 0)
    return;

  for (int32_t x = x_start; x <= x_end; x++) {
    uint16_t color16 = lv_color_to_u16(
        color_lerp(left_color, right_color, (float)(x - x_start) / width));
    for (int32_t y = y_top; y <= y_bot; y++) {
      set_pixel(diagram, x, y, color16);
    }
  }
}

static void draw_bezier_ribbon(sankey_diagram_t *diagram, float x0,
                               float y0_top, float y0_bot, float x3,
                               float y3_top, float y3_bot,
                               lv_color_t start_color, lv_color_t end_color) {
  float dx = (x3 - x0) / 3.0f;
  float x1 = x0 + dx, x2 = x3 - dx;

  for (int i = 0; i < CURVE_SAMPLES; i++) {
    float t1 = (float)i / CURVE_SAMPLES;
    float t2 = (float)(i + 1) / CURVE_SAMPLES;
    uint16_t color16 =
        lv_color_to_u16(color_lerp(start_color, end_color, (t1 + t2) / 2.0f));

    float xt1 = bezier_eval(x0, x1, x2, x3, t1);
    float yt1_top = bezier_eval(y0_top, y0_top, y3_top, y3_top, t1);
    float yt1_bot = bezier_eval(y0_bot, y0_bot, y3_bot, y3_bot, t1);

    float xt2 = bezier_eval(x0, x1, x2, x3, t2);
    float yt2_top = bezier_eval(y0_top, y0_top, y3_top, y3_top, t2);
    float yt2_bot = bezier_eval(y0_bot, y0_bot, y3_bot, y3_bot, t2);

    int32_t xs = (int32_t)(xt1 + 0.5f), xe = (int32_t)(xt2 + 0.5f);

    for (int32_t x = xs; x <= xe; x++) {
      float frac = (xe != xs) ? (float)(x - xs) / (xe - xs) : 0.0f;
      int32_t y1 = (int32_t)(yt1_top + frac * (yt2_top - yt1_top) + 0.5f);
      int32_t y2 = (int32_t)(yt1_bot + frac * (yt2_bot - yt1_bot) + 0.5f);
      if (y1 > y2) {
        int32_t tmp = y1;
        y1 = y2;
        y2 = tmp;
      }
      for (int32_t y = y1; y <= y2; y++) {
        set_pixel(diagram, x, y, color16);
      }
    }
  }
}

static void calculate_flow_layout(sankey_flow_t *flows, size_t count,
                                  uint64_t total_amount, int32_t height,
                                  float y_offset) {
  if (count == 0 || total_amount == 0)
    return;

  float thickness_budget = height * THICKNESS_BUDGET_PCT / 100.0f;
  float gap = (count > 1)
                  ? height * (100 - THICKNESS_BUDGET_PCT) / 100.0f / (count - 1)
                  : 0;

  float total_raw = 0;
  for (size_t i = 0; i < count; i++) {
    flows[i].thickness =
        (float)flows[i].amount / total_amount * thickness_budget;
    if (flows[i].thickness < MIN_THICKNESS)
      flows[i].thickness = MIN_THICKNESS;
    total_raw += flows[i].thickness;
  }

  if (total_raw > thickness_budget) {
    float scale = thickness_budget / total_raw;
    for (size_t i = 0; i < count; i++)
      flows[i].thickness *= scale;
  }

  float y = y_offset + flows[0].thickness / 2.0f;
  for (size_t i = 0; i < count; i++) {
    flows[i].y_center = y;
    if (i < count - 1) {
      y += flows[i].thickness / 2.0f + gap + flows[i + 1].thickness / 2.0f;
    }
  }
}

sankey_diagram_t *sankey_diagram_create(lv_obj_t *parent, int32_t width,
                                        int32_t height) {
  if (!parent || width <= 0 || height <= 0)
    return NULL;

  sankey_diagram_t *diagram = calloc(1, sizeof(sankey_diagram_t));
  if (!diagram)
    return NULL;

  diagram->width = width;
  diagram->height = height;
  diagram->draw_buf =
      lv_draw_buf_create(width, height, LV_COLOR_FORMAT_RGB565, LV_STRIDE_AUTO);
  if (!diagram->draw_buf) {
    free(diagram);
    return NULL;
  }

  diagram->canvas = lv_canvas_create(parent);
  if (!diagram->canvas) {
    lv_draw_buf_destroy(diagram->draw_buf);
    free(diagram);
    return NULL;
  }

  lv_canvas_set_draw_buf(diagram->canvas, diagram->draw_buf);
  lv_obj_set_size(diagram->canvas, width, height);
  return diagram;
}

void sankey_diagram_destroy(sankey_diagram_t *diagram) {
  if (!diagram)
    return;
  if (diagram->canvas)
    lv_obj_del(diagram->canvas);
  if (diagram->draw_buf)
    lv_draw_buf_destroy(diagram->draw_buf);
  free(diagram);
}

void sankey_diagram_set_inputs(sankey_diagram_t *diagram,
                               const uint64_t *amounts, size_t count) {
  if (!diagram || !amounts || count == 0)
    return;

  diagram->total_input = 0;
  diagram->input_overflow = (count > MAX_FLOWS) ? (count - MAX_FLOWS) : 0;
  diagram->input_count = (count > MAX_FLOWS) ? MAX_FLOWS : count;

  for (size_t i = 0; i < count; i++)
    diagram->total_input += amounts[i];
  for (size_t i = 0; i < diagram->input_count; i++) {
    diagram->inputs[i].amount = amounts[i];
    diagram->inputs[i].color = lv_color_hex(0xFFFFFF);
  }
}

void sankey_diagram_set_outputs(sankey_diagram_t *diagram,
                                const uint64_t *amounts, size_t count,
                                const lv_color_t *colors) {
  if (!diagram || !amounts || count == 0)
    return;

  diagram->total_output = 0;
  diagram->output_overflow = (count > MAX_FLOWS) ? (count - MAX_FLOWS) : 0;
  diagram->output_count = (count > MAX_FLOWS) ? MAX_FLOWS : count;

  for (size_t i = 0; i < count; i++)
    diagram->total_output += amounts[i];
  for (size_t i = 0; i < diagram->output_count; i++) {
    diagram->outputs[i].amount = amounts[i];
    diagram->outputs[i].color = colors ? colors[i] : lv_color_hex(0xFFFFFF);
  }
}

void sankey_diagram_render(sankey_diagram_t *diagram) {
  if (!diagram || !diagram->canvas || !diagram->draw_buf)
    return;

  lv_draw_buf_clear(diagram->draw_buf, NULL);

  uint8_t *buf = (uint8_t *)diagram->draw_buf->data;
  uint32_t stride = diagram->draw_buf->header.stride;
  lv_color_t bg = bg_color();
  uint16_t bg16 = lv_color_to_u16(bg);

  for (int32_t y = 0; y < diagram->height; y++) {
    uint16_t *row = (uint16_t *)(buf + y * stride);
    for (int32_t x = 0; x < diagram->width; x++)
      row[x] = bg16;
  }

  if (diagram->input_count == 0 || diagram->output_count == 0) {
    lv_obj_invalidate(diagram->canvas);
    return;
  }

  uint64_t total_ref = diagram->total_input ? diagram->total_input : 1;
  float center_x = diagram->width / 2.0f;
  float center_y = diagram->height / 2.0f;

  calculate_flow_layout(diagram->inputs, diagram->input_count, total_ref,
                        diagram->height, 0);
  calculate_flow_layout(diagram->outputs, diagram->output_count, total_ref,
                        diagram->height, 0);

  float input_stack_height = 0, output_stack_height = 0;
  for (size_t i = 0; i < diagram->input_count; i++)
    input_stack_height += diagram->inputs[i].thickness;
  for (size_t i = 0; i < diagram->output_count; i++)
    output_stack_height += diagram->outputs[i].thickness;

  float *input_center_positions = malloc(diagram->input_count * sizeof(float));
  float *output_center_positions =
      malloc(diagram->output_count * sizeof(float));
  if (!input_center_positions || !output_center_positions) {
    free(input_center_positions);
    free(output_center_positions);
    return;
  }

  float y_pos = center_y - input_stack_height / 2.0f;
  for (size_t i = 0; i < diagram->input_count; i++) {
    input_center_positions[i] = y_pos + diagram->inputs[i].thickness / 2.0f;
    y_pos += diagram->inputs[i].thickness;
  }

  y_pos = center_y - output_stack_height / 2.0f;
  for (size_t i = 0; i < diagram->output_count; i++) {
    output_center_positions[i] = y_pos + diagram->outputs[i].thickness / 2.0f;
    y_pos += diagram->outputs[i].thickness;
  }

  float fade_width = diagram->width * 0.05f;
  float fade_start_x = diagram->width - fade_width;
  lv_color_t white = lv_color_hex(0xFFFFFF);

  for (size_t i = 0; i < diagram->input_count; i++) {
    float half = diagram->inputs[i].thickness / 2.0f;
    draw_gradient_rect(diagram, 0, (int32_t)fade_width,
                       (int32_t)(diagram->inputs[i].y_center - half),
                       (int32_t)(diagram->inputs[i].y_center + half), bg,
                       white);
    draw_bezier_ribbon(diagram, fade_width, diagram->inputs[i].y_center - half,
                       diagram->inputs[i].y_center + half, center_x,
                       input_center_positions[i] - half,
                       input_center_positions[i] + half,
                       diagram->inputs[i].color, diagram->inputs[i].color);
  }

  for (size_t i = 0; i < diagram->output_count; i++) {
    float half = diagram->outputs[i].thickness / 2.0f;
    draw_bezier_ribbon(diagram, center_x, output_center_positions[i] - half,
                       output_center_positions[i] + half, fade_start_x,
                       diagram->outputs[i].y_center - half,
                       diagram->outputs[i].y_center + half, white,
                       diagram->outputs[i].color);
    draw_gradient_rect(diagram, (int32_t)fade_start_x, diagram->width - 1,
                       (int32_t)(diagram->outputs[i].y_center - half),
                       (int32_t)(diagram->outputs[i].y_center + half),
                       diagram->outputs[i].color, bg);
  }

  free(input_center_positions);
  free(output_center_positions);
  lv_image_cache_drop(diagram->draw_buf);
  lv_obj_invalidate(diagram->canvas);
}

lv_obj_t *sankey_diagram_get_obj(sankey_diagram_t *diagram) {
  return diagram ? diagram->canvas : NULL;
}

size_t sankey_diagram_get_input_overflow(sankey_diagram_t *diagram) {
  return diagram ? diagram->input_overflow : 0;
}

size_t sankey_diagram_get_output_overflow(sankey_diagram_t *diagram) {
  return diagram ? diagram->output_overflow : 0;
}
