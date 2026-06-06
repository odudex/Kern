#include "swipe_back.h"
#include "theme.h"
#include <stdlib.h>

#define COMMIT_RATIO 25  // % of screen width to commit back nav
#define FOLLOW_RATIO 100 // screen tracks finger 1:1

typedef struct {
  lv_obj_t *screen;
  void (*back_cb)(void);
  bool active;
  int32_t start_x;
} swipe_ctx_t;

static void anim_x_cb(void *obj, int32_t v) {
  lv_obj_set_x((lv_obj_t *)obj, v);
}

static void snap_back(lv_obj_t *screen) {
  lv_anim_t a;
  lv_anim_init(&a);
  lv_anim_set_var(&a, screen);
  lv_anim_set_exec_cb(&a, anim_x_cb);
  lv_anim_set_values(&a, lv_obj_get_x(screen), 0);
  lv_anim_set_duration(&a, 200);
  lv_anim_set_path_cb(&a, lv_anim_path_ease_out);
  lv_anim_start(&a);
}

static void slide_off_done(lv_anim_t *a) {
  swipe_ctx_t *ctx = lv_anim_get_user_data(a);
  lv_obj_set_x(ctx->screen, 0);
  if (ctx->back_cb)
    ctx->back_cb();
}

static void slide_off(swipe_ctx_t *ctx) {
  lv_anim_t a;
  lv_anim_init(&a);
  lv_anim_set_var(&a, ctx->screen);
  lv_anim_set_exec_cb(&a, anim_x_cb);
  lv_anim_set_values(&a, lv_obj_get_x(ctx->screen), theme_screen_width());
  lv_anim_set_duration(&a, 150);
  lv_anim_set_path_cb(&a, lv_anim_path_ease_in);
  lv_anim_set_user_data(&a, ctx);
  lv_anim_set_completed_cb(&a, slide_off_done);
  lv_anim_start(&a);
}

static void pressing_cb(lv_event_t *e) {
  swipe_ctx_t *ctx = lv_event_get_user_data(e);
  lv_indev_t *indev = lv_indev_active();
  if (!indev)
    return;
  lv_point_t pt;
  lv_indev_get_point(indev, &pt);
  if (!ctx->active) {
    if (pt.x > theme_screen_width() / 5)
      return; // 20% edge zone
    ctx->active = true;
    ctx->start_x = pt.x;
  }
  int32_t delta = pt.x - ctx->start_x;
  if (delta < 0)
    delta = 0;
  lv_obj_set_x(ctx->screen, delta * FOLLOW_RATIO / 100);
}

static void released_cb(lv_event_t *e) {
  swipe_ctx_t *ctx = lv_event_get_user_data(e);
  if (!ctx->active)
    return;
  ctx->active = false;
  int32_t cur_x = lv_obj_get_x(ctx->screen);
  int32_t threshold = theme_screen_width() * COMMIT_RATIO / 100;
  if (cur_x >= threshold)
    slide_off(ctx);
  else
    snap_back(ctx->screen);
}

static void delete_cb(lv_event_t *e) { free(lv_event_get_user_data(e)); }

void swipe_back_attach(lv_obj_t *screen, void (*back_cb)(void)) {
  if (!screen || !back_cb)
    return;
  swipe_ctx_t *ctx = malloc(sizeof(swipe_ctx_t));
  if (!ctx)
    return;
  ctx->screen = screen;
  ctx->back_cb = back_cb;
  ctx->active = false;
  ctx->start_x = 0;
  lv_obj_add_flag(screen, LV_OBJ_FLAG_CLICKABLE);
  lv_obj_add_event_cb(screen, pressing_cb, LV_EVENT_PRESSING, ctx);
  lv_obj_add_event_cb(screen, released_cb, LV_EVENT_RELEASED, ctx);
  lv_obj_add_event_cb(screen, delete_cb, LV_EVENT_DELETE, ctx);
}
