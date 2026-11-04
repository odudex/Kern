/*
 * Self Test page: runs core/self_test's known-answer checks on a worker task
 * (kef_encrypt pattern: an LVGL timer polls for completion) and lists each
 * result.
 */

#include "self_test_page.h"
#include "../../core/self_test.h"
#include "../../ui/input_helpers.h"
#include "../../ui/oneshot.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/session_cleanup.h"
#include "../../utils/worker_task.h"

#define SELF_TEST_STACK_SIZE 16384
#define MAX_CHECKS 16

static void (*return_callback)(void) = NULL;
static lv_obj_t *screen = NULL;
static lv_obj_t *body = NULL;
static lv_obj_t *status_label = NULL;
static lv_timer_t *poll_timer = NULL;
static ui_oneshot_t rerun;

static self_test_result_t results[MAX_CHECKS];
static volatile size_t progress;
static volatile bool done;
static bool running;

static void start_run(void);

static void run_work(void) { self_test_run_all(results, &progress); }

static size_t check_count(void) {
  size_t count = self_test_count();
  return count < MAX_CHECKS ? count : MAX_CHECKS;
}

static lv_obj_t *small_label(lv_obj_t *parent, const char *text,
                             bool secondary) {
  lv_obj_t *label = theme_create_label(parent, text, secondary);
  lv_obj_set_style_text_font(label, theme_font_small(), 0);
  return label;
}

static void add_result_row(const self_test_result_t *r) {
  lv_obj_t *row = theme_create_flex_row(body);
  lv_obj_set_width(row, LV_PCT(100));
  lv_obj_set_style_pad_column(row, theme_small_padding(), 0);

  lv_obj_t *name = small_label(row, r->name, false);
  lv_obj_set_flex_grow(name, 1);
  lv_label_set_long_mode(name, LV_LABEL_LONG_WRAP);

  if (!r->skipped)
    lv_label_set_text_fmt(small_label(row, "", true), "%u ms", (unsigned)r->ms);
  lv_obj_t *verdict = small_label(row,
                                  r->skipped  ? "N/A"
                                  : r->passed ? "PASS"
                                              : "FAIL",
                                  r->skipped);
  if (!r->skipped)
    lv_obj_set_style_text_color(verdict,
                                r->passed ? good_color() : error_color(), 0);
}

static void rerun_cb(lv_timer_t *timer) {
  (void)timer;
  start_run();
}

/* Deferred: starting over deletes this button. */
static void run_again_cb(lv_event_t *e) {
  (void)e;
  ui_oneshot_start(&rerun, rerun_cb, 0);
}

static void show_results(void) {
  size_t count = check_count(), failed = 0;
  for (size_t i = 0; i < count; i++)
    failed += !results[i].passed && !results[i].skipped;

  lv_obj_clean(body);
  status_label = NULL;
  lv_obj_t *summary = theme_create_label(body, "", false);
  if (failed) {
    lv_label_set_text_fmt(summary, "%u of %u checks failed", (unsigned)failed,
                          (unsigned)count);
    lv_obj_set_style_text_color(summary, error_color(), 0);
    lv_obj_t *advice =
        small_label(body, "Do not use this device to sign.", true);
    lv_obj_set_width(advice, LV_PCT(100));
    lv_label_set_long_mode(advice, LV_LABEL_LONG_WRAP);
  } else {
    lv_label_set_text(summary, "All checks passed");
    lv_obj_set_style_text_color(summary, good_color(), 0);
  }
  theme_create_separator(body, secondary_color());

  for (size_t i = 0; i < count; i++)
    add_result_row(&results[i]);

  lv_obj_t *again = theme_create_button(body, "Run again", false);
  lv_obj_set_style_margin_top(again, theme_default_padding(), 0);
  lv_obj_add_event_cb(again, run_again_cb, LV_EVENT_CLICKED, NULL);
}

static void poll_cb(lv_timer_t *timer) {
  (void)timer;
  if (!done) {
    if (status_label)
      lv_label_set_text_fmt(status_label, "Running checks... %u of %u",
                            (unsigned)progress, (unsigned)check_count());
    return;
  }
  worker_task_wait();
  running = false;
  lv_timer_del(poll_timer);
  poll_timer = NULL;
  show_results();
}

static void start_run(void) {
  if (running || !body)
    return;
  lv_obj_clean(body);
  status_label = theme_create_label(body, "Running checks...", true);

  progress = 0;
  done = false;
  if (self_test_count() > MAX_CHECKS ||
      !worker_task_start("self_test", SELF_TEST_STACK_SIZE, run_work, &done)) {
    lv_label_set_text(status_label, "Could not start the checks");
    return;
  }
  running = true;
  poll_timer = lv_timer_create(poll_cb, 100, NULL);
}

static void back_cb(lv_event_t *e) {
  (void)e;
  if (return_callback)
    return_callback();
}

void self_test_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  session_cleanup_register(self_test_page_destroy);
  return_callback = return_cb;

  screen = theme_create_page_container(parent);
  ui_create_back_button(screen, back_cb);
  theme_create_page_title(screen, "Self Test");

  int32_t top_h = theme_corner_button_height() + theme_default_padding();
  body = theme_create_page_container(screen);
  lv_obj_set_size(body, LV_PCT(100), theme_screen_height() - top_h);
  lv_obj_align(body, LV_ALIGN_BOTTOM_MID, 0, 0);
  lv_obj_set_style_pad_all(body, theme_default_padding(), 0);
  lv_obj_set_style_pad_gap(body, theme_small_padding(), 0);
  lv_obj_set_flex_flow(body, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(body, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_add_flag(body, LV_OBJ_FLAG_SCROLLABLE);
  lv_obj_set_scrollbar_mode(body, LV_SCROLLBAR_MODE_AUTO);

  start_run();
}

void self_test_page_show(void) {
  if (screen)
    lv_obj_clear_flag(screen, LV_OBJ_FLAG_HIDDEN);
}

void self_test_page_hide(void) {
  if (screen)
    lv_obj_add_flag(screen, LV_OBJ_FLAG_HIDDEN);
}

void self_test_page_destroy(void) {
  session_cleanup_unregister(self_test_page_destroy);
  ui_oneshot_cancel(&rerun);
  if (running) {
    worker_task_wait();
    running = false;
  }
  if (poll_timer) {
    lv_timer_del(poll_timer);
    poll_timer = NULL;
  }
  if (screen) {
    lv_obj_del(screen);
    screen = NULL;
  }
  body = NULL;
  status_label = NULL;
  return_callback = NULL;
}
