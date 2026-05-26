#ifndef SETTINGS_ROW_H
#define SETTINGS_ROW_H

#include <lvgl.h>
#include <stdbool.h>
#include <stdint.h>

/* Settings-page rows.
 *
 * - `settings_row_toggle` and `settings_row_dropdown` produce a
 *   `[Label] [Item] [?]` row; the trailing help button opens a modal
 *   showing `help_title` + `help_msg` (via dialog_show_info). The
 *   widget is stored on the row's user_data for `settings_row_get_widget()`.
 * - `settings_row_action` produces a full-width button labelled `label`;
 *   tapping it fires `on_click` (intended for sub-page navigation).
 *
 * `help_title` and `help_msg` must be statically allocated (string
 * literals) — they are stored by reference, not copied. */

lv_obj_t *settings_row_toggle(lv_obj_t *parent, const char *label, bool initial,
                              lv_event_cb_t on_change, const char *help_title,
                              const char *help_msg);

lv_obj_t *settings_row_dropdown(lv_obj_t *parent, const char *label,
                                const char *options, uint16_t selected,
                                lv_event_cb_t on_change, const char *help_title,
                                const char *help_msg);

lv_obj_t *settings_row_action(lv_obj_t *parent, const char *label,
                              lv_event_cb_t on_click);

/* Retrieve the toggle/dropdown widget embedded in a row created by
 * `settings_row_toggle` or `settings_row_dropdown`. Returns NULL for
 * action rows. */
lv_obj_t *settings_row_get_widget(lv_obj_t *row);

#endif /* SETTINGS_ROW_H */
