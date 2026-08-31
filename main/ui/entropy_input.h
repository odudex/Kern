#ifndef ENTROPY_INPUT_H
#define ENTROPY_INPUT_H

/* Feed LVGL touch events into the core entropy pool. Call once the display is
 * up, holding the LVGL lock - it mutates an input device's callback list while
 * the LVGL task is already running. Lives in the UI layer because core/ must
 * stay free of LVGL. */
void entropy_input_attach(void);

#endif // ENTROPY_INPUT_H
