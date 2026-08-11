// Research-and-development disclaimer, acknowledged once per firmware version

#include "disclaimer.h"
#include "../core/settings.h"
#include "../project.h"
#include "../ui/dialog.h"
#include <esp_app_desc.h>

#define DISCLAIMER_TITLE PROJECT_NAME " is R&D"

#define DISCLAIMER_TEXT                                                        \
  "This is a research and development project, not a product.\n\n"             \
  "It exists to explore new hardware and Bitcoin self-custody ideas.\n\n"      \
  "The firmware is unaudited. Testnet is what it is built for. Any mainnet "   \
  "use is entirely at your own risk, and no security guarantees are made."

static disclaimer_done_cb done_callback = NULL;

static void acknowledged_cb(void *user_data) {
  (void)user_data;
  settings_acknowledge_disclaimer(esp_app_get_description()->version);
  if (done_callback)
    done_callback();
}

void disclaimer_gate(disclaimer_done_cb done) {
  done_callback = done;

  if (settings_disclaimer_acknowledged(esp_app_get_description()->version)) {
    if (done)
      done();
    return;
  }

  dialog_show_acknowledge(DISCLAIMER_TITLE, DISCLAIMER_TEXT, "I understand",
                          acknowledged_cb, NULL, DIALOG_STYLE_FULLSCREEN);
}
