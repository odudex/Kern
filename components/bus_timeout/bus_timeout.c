#include "bus_timeout.h"

#include "sdkconfig.h"

#if CONFIG_ESP32P4_REV_MIN_FULL >= 300
#include "soc/hp_system_reg.h"
#include "soc/soc.h"
#endif

// ESP32-P4 v3.x can hold a core load or store on the PSRAM path for longer than
// the bus timeout (65535 cycles, the register maximum). The access would
// complete, but the timeout turns it into an access fault. Bus errors are
// asynchronous on this core, so the fault cannot be retried. The timeout stays
// on until the scheduler runs: a deadlock while FreeRTOS creates the main task
// never resolves, and there the timeout's panic reboots in about a second,
// while a hang waits about 10 s for the interrupt watchdog's startup timeout.
void bus_timeout_disable(void) {
#if CONFIG_ESP32P4_REV_MIN_FULL >= 300
  REG_CLR_BIT(HP_SYSTEM_CORE_DBUS_TIMEOUT_REG, HP_SYSTEM_CORE_DBUS_TIMEOUT_EN);
  REG_CLR_BIT(HP_SYSTEM_CORE_IBUS_TIMEOUT_REG, HP_SYSTEM_CORE_IBUS_TIMEOUT_EN);
#endif
}
