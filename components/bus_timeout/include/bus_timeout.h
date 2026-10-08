#pragma once

// Disables the HP core bus timeout on ESP32-P4 v3.x; a no-op on earlier
// revisions. Call once the scheduler is running.
void bus_timeout_disable(void);
