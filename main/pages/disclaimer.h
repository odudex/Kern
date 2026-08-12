// Research-and-development disclaimer, acknowledged once per firmware version

#ifndef DISCLAIMER_H
#define DISCLAIMER_H

typedef void (*disclaimer_done_cb)(void);

/* Show the disclaimer and run `done` once it is acknowledged. Already
   acknowledged for the running version: `done` runs straight away. */
void disclaimer_gate(disclaimer_done_cb done);

#endif // DISCLAIMER_H
