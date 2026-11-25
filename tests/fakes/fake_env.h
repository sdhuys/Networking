#pragma once
// Controls for the link-time replacements of src/time_now.c and src/random.c.
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// fake_time.c (unit tests only)
uint64_t fake_clock_ms(void);
void fake_clock_advance(uint64_t ms);

// fake_random.c (all test builds): percentage of outgoing TCP segments the stack drops
void fake_set_drop_percent(uint8_t percent);
void fake_drop_percent_from_env(void); // reads STACK_DROP_PCT

#ifdef __cplusplus
}
#endif
