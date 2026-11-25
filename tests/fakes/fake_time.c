// Test replacement for src/time_now.c, linked into the unit tests only.
// Time stands still until a test moves it, so timer behaviour (RTO, delayed ACK,
// zero-window probes, TIME_WAIT) is exact and instant.

#include "fake_env.h"
#include "time_now.h"
#include <stdatomic.h>

// Start well above zero: some code treats 0 as "unset".
static _Atomic uint64_t fake_now_ms = 1000000;

uint64_t now_ms(void)
{
	return atomic_load(&fake_now_ms);
}

uint32_t now_ms_32(void)
{
	return (uint32_t)now_ms();
}

uint64_t now_s(void)
{
	return now_ms() / 1000;
}

uint64_t fake_clock_ms(void)
{
	return atomic_load(&fake_now_ms);
}

void fake_clock_advance(uint64_t ms)
{
	atomic_fetch_add(&fake_now_ms, ms);
}
