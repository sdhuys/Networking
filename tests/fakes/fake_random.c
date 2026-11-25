// Test replacement for src/random.c. chance() is only used by send_tcp_down to drop
// outgoing segments on purpose. Tests and the interop peer control the drop rate here
// (default 0) instead of the hard-coded 5%, so losses happen where the test puts them.

#include "fake_env.h"
#include "random.h"
#include <stdatomic.h>
#include <stdlib.h>

static _Atomic uint8_t drop_percent = 0;
static _Atomic uint32_t rng_state = 0x12345678u;

void fake_set_drop_percent(uint8_t percent)
{
	atomic_store(&drop_percent, percent > 100 ? 100 : percent);
}

void fake_drop_percent_from_env(void)
{
	const char *v = getenv("STACK_DROP_PCT");
	if (v)
		fake_set_drop_percent((uint8_t)atoi(v));
}

static uint32_t next_random(void)
{
	// xorshift32: deterministic for a given sequence of calls
	uint32_t x = atomic_load(&rng_state);
	uint32_t n;
	do {
		n = x;
		n ^= n << 13;
		n ^= n >> 17;
		n ^= n << 5;
	} while (!atomic_compare_exchange_weak(&rng_state, &x, n));
	return n;
}

bool chance(uint8_t prob)
{
	(void)prob; // the stack's own rate is ignored
	uint8_t p = atomic_load(&drop_percent);
	if (p == 0)
		return false;
	return (next_random() % 100) < p;
}
