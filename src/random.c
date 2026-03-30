#include <inttypes.h>
#include <stdbool.h>
#include <sys/random.h>
#include <stdio.h>

bool chance(uint8_t prob)
{
	prob = prob > 100 ? 100 : prob;

	uint8_t random_byte;
	if (getrandom(&random_byte, sizeof(random_byte), 0) < 0)
		return false;

	if (random_byte < (255 * (prob / (float)100)))
		return true;

	return false;
}
