#include "time_now.h"

uint64_t now_ms()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

uint32_t now_ms_32()
{
	return (uint32_t)now_ms();
}

uint64_t now_s()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}