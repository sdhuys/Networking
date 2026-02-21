#include "hash.h"

static uint64_t table_key[2];
static uint64_t cookie_key[2];

void hash_init(void)
{
	if (getrandom(table_key, sizeof(table_key), 0) != sizeof(table_key))
		abort();

	if (getrandom(cookie_key, sizeof(cookie_key), 0) != sizeof(cookie_key))
		abort();
}
/* ---------------- SipHash-2-4 ---------------- */

static inline uint64_t rotl64(uint64_t x, int b)
{
	return (x << b) | (x >> (64 - b));
}

/* Endian-safe, alignment-safe */
static inline uint64_t load_le64(const unsigned char *p)
{
	return ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
	       ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
	       ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

#define SIPROUND()                                                                                 \
	do {                                                                                       \
		v0 += v1;                                                                          \
		v1 = rotl64(v1, 13);                                                               \
		v1 ^= v0;                                                                          \
		v0 = rotl64(v0, 32);                                                               \
		v2 += v3;                                                                          \
		v3 = rotl64(v3, 16);                                                               \
		v3 ^= v2;                                                                          \
		v0 += v3;                                                                          \
		v3 = rotl64(v3, 21);                                                               \
		v3 ^= v0;                                                                          \
		v2 += v1;                                                                          \
		v1 = rotl64(v1, 17);                                                               \
		v1 ^= v2;                                                                          \
		v2 = rotl64(v2, 32);                                                               \
	} while (0)

static uint64_t siphash24(const unsigned char *in, size_t len, const uint64_t key[2])
{
	uint64_t v0 = 0x736f6d6570736575ULL ^ key[0];
	uint64_t v1 = 0x646f72616e646f6dULL ^ key[1];
	uint64_t v2 = 0x6c7967656e657261ULL ^ key[0];
	uint64_t v3 = 0x7465646279746573ULL ^ key[1];

	const unsigned char *end = in + (len & ~7);
	uint64_t m;
	uint64_t b = (uint64_t)len << 56;

	for (; in != end; in += 8) {
		m = load_le64(in);
		v3 ^= m;
		SIPROUND();
		SIPROUND();
		v0 ^= m;
	}

	m = b;
	switch (len & 7) {
	case 7:
		m |= (uint64_t)in[6] << 48;
		// fallthrough
	case 6:
		m |= (uint64_t)in[5] << 40;
		// fallthrough
	case 5:
		m |= (uint64_t)in[4] << 32;
		// fallthrough
	case 4:
		m |= (uint64_t)in[3] << 24;
		// fallthrough
	case 3:
		m |= (uint64_t)in[2] << 16;
		// fallthrough
	case 2:
		m |= (uint64_t)in[1] << 8;
		// fallthrough
	case 1:
		m |= (uint64_t)in[0];
	}

	v3 ^= m;
	SIPROUND();
	SIPROUND();
	v0 ^= m;

	v2 ^= 0xff;
	SIPROUND();
	SIPROUND();
	SIPROUND();
	SIPROUND();

	return v0 ^ v1 ^ v2 ^ v3;
}

// -----  public --------
uint32_t hash_table(const void *data, size_t len)
{
	uint64_t h = siphash24(data, len, table_key);
	return (uint32_t)(h ^ (h >> 32));
}

uint32_t hash_syncookie(const void *data, size_t len, uint64_t time)
{
	unsigned char buf[16];
	if (len + sizeof(time) > sizeof(buf))
		abort();

	memcpy(buf, data, len);
	memcpy(buf + len, &time, sizeof(time));

	uint64_t h = siphash24(buf, len + sizeof(time), cookie_key);
	return (uint32_t)(h ^ (h >> 32));
}
