#include <stdio.h>
#include <string.h>
#include "libsha1.h"

const uint32_t hash160[5] = {
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
	0xc3d2e1f0
};

const uint32_t k160[4] = {
	0x5a827999,
	0x6ed9eba1,
	0x8f1bbcdc,
	0xca62c1d6
};

template <int N, typename T>
static inline T ROTL(T x)
{
	return (x << N) | (x >> (sizeof(x) * 8 - N));
}

template <int N, typename T>
static inline T ROTR(T x)
{
	return (x << (sizeof(x) * 8 - N)) | (x >> N);
}

template <typename T>
struct Ch {
	T operator() (T x, T y, T z) {
		return (x & y) ^ (~x & z);
	}
};

template <typename T>
struct Parity {
	T operator() (T x, T y, T z) {
		return x ^ y ^ z;
	}
};

template <typename T>
struct Maj {
	T operator() (T x, T y, T z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}
};


#if defined(__RENESAS_VERSION__) && (defined(_SH4ALDSP) || defined(_SH4A))
#include <umachine.h>
#define bswap_32(a) end_cnvl(a)
#elif defined(__GNUC__) && defined(__sh__) /* SuperH */
static inline uint32_t bswap_32(uint32_t a) {
	__asm__(
		"swap.b %0,%0\n\t"
		"swap.w %0,%0\n\t"
		"swap.b %0,%0\n\t"
		: "=r" (a) : "0" (a) );
	return a;
}
#elif defined(__i386__)
	static inline unsigned int bswap_32(uint32_t a) {
		__asm__( "bswap %0" : "=r" (a) : "0" (a) );
		return a;
	}
#else

	#define bswap_32(a) ( ( (a) << 24 ) | ( ( (a) & 0xff00 ) << 8 ) | ( ( (a) >> 8 ) & 0xff00 ) | ( ( (a) >> 24 ) & 0xff ) )
#endif


#ifdef WORDS_BIGENDIAN
#define memcopy_byteorder16(a, b) memcpy(a, b, sizeof(a[0]) * 16)
#else
static void memcopy_byteorder16(uint32_t *dst, const byte_t *src)
{
	const uint32_t *src32 = (const uint32_t *)src;
	int i = 16 / 2;
	do {
		dst[0] = bswap_32(*src32++);
		dst[1] = bswap_32(*src32++);
		dst += 2;
	} while (--i);
}
#endif

static void expand_w(uint32_t *wt, const byte_t *input)
{
	uint32_t *w = wt;
	uint32_t *w_out = wt + 16;
	int i = 4;
	memcopy_byteorder16(wt, input);
	do {
		int j = 16 / 2;
		do {
			w_out[0] = ROTL<1>(w[0] ^ w[2] ^ w[8] ^ w[13]);
			w_out[1] = ROTL<1>(w[1] ^ w[3] ^ w[9] ^ w[14]);
			w_out += 2;
			w += 2;
		} while (--j);
	} while (--i);
}

template <typename FT>
static inline void sha1_core(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d, uint32_t& e, uint32_t k, uint32_t *w, FT func)
{
	int i = 20;
	do {
		int t = ROTL<5>(a) + func(b, c, d) + e + k + *w++;
		e = d;
		d = c;
		c = ROTR<2>(b);
		b = a;
		a = t;
	} while (--i);
}

void proc_block(uint32_t *hash, const byte_t *input)
{
	uint32_t a, b, c, d, e;
	uint32_t wt[80];

	expand_w(wt, input);
	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];

	sha1_core(a, b, c, d, e, k160[0], wt, Ch<uint32_t>());
	sha1_core(a, b, c, d, e, k160[1], wt + 20, Parity<uint32_t>());
	sha1_core(a, b, c, d, e, k160[2], wt + 40, Maj<uint32_t>());
	sha1_core(a, b, c, d, e, k160[3], wt + 60, Parity<uint32_t>());

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
}

void write_bitlen(byte_t *dst, uint64_t len)
{
	dst[0] = len >> 56;
	dst[1] = len >> 48;
	dst[2] = len >> 40;
	dst[3] = len >> 32;
	dst[4] = len >> 24;
	dst[5] = len >> 16;
	dst[6] = len >> 8;
	dst[7] = len;
}

static void proc_last_block(const byte_t *input, size_t input_bytes, uint64_t bits64, uint32_t *hash)
{
	uint32_t last_block[16];
	memcpy(last_block, input, input_bytes);
	((byte_t *)last_block)[input_bytes] = 0x80;
	memset((byte_t *)last_block + input_bytes + 1, 0, 63 - input_bytes);
	if (input_bytes < 56) {
		write_bitlen((byte_t *)last_block + 56, bits64);
	}
	proc_block(hash, (byte_t *)last_block);
	if (56 <= input_bytes) {
		memset((byte_t *)last_block, 0, 56);
		write_bitlen((byte_t *)last_block + 56, bits64);
		proc_block(hash, (byte_t *)last_block);
	}
}

int sha1enc(const byte_t *input, size_t input_bytes, byte_t *output)
{
	uint32_t hash[5];
	uint64_t bits64 = input_bytes * 8;
	int blocks = input_bytes >> 6;
	memcpy(hash, hash160, sizeof(hash160));
	if (blocks != 0) {
		proc_block(hash, &input[0]);
		for (int i = 1; i < blocks; ++i) {
			proc_block(hash, &input[i * 64]);
		}
	}
	proc_last_block(&input[blocks * 64], input_bytes - blocks * 64, bits64, hash);
	memcpy(output, hash, sizeof(hash));
	return 0;
}
