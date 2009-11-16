/** Yet Another SHA-1 Encoder
 *  Copyright 2009 Takayuki Minegishi
 *
 *  Permission is hereby granted, free of charge, to any person
 *  obtaining a copy of this software and associated documentation
 *  files (the "Software"), to deal in the Software without
 *  restriction, including without limitation the rights to use, copy,
 *  modify, merge, publish, distribute, sublicense, and/or sell copies
 *  of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be
 *  included in all copies or substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *  HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include "libsha1.h"
#ifdef __RENESAS_VERSION__
#include <umachine.h>
#endif

const uint32_t hash160[5] = {
	0x67452301,
	0xefcdab89,
	0x98badcfe,
	0x10325476,
	0xc3d2e1f0
};

const uint32_t k160[4] = {
	0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
};

const uint32_t hash256[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

const uint32_t k256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTL(N, x) (((x) << (N)) | ((x) >> (sizeof(x) * 8 - (N))))
#define ROTR(N, x) (((x) << (sizeof(x) * 8 - (N))) | ((x) >> N))

#ifdef __RENESAS_VERSION__
#define ROTL1(x) rotl(x)
#define ROTR2(x) rotr(rotr(x))
#else
#define ROTL1(x) ROTL(1, x)
#define ROTR2(x) ROTR(2, x)
#endif

template <typename T>
struct Ch {
	T operator() (T x, T y, T z) {
		return (x & y) ^ (~x & z);
	}
};

template <typename T>
struct Maj {
	T operator() (T x, T y, T z) {
		return (x & y) ^ (x & z) ^ (y & z);
	}
};


struct Parity {
	uint32_t operator() (uint32_t x, uint32_t y, uint32_t z) {
		return x ^ y ^ z;
	}
};


#if defined(__RENESAS_VERSION__)
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
static inline void memcopy_byteorder16(uint32_t *dst, const byte_t *src)
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

static inline void expand_w160(uint32_t *wt, const byte_t *input)
{
	uint32_t *w = wt;
	uint32_t *w_out = wt + 16;
	int i = 4;
	memcopy_byteorder16(wt, input);
	do {
		int j = 16 / 2;
		do {
			w_out[0] = ROTL1(w[0] ^ w[2] ^ w[8] ^ w[13]);
			w_out[1] = ROTL1(w[1] ^ w[3] ^ w[9] ^ w[14]);
			w_out += 2;
			w += 2;
		} while (--j);
	} while (--i);
}

template <typename FT>
static inline void sha1_core(uint32_t& aa, uint32_t& bb, uint32_t& cc, uint32_t& dd, uint32_t& ee, uint32_t k, uint32_t *w, FT func)
{
	uint32_t a = aa;
	uint32_t b = bb;
	uint32_t c = cc;
	uint32_t d = dd;
	uint32_t e = ee;
	int i = 20;
	do {
		int t = ROTL(5, a) + func(b, c, d) + e + k + *w++;
		e = d;
		d = c;
		c = ROTR2(b);
		b = a;
		a = t;
	} while (--i);
	aa = a;
	bb = b;
	cc = c;
	dd = d;
	ee = e;
}

static void proc_block160(uint32_t *hash, const byte_t *input)
{
	uint32_t a, b, c, d, e;
	uint32_t wt[80];

	expand_w160(wt, input);
	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];

	sha1_core(a, b, c, d, e, k160[0], wt, Ch<uint32_t>());
	sha1_core(a, b, c, d, e, k160[1], wt + 20, Parity());
	sha1_core(a, b, c, d, e, k160[2], wt + 40, Maj<uint32_t>());
	sha1_core(a, b, c, d, e, k160[3], wt + 60, Parity());

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
}

static void write_bitlen(byte_t *dst, uint64_t len)
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

static void proc_last_block160(const byte_t *input, size_t input_bytes, uint64_t bits64, uint32_t *hash)
{
	uint32_t last_block[16];
	memcpy(last_block, input, input_bytes);
	((byte_t *)last_block)[input_bytes] = 0x80;
	memset((byte_t *)last_block + input_bytes + 1, 0, 63 - input_bytes);
	if (input_bytes < 56) {
		write_bitlen((byte_t *)last_block + 56, bits64);
	}
	proc_block160(hash, (byte_t *)last_block);
	if (56 <= input_bytes) {
		memset((byte_t *)last_block, 0, 56);
		write_bitlen((byte_t *)last_block + 56, bits64);
		proc_block160(hash, (byte_t *)last_block);
	}
}

int sha1enc(const byte_t *input, size_t input_bytes, byte_t *output)
{
	uint32_t hash[5];
	uint64_t bits64 = input_bytes * 8;
	int blocks = input_bytes >> 6;
	memcpy(hash, hash160, sizeof(hash160));
	if (blocks != 0) {
		proc_block160(hash, &input[0]);
		for (int i = 1; i < blocks; ++i) {
			proc_block160(hash, &input[i * 64]);
		}
	}
	proc_last_block160(&input[blocks * 64], input_bytes - blocks * 64, bits64, hash);
	memcpy(output, hash, sizeof(hash));
	return 0;
}

static inline uint32_t sigma0(uint32_t x)
{
	return ROTR(7, x) ^ ROTR(18, x) ^ (x >> 3);
}

static inline uint32_t sigma1(uint32_t x)
{
	return ROTR(17, x) ^ ROTR(19, x) ^ (x >> 10);
}

static inline uint32_t Sigma0(uint32_t x)
{
	return ROTR2(x) ^ ROTR(13, x) ^ ROTR(22, x);
}

static inline uint32_t Sigma1(uint32_t x)
{
	return ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x);
}

static inline void expand_w256(uint32_t *wt, const byte_t *input)
{
	uint32_t *w = wt;
	uint32_t *w_out = wt + 16;
	int i = 3;
	memcopy_byteorder16(wt, input);
	do {
		int j = 16 / 2;
		do {
			w_out[0] = w[0] + sigma0(w[1]) + w[9] + sigma1(w[14]);
			w_out[1] = w[1] + sigma0(w[2]) + w[10] + sigma1(w[15]);
			w_out += 2;
			w += 2;
		} while (--j);
	} while (--i);
}

static inline void proc_block256(uint32_t *hash, const byte_t *input)
{
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t wt[64];

	expand_w256(wt, input);
	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];
	f = hash[5];
	g = hash[6];
	h = hash[7];
	for (int i = 0; i < 64; ++i) {
		uint32_t t1 = h + Sigma1(e) + Ch<uint32_t>()(e, f, g) + k256[i] + wt[i];
		uint32_t t2 = Sigma0(a) + Maj<uint32_t>()(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
	hash[5] += f;
	hash[6] += g;
	hash[7] += h;
}

static void proc_last_block256(const byte_t *input, size_t input_bytes, uint64_t bits64, uint32_t *hash)
{
	uint32_t last_block[16];
	memcpy(last_block, input, input_bytes);
	((byte_t *)last_block)[input_bytes] = 0x80;
	memset((byte_t *)last_block + input_bytes + 1, 0, 63 - input_bytes);
	if (input_bytes < 56) {
		write_bitlen((byte_t *)last_block + 56, bits64);
	}
	proc_block256(hash, (byte_t *)last_block);
	if (56 <= input_bytes) {
		memset((byte_t *)last_block, 0, 56);
		write_bitlen((byte_t *)last_block + 56, bits64);
		proc_block256(hash, (byte_t *)last_block);
	}
}

int sha256enc(const byte_t *input, size_t input_bytes, byte_t *output)
{
	uint32_t hash[8];
	uint64_t bits64 = input_bytes * 8;
	int blocks = input_bytes >> 6;
	memcpy(hash, hash256, sizeof(hash256));
	if (blocks != 0) {
		proc_block256(hash, &input[0]);
		for (int i = 1; i < blocks; ++i) {
			proc_block256(hash, &input[i * 64]);
		}
	}
	proc_last_block256(&input[blocks * 64], input_bytes - blocks * 64, bits64, hash);
	memcpy(output, hash, sizeof(hash));
	return 0;
}

