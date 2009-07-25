#ifndef _LIBSHA1_H_
#define _LIBSHA1_H_
#ifdef __GNUC__
#include <stdint.h>
#else
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#endif

typedef unsigned char byte_t;
int sha1enc(const byte_t *input, size_t input_bytes, byte_t *output);

#endif /* #ifndef _LIBSHA1_H_ */
