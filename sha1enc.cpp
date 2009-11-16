#include <stdio.h>
#include <string.h>
#include "libsha1.h"


#ifdef __RENESAS_VERSION__
extern "C" {
void abort() {}
void write() {}
void read() {}
void lseek() {}
void close(int i) {}
int open(char *f) {
	return 0;
}
void *sbrk(int cnt) {
	return 0;
}
}
#endif

#include <vector>

#ifndef __RENESAS_VERSION__
using namespace std;
#endif

static long file_length(FILE *fin)
{
	fseek(fin, 0L, SEEK_END);
	long pos = ftell(fin);
	rewind(fin);
	return pos;
}

static void printhash(uint32_t *hash, int size)
{
	for (int i = 0; i < size; ++i) {
		printf("%08x", hash[i]);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		return -1;
	}
	FILE *fin = fopen(argv[1], "rb");
	if (!fin) {
		return -1;
	}
	long len = file_length(fin);
	vector<byte_t> input(len);
	size_t actual_len = fread(&input[0], 1, len, fin);
	uint32_t hash[8];
	sha256enc(&input[0], len, (byte_t *)hash);
	printhash(hash, 8);
	fclose(fin);
	return 0;
}
