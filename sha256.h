#ifndef SHA256_H
#define SHA256_H

#include "stdint.h"

#define SHA256_BLOCK_SIZE 32

typedef struct {
    uint8_t block[64];
    uint32_t datalen;
    uint32_t bitlen[2];
    uint32_t state[8];
} SHA256_CTX;

/* DBL_INT_ADD treats two unsigned ints a and b as one 64-bit integer and adds c to it */
#define DBL_INT_ADD(a, b, c)  \
    if (a > 0xffffffff - (c)) \
        ++b;                  \
    a += c;
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx, uint8_t block[], uint32_t len);
void sha256_final(SHA256_CTX* ctx, uint8_t hash[]);

#endif
