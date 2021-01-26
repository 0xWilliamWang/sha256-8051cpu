#include "sha256.h"
#include "stdint.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
/*for debug*/
void print_hex_uint8(char* tips, uint8_t* hex, uint32_t len) {
    uint32_t i = 0;
    printf("%s: ", tips);
    for (; i < len; i++) {
        printf("0x%.2x,", hex[i]);
    }
    printf("\n");
}

/*for debug*/
void print_hex_uint32(char* tips, uint32_t* hex, uint32_t len) {
    uint32_t i = 0;
    printf("%s: ", tips);
    for (; i < len; i++) {
        printf("0x%.8x,", hex[i]);
    }
    printf("\n");
}

void test_base_op() {
    int i = 0;
    uint32_t num[10] = {0};
    uint32_t num1 = 0x12345678;
    uint32_t num2 = 0x12328678;
    uint32_t num3 = 0x28678678;
    /*     CH       */
    num[i++] = CH(num1, num2, num3);
    assert(num[0] == 0x3A738678);

    /*     MAJ       */
    i = 0;
    num[i++] = MAJ(num1, num2, num3);
    assert(num[0] == 0x12368678);

    /*     DBL_INT_ADD       */
    i = 0;
    DBL_INT_ADD(num[0], num2, num3);
    assert(num[0] == 0x3A9E0CF0);

    /*     EPx       */
    i = 0;
    num[i++] = EP0(num1);
    num[i++] = EP0(num2);
    num[i++] = EP0(num3);
    num[i++] = EP1(num1);
    num[i++] = EP1(num2);
    num[i++] = EP1(num3);

    i = 0;
    assert(num[i++] == 0x66146474);
    assert(num[i++] == 0xfd55d042);
    assert(num[i++] == 0xa7c14203);
    assert(num[i++] == 0x3561abda);
    assert(num[i++] == 0x3609b040);
    assert(num[i++] == 0x1c67aefd);

    /*     SIGx       */
    i = 0;
    num[i++] = SIG0(num1);
    num[i++] = SIG0(num2);
    num[i++] = SIG0(num3);
    num[i++] = SIG1(num1);
    num[i++] = SIG1(num2);
    num[i++] = SIG1(num3);

    i = 0;
    assert(num[i++] == 0xe7fce6ee);
    assert(num[i++] == 0x53fc314f);
    assert(num[i++] == 0x14c235da);
    assert(num[i++] == 0xa1f78649);
    assert(num[i++] == 0x13f787fe);
    assert(num[i++] == 0x33f908de);

    /*     ROTATE       */
    i = 0;
    num[i++] = ROTLEFT(num1, 4);
    num[i++] = ROTLEFT(num1, 8);
    num[i++] = ROTLEFT(num1, 12);
    num[i++] = ROTLEFT(num1, 16);
    num[i++] = ROTLEFT(num1, 24);

    assert(num[0] == 0x23456781);
    assert(num[1] == 0x34567812);
    assert(num[2] == 0x45678123);
    assert(num[3] == 0x56781234);
    assert(num[4] == 0x78123456);

    num[i++] = ROTRIGHT(num1, 4);
    num[i++] = ROTRIGHT(num1, 8);
    num[i++] = ROTRIGHT(num1, 12);
    num[i++] = ROTRIGHT(num1, 16);
    num[i++] = ROTRIGHT(num1, 24);

    assert(num[5 + 0] == 0x81234567);
    assert(num[5 + 1] == 0x78123456);
    assert(num[5 + 2] == 0x67812345);
    assert(num[5 + 3] == 0x56781234);
    assert(num[5 + 4] == 0x34567812);
}

void sha256_test1() {
    uint8_t t = 0;
    uint8_t text1[] = {"abc"};
    uint8_t hash1[SHA256_BLOCK_SIZE] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                                        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    uint8_t buf[SHA256_BLOCK_SIZE];

    uint32_t ctx_state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t ctx_block[64] = {
        0x80, 0x03, 0x00, 0x00, 0x80, 0x03, 0x00, 0x00,
        0x80, 0x03, 0x00, 0x00, 0x80, 0x03, 0x00, 0x00,
        0x80, 0x03, 0x00, 0x00, 0x80, 0x03, 0x00, 0x00,
        0x80, 0x03, 0x00, 0x00, 0x80, 0x03, 0x00, 0x00,
        0x80, 0x03, 0x00, 0x00, 0x80, 0x03, 0x00, 0x00,
        0x80, 0x03, 0x00, 0x00, 0x80, 0x03, 0x00, 0x00,
        0x80, 0x03, 0x00, 0x00, 0x80, 0x03, 0x00, 0x00,
        0x80, 0x03, 0x00, 0x00, 0x80, 0x03, 0x00, 0x00};

    SHA256_CTX ctx;
    sha256_init(&ctx);
    assert(memcmp(ctx_state, ctx.state, sizeof(ctx_state)) == 0);
    assert(ctx.datalen == 0);
    assert(ctx.bitlen[0] == 0);
    assert(ctx.bitlen[1] == 0);

    sha256_update(&ctx, text1, strlen(text1));
    assert(memcmp(ctx_state, ctx.state, sizeof(ctx_state)) == 0);

    sha256_final(&ctx, buf);
    assert(memcmp(hash1, buf, SHA256_BLOCK_SIZE) == 0);
}

void sha256_test() {
    uint8_t text2[] = {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
    uint8_t text3[] = {"aaaaaaaaaa"};
    uint8_t hash2[SHA256_BLOCK_SIZE] = {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
                                        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                                        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
                                        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1};
    uint8_t hash3[SHA256_BLOCK_SIZE] = {0xbf, 0x2c, 0xb5, 0x8a, 0x68, 0xf6, 0x84, 0xd9,
                                        0x5a, 0x3b, 0x78, 0xef, 0x8f, 0x66, 0x1c, 0x9a,
                                        0x4e, 0x5b, 0x09, 0xe8, 0x2c, 0xc8, 0xf9, 0xcc,
                                        0x88, 0xcc, 0xe9, 0x05, 0x28, 0xca, 0xeb, 0x27};

    uint8_t buf[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    int pass = 1;
    sha256_init(&ctx);
    sha256_update(&ctx, text2, strlen(text2));
    sha256_final(&ctx, buf);
    assert(memcmp(hash2, buf, SHA256_BLOCK_SIZE) == 0);

    sha256_init(&ctx);
    sha256_update(&ctx, text3, strlen(text3));
    sha256_final(&ctx, buf);
    assert(memcmp(hash3, buf, SHA256_BLOCK_SIZE) == 0);
}

void test_data_type(void) {
    assert(sizeof(uint8_t) == 1);
    assert(sizeof(uint32_t) == 4);
}

int main() {
    test_data_type();
    test_base_op();
    sha256_test1();
    sha256_test();
#ifndef __C51__
    printf("test passed!\n");
#endif
    return 0;
}
