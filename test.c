#include "sha256.h"
#include "stdint.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t* msg;
    uint32_t msglen;
    uint8_t hash[SHA256_BLOCK_SIZE];
} vector_t;

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

void test_case() {
    uint8_t hash[SHA256_BLOCK_SIZE];
    uint8_t tmp = 0x01;
    uint8_t tmp1[32] = {0x4b, 0xf5, 0x12, 0x2f, 0x34, 0x45, 0x54, 0xc5,
                        0x3b, 0xde, 0x2e, 0xbb, 0x8c, 0xd2, 0xb7, 0xe3,
                        0xd1, 0x60, 0x0a, 0xd6, 0x31, 0xc3, 0x85, 0xa5,
                        0xd7, 0xcc, 0xe2, 0x3c, 0x77, 0x85, 0x45, 0x9a};
    /*some case from https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2withchangenotice.pdf*/
    vector_t vectors[] = {
        {"abc",
         3,
         {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
          0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
          0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
          0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad}},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         56,
         {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
          0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
          0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
          0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1}},
        {"aaaaaaaaaa",
         10,
         {0xbf, 0x2c, 0xb5, 0x8a, 0x68, 0xf6, 0x84, 0xd9,
          0x5a, 0x3b, 0x78, 0xef, 0x8f, 0x66, 0x1c, 0x9a,
          0x4e, 0x5b, 0x09, 0xe8, 0x2c, 0xc8, 0xf9, 0xcc,
          0x88, 0xcc, 0xe9, 0x05, 0x28, 0xca, 0xeb, 0x27}},
        {&tmp,
         1,
         {0x4b, 0xf5, 0x12, 0x2f, 0x34, 0x45, 0x54, 0xc5,
          0x3b, 0xde, 0x2e, 0xbb, 0x8c, 0xd2, 0xb7, 0xe3,
          0xd1, 0x60, 0x0a, 0xd6, 0x31, 0xc3, 0x85, 0xa5,
          0xd7, 0xcc, 0xe2, 0x3c, 0x77, 0x85, 0x45, 0x9a}},
        {tmp1,
         32,
         {0x9c, 0x12, 0xcf, 0xdc, 0x04, 0xc7, 0x45, 0x84,
          0xd7, 0x87, 0xac, 0x3d, 0x23, 0x77, 0x21, 0x32,
          0xc1, 0x85, 0x24, 0xbc, 0x7a, 0xb2, 0x8d, 0xec,
          0x42, 0x19, 0xb8, 0xfc, 0x5b, 0x42, 0x5f, 0x70}},

    };
    SHA256_CTX ctx;
    uint32_t i = 0;
    uint32_t count = sizeof(vectors) / sizeof(vectors[0]);

    for (i = 0; i < count; i++) {
        sha256_init(&ctx);
        sha256_update(&ctx, vectors[i].msg, vectors[i].msglen);
        sha256_final(&ctx, hash);
        assert(memcmp(vectors[i].hash, hash, SHA256_BLOCK_SIZE) == 0);
    }
}

void test_data_type(void) {
    assert(sizeof(uint8_t) == 1);
    assert(sizeof(uint32_t) == 4);
}

int main() {
    test_data_type();
    test_base_op();
    test_case();
#ifndef __C51__
    printf("test passed!\n");
#endif
    return 0;
}
