#include <stdio.h>
#include <stdint.h>
#include <memory.h>
#include <string.h>
#include "sha256.h"

int print_hex(char *tips, uint8_t *hex, int size)
{
	int i = 0;
	printf("%s: ", tips);
	for (; i < size; i++)
	{
		printf("%.2x", hex[i]);
	}
	printf("\n");
}

int test_base_op()
{
	int i = 0;
	uint32_t num[10] = {0};
	uint32_t num1 = 0x12345678;

	num[i++] = ROTLEFT(num1, 4);
	num[i++] = ROTLEFT(num1, 8);
	num[i++] = ROTLEFT(num1, 12);
	num[i++] = ROTLEFT(num1, 16);
	num[i++] = ROTLEFT(num1, 24);

	num[i++] = ROTRIGHT(num1, 4);
	num[i++] = ROTRIGHT(num1, 8);
	num[i++] = ROTRIGHT(num1, 12);
	num[i++] = ROTRIGHT(num1, 16);
	num[i++] = ROTRIGHT(num1, 24);
}

int sha256_test1()
{
	uint8_t text1[] = {"abc"};
	uint8_t hash1[SHA256_BLOCK_SIZE] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
										0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
	uint8_t buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	int pass = 1;
	int tmp = 0;
	tmp = sizeof(ctx.bitlen);
	sha256_init(&ctx);
	sha256_update(&ctx, text1, strlen(text1));
	sha256_final(&ctx, buf);
	print_hex("text1", buf, SHA256_BLOCK_SIZE);
	pass = pass && !memcmp(hash1, buf, SHA256_BLOCK_SIZE);
}

int sha256_test()
{
	uint8_t text2[] = {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
	uint8_t text3[] = {"aaaaaaaaaa"};
	uint8_t hash2[SHA256_BLOCK_SIZE] = {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
										0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1};
	uint8_t hash3[SHA256_BLOCK_SIZE] = {0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
										0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0};
	uint8_t buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	int idx;
	int pass = 1;
	sha256_init(&ctx);
	sha256_update(&ctx, text2, strlen(text2));
	sha256_final(&ctx, buf);
	print_hex("text2", buf, SHA256_BLOCK_SIZE);
	pass = pass && !memcmp(hash2, buf, SHA256_BLOCK_SIZE);

	sha256_init(&ctx);
	sha256_update(&ctx, text3, strlen(text3));
	sha256_final(&ctx, buf);
	print_hex("text3", buf, SHA256_BLOCK_SIZE);
	pass = pass && !memcmp(hash3, buf, SHA256_BLOCK_SIZE);

	return (pass);
}

void test_data_type(void)
{
	int i = 0;
	int len[4];
	len[i++] = sizeof(int);
	len[i++] = sizeof(uint8_t);
	len[i++] = sizeof(uint32_t);
	i++;
}

/*测试uint32数据的自增和溢出*/
void test_uint32(void)
{
	uint32_t num1 = 0x11111111;
	uint32_t num2 = 0xffffffff;
	SHA256_CTX ctx;

	num1++;
	num1++;
	num1++;
	num1++;

	num2++;
	num2++;
	num2++;
	num2++;

	ctx.state[0] = 0x6a09e667;
	ctx.state[1] = 0xbb67ae85;
	ctx.state[2] = 0x3c6ef372;
	ctx.state[3] = 0xa54ff53a;
	ctx.state[4] = 0x510e527f;
	ctx.state[5] = 0x9b05688c;
	ctx.state[6] = 0x1f83d9ab;
	ctx.state[7] = 0x5be0cd19;

	ctx.state[0] += ctx.state[0];
	ctx.state[1] += ctx.state[1];
	ctx.state[2] += ctx.state[2];
	ctx.state[3] += ctx.state[3];
	ctx.state[4] += ctx.state[4];
	ctx.state[5] += ctx.state[5];
	ctx.state[6] += ctx.state[6];
	ctx.state[7] += ctx.state[7];
}

int main()
{
	test_data_type();
	test_uint32();
	test_base_op();
	sha256_test1();
	sha256_test();
	return (0);
}
