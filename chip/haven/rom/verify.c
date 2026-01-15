/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hw_sha256.h"
#include "debug_printf.h"
#include "registers.h"
#include "setup.h"
#include "signed_header.h"

#define RSA_NUM_WORDS 96
#define RSA_NUM_BYTES (RSA_NUM_WORDS * 4)

#define RANDOM_STEP 211

static const uint32_t ROMKEY_PROD[RSA_NUM_WORDS + 1] = {
	0xaa66150f, 0xbc21c611, 0xe9414c38, 0x4ef54d7b, 0xdeffc545, 0x44c64800, 
	0x846a62c3, 0xe68e53ad, 0xffa417bc, 0x3650ea97, 0x3495844d, 0xe5bf8121,
	0xa73a4d33, 0x87879cb8, 0x02a2bf1d, 0xa5405e99, 0x2797b56c, 0x1996f5b3,
	0xd3faf121, 0x1fa24e15, 0xfa2f7394, 0x74d74fbe, 0x64dc7135, 0x09515f37,
	0x6e178e71, 0x56131e15, 0xe41d4fb6, 0xd4796936, 0xd6844330, 0xf2ff9620,
	0xda675c5a, 0x1e4a9f65, 0xfc5b5dc3, 0x610d1d60, 0x53de2b0d, 0x397c5d55,
	0xc17335c2, 0xc3197932, 0x263e362f, 0x6ce6845c, 0x207cb68b, 0x8f2d9b7a,
	0x01159df6, 0x1ac71332, 0xf4196157, 0xd77f841b, 0xa963ae78, 0x3fb7ebcb,
	0x2978afcf, 0x53fd760c, 0x1a04bc66, 0xde607225, 0xb42f6037, 0xc90bb767,
	0x18aad9f9, 0x4466acb0, 0x02026e59, 0x3bf73d60, 0xde90d3b6, 0xf9de49ec,
	0xeea005b7, 0x48208abf, 0x4d88d62a, 0xd5ba9528, 0x5c48d13b, 0x2ebc19a9,
	0x1eb28504, 0xb973f7c8, 0xc5786fcb, 0x8b8b3fa4, 0xd3f18bb5, 0x9b698adf,
	0x1c2a6255, 0xdaa82f20, 0x87723863, 0xfb70a0bf, 0x24219128, 0xca84f53c,
	0x2b59a24c, 0xed18e2f7, 0x866bbe00, 0x6901542c, 0xab69c083, 0x9dd77054,
	0xe84fea06, 0xff9dd20e, 0x594c4106, 0x259af98c, 0xcfaca7aa, 0xc1344bd2,
	0x72866917, 0x2868c544, 0xa6c1b0eb, 0xe3d6d826, 0x232a95bd, 0x6e6acc02,
	0x6d7481bf
};

static const uint32_t ROMKEY_DEV[RSA_NUM_WORDS + 1] = {
	0x3716ee6b, 0x662eb1bd, 0x04a99224, 0x41c8ae1e, 0x24f50d57, 0x0c289432, 
	0x55ca6813, 0x419fd28d, 0xa8575143, 0xbe2db276, 0xe5c4b45a, 0x1343dc35,
	0xab407a43, 0x27599036, 0xde226237, 0xa8b79ab3, 0x51651986, 0xcf5647b1,
	0x4ebeb6a9, 0x40425b6f, 0x81df4b88, 0xa56c6429, 0x677dbf7c, 0x8dc65ea3,
	0x088f3764, 0x9816e9e5, 0x57bde914, 0x78f6057e, 0x258af547, 0x99a877d3,
	0xa29726e2, 0xaf43c063, 0x96c3eb80, 0x860a6af8, 0x245ee1de, 0x8f9f2962,
	0xdb974102, 0xd38d20ae, 0x952b0e00, 0x25e6b61a, 0xc9acec09, 0x1c07a4ef,
	0x1ae7c224, 0x4da67bbd, 0xe57456a7, 0xf7ddb8e6, 0xa7f0f23d, 0xc22a42c2,
	0x17ec86eb, 0xdc8c020d, 0xd7160e79, 0x0787bb38, 0x54abb9cd, 0xa120afdf,
	0xbbcdd0d5, 0xad832d36, 0x6fd49734, 0x74da5fef, 0x8e2352de, 0x8af5144a,
	0x04a59ce2, 0x21de5633, 0xe33f8e15, 0x7c40d4e4, 0xee65db93, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000
};

static inline uint32_t bswap(uint32_t a)
{
	uint32_t result;

	__asm__ volatile("rev %0, %1;" : "=r"(result) : "r"(a));

	return result;
}

/* Montgomery c[] += a * b[] / R % key. */
static void montMulAdd(const uint32_t *key,
		       uint32_t *c, const uint32_t a,
		       const uint32_t *b)
{
	register uint64_t tmp;
	uint32_t i, A, B, d0;

	{

		tmp = c[0] + (uint64_t)a * b[0];
		A = tmp >> 32;
		d0 = (uint32_t)tmp * *key++;
		tmp = (uint32_t)tmp + (uint64_t)d0 * *key++;
		B = tmp >> 32;
	}

	for (i = 0; i < RSA_NUM_WORDS - 1; ++i) {
		tmp = A + (uint64_t)a * b[i + 1] + c[i + 1];
		A = tmp >> 32;
		tmp = B + (uint64_t)d0 * *key++ + (uint32_t)tmp;
		c[i] = (uint32_t)tmp;
		B = tmp >> 32;
	}

	c[RSA_NUM_WORDS - 1] = A + B;
}

/* Montgomery c[] = a[] * b[] / R % key. */
static void montMul(const uint32_t *key,
		    uint32_t *c, const uint32_t *a,
		    const uint32_t *b)
{
	int i;

	for (i = 0; i < RSA_NUM_WORDS; ++i)
		c[i] = 0;

	for (i = 0; i < RSA_NUM_WORDS; ++i)
		montMulAdd(key, c, a[i], b);
}

/* Montgomery c[] = a[] * 1 / R % key. */
static void montMul1(const uint32_t *key,
		     uint32_t *c, const uint32_t *a)
{
	int i;

	for (i = 0; i < RSA_NUM_WORDS; ++i)
		c[i] = 0;

	montMulAdd(key, c, 1, a);
	for (i = 1; i < RSA_NUM_WORDS; ++i)
		montMulAdd(key, c, 0, a);
}

/* In-place exponentiation to power 3 % key. */
void modpow3(const uint32_t *key,
		    const uint32_t *signature, uint32_t *out)
{
	static uint32_t aaR[RSA_NUM_WORDS];
	static uint32_t aaaR[RSA_NUM_WORDS];

	montMul(key, aaR, signature, signature);
	montMul(key, aaaR, aaR, signature);
	montMul1(key, out, aaaR);
}

void LOADERKEY_verify(uint32_t key, const uint32_t *signature, 
					const uint32_t *sha256)
{
	static uint32_t buf[RSA_NUM_WORDS] // 0x10668 - 0x107e8
		__attribute__((section(".guarded_data")));
	static uint32_t hash[SHA256_DIGEST_WORDS] // 0x107e8 - 0x10808
		__attribute__((section(".guarded_data")));
	uint32_t offset;
	const uint32_t *pubkey = ROMKEY_PROD;
	int i;


	if (!(GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 8) && key == 0x3716ee6b)
		pubkey = ROMKEY_DEV;

	modpow3(pubkey, signature, buf);

	/* 
	 * We selected the ROM dev key, the key size will 
	 * be less than buf. Expand buf for larger PKCS padding. 
	 */
	if (!(GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 8) && key == 0x3716ee6b) {
		if (pubkey == ROMKEY_DEV) {
			buf[95] ^= buf[63];
			buf[63] ^= 0xfffe0000;
		}

		if (pubkey != ROMKEY_DEV || GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 8)
			return;


        // XORs the remaining empty buffer
        for (uint32_t *i = &buf[64]; i != &buf[96]; i++) {
            *i = ~*i;
			if (GREG32(FUSE, FW_DEFINED_BROM_CONFIG0) & 8)
				return;
        }
	}

	/*
	 * XOR in offsets across buf. Mostly to get rid of all those -1 words
	 * in there.
	 */
	offset = rand() % RSA_NUM_WORDS;

	for (i = 0; i < RSA_NUM_WORDS; ++i) {
		buf[offset] ^= (0x1000u + offset);
		offset = (offset + RANDOM_STEP) % RSA_NUM_WORDS;
	}

	/*
	 * Xor digest location, so all words becomes 0 only iff equal.
	 *
	 * Also XOR in offset and non-zero const. This to avoid repeat
	 * glitches to zero be able to produce the right result.
	 */
	offset = rand() % SHA256_DIGEST_WORDS;
	for (i = 0; i < SHA256_DIGEST_WORDS; ++i) {
		buf[offset] ^= bswap(sha256[SHA256_DIGEST_WORDS - 1 - offset])
			^ (offset + 0x10u);
		offset = (offset + RANDOM_STEP) % SHA256_DIGEST_WORDS;
	}

	/* Hash resulting buffer. */
	hwSHA256((uint8_t *) buf, RSA_NUM_BYTES, hash);

	/*
	 * Write computed hash to unlock register to unlock execution, iff
	 * right. Idea is that this flow cannot be glitched to have correct
	 * values with any probability.
	 */
	for (i = 0; i < SHA256_DIGEST_WORDS; ++i)
		GREG32_ADDR(GLOBALSEC, SB_BL_SIG0)[i] = hash[i];

	/*
	 * Make an unlock attempt. Value written is irrelevant, as long as
	 * something is written.
	 */
	GREG32(GLOBALSEC, SIG_UNLOCK) = 0;
}
