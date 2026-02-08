/* Copyright 2015 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common.h"
#include "debug_printf.h"
#include "registers.h"
#include "setup.h"

static void _sha_write(const void *data, size_t n)
{
	const uint8_t *bp = (const uint8_t *)data;
	const uint32_t *wp;

	while (n && ((uint32_t)bp & 3)) {  /* Feed unaligned start bytes. */
		*((uint8_t *)GREG32_ADDR(KEYMGR, SHA_INPUT_FIFO)) = *bp++;
		n -= 1;
	}

	wp = (uint32_t *)bp;
	while (n >= 32) { /* Feed groups of aligned words. */
		GREG32(KEYMGR, SHA_INPUT_FIFO) = *wp++;
		GREG32(KEYMGR, SHA_INPUT_FIFO) = *wp++;
		GREG32(KEYMGR, SHA_INPUT_FIFO) = *wp++;
		GREG32(KEYMGR, SHA_INPUT_FIFO) = *wp++;
		GREG32(KEYMGR, SHA_INPUT_FIFO) = *wp++;
		GREG32(KEYMGR, SHA_INPUT_FIFO) = *wp++;
		GREG32(KEYMGR, SHA_INPUT_FIFO) = *wp++;
		GREG32(KEYMGR, SHA_INPUT_FIFO) = *wp++;
		n -= 32;
	}

	while (n >= 4) {  /* Feed individual aligned words. */
		GREG32(KEYMGR, SHA_INPUT_FIFO) = *wp++;
		n -= 4;
	}

	bp = (uint8_t *)wp;
	while (n) {  /* Feed remaing bytes. */
		*((uint8_t *)GREG32_ADDR(KEYMGR, SHA_INPUT_FIFO))  = *bp++;
		n -= 1;
	}
}

static void _sha_wait(uint32_t *digest)
{
	int i;

	/*
	 * Wait for result. TODO: what harm does glitching do? Read out
	 * non-digest? Old digest?
	 */
	while (!GREG32(KEYMGR, SHA_ITOP))
		;

	/* Read out final digest. */
	digest[0] = GREG32(KEYMGR, SHA_STS_H0);
	digest[1] = GREG32(KEYMGR, SHA_STS_H1);
	digest[2] = GREG32(KEYMGR, SHA_STS_H2);
	digest[3] = GREG32(KEYMGR, SHA_STS_H3);
	digest[4] = GREG32(KEYMGR, SHA_STS_H4);
	digest[5] = GREG32(KEYMGR, SHA_STS_H5);
	digest[6] = GREG32(KEYMGR, SHA_STS_H6);
	digest[7] = GREG32(KEYMGR, SHA_STS_H7);
}

void hwSHA256(const void *data, size_t n, uint32_t *digest)
{
	GREG32(KEYMGR, SHA_ITOP) = 0;  /* Clear status. */

	// something something

	GREG32(KEYMGR, SHA_CFG_MSGLEN_LO) =  n;
	GREG32(KEYMGR, SHA_CFG_MSGLEN_HI) = 0;

	GREG32(KEYMGR, SHA_CFG_EN) = 1;
	GREG32(KEYMGR, SHA_TRIG) = 1;

	_sha_write(data, n);
	_sha_wait(digest);
}

void hw_sha256_init(void)
{
	GREG32(KEYMGR, SHA_ITOP) = 1;
	// something something
}

void hw_sha256_update(void)
{

}

void hw_sha256_update(const uint8_t *data, size_t n)
{
	if (!len)
		return;

	_sha_write(data, n);
}

void hw_sha256_final(uint32_t *out)
{
	GREG32(KEYMGR, SHA_TRIG) = 8;
	_sha_wait(out);
}