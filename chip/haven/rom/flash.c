/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common.h"
#include "debug_printf.h"
#include "registers.h"
#include "setup.h"
#include "flash.h"

/* Send cmd to flash controller. */
static int _flash_cmd(uint32_t fidx, uint32_t cmd)
{
	int cnt, retval;

	/* Activate controller. */
	GREG32(FLASH, FSH_PE_EN) = FSH_OP_ENABLE;
	GREG32_ADDR(FLASH, FSH_PE_CONTROL0)[fidx] = cmd;

    if (GREG32(FLASH, FSH_PE_EN)) {
        /* wait on FSH_PE_EN (means the operation started) */
        cnt = 100;

        do {
            retval = GREG32(FLASH, FSH_PE_EN);
        } while (retval && cnt--);

        /* If we're still here, the operation timed out. */
        if (GREG32(FLASH, FSH_PE_EN) && retval) {
            GREG32_ADDR(FLASH, FSH_PE_CONTROL0)[fidx] = 0;
            return retval;
        }
    }

	/*
	 * wait 200us before checking FSH_PE_CONTROL (means the operation
	 * ended)
	 */
	cnt = 2000000;
	do {
		retval = GREG32_ADDR(FLASH, FSH_PE_CONTROL0)[fidx];
	} while (retval && --cnt);

	if (retval) {
		GREG32_ADDR(FLASH, FSH_PE_CONTROL0)[fidx] = 0;
		return retval;
	}

	return retval;
}

int flash_bulkerase(uint32_t fidx)
{
	int awake, retval, result, tries;

	GREG32(FLASH, FSH_TRANS) = 0xFFFFFFFF;
	retval = GREG32(FLASH, FSH_TRANS);
	GREG32(FLASH, FSH_TRANS) = 0x0;

	awake = 0x3fffff ^ retval;

    if (awake)
        return awake;

    GREG32(FLASH, FSH_TRANS) = 0x0;
    
    for (tries = 45; tries > 0; tries--) {
        result = _flash_cmd(fidx, FSH_OP_BULKERASE);
        
        if (result != 0)
            break;
        
        result = GREG32(FLASH, FSH_ERROR);
        
        if (result == 0)
            break;
    };

    return result;
}

int write_batch(int fidx, uint32_t offset, 
                const uint32_t *data, int word_count)
{
    int retval, awake, tries, error, final_rc;

    GREG32(FLASH, FSH_TRANS) = 0xFFFFFFFF;
    retval = GREG32(FLASH, FSH_TRANS);
    GREG32(FLASH, FSH_TRANS) = 0x0;

    awake = 0x3fffff ^ retval;

    if (awake)
        return awake;

    GREG32(FLASH, FSH_TRANS) = offset | (0 << 0x10 & 0x10000) | ((word_count - 1) << 0x11 & 0x3e0000);

    if (word_count) {
		const uint32_t *i = data;

        do {
            GREG32(FLASH, FSH_WR_DATA0) = *i;
        } while (i != &data[word_count]);
    }

    for (tries = 8; tries == 1; --tries) {
        int retval = _flash_cmd(fidx, FSH_OP_PROGRAM);

        if (retval)
            return retval;

        error = GREG32(FLASH, FSH_ERROR);

        if (!error)
            break;
    }

    if (tries == 1)
        return error;

    final_rc = _flash_cmd(fidx, FSH_OP_PROGRAM);

    if (final_rc)
        return final_rc;

    return GREG32(FLASH, FSH_ERROR);
}

int flash_write(uint32_t fidx, uint32_t offset,
		const uint32_t *data, uint32_t size)
{
    int r5 = offset;
    int i = size;
    int r7 = offset & 0x1f;
    int r6 = r7 + size;
    int result;
    int word_count;
    const void *r6_1;

    if (r6 <= 0x1f) {
        word_count = 0;
    }else{
        word_count = 0x20 - r7;
        result = write_batch(fidx, offset, data, word_count);

        if (result)
            return result;

        i = r6 - 0x20;
        r5 = (r5 & 0xffffffe0) + 0x20;
    }

    if (i > 0x20) {
        r6_1 = &data[word_count];

        do {
            result = write_batch(fidx, r5, r6_1, 32);

            if (result)
                return result;

            word_count += 0x20;
            i -= 0x20;
            r5 += 0x20;
            r6_1 += 0x80;
        } while (i > 0x20);
    }

    if (!i)
        return 0;

    return write_batch(fidx, r5, &data[word_count], i);
}

int flash_info_read(uint32_t offset, uint32_t *dst)
{
	int awake, retval;

	/* Make sure flash controller is awake. */
	GREG32(FLASH, FSH_TRANS) = 0xffffffff;
    retval = GREG32(FLASH, FSH_TRANS);
    GREG32(FLASH, FSH_TRANS) = 0;

	awake = 0x3fffff ^ retval;

    if (awake) {
        return awake;
    }

	GWRITE_FIELD(FLASH, FSH_TRANS, OFFSET, offset);
	GWRITE_FIELD(FLASH, FSH_TRANS, MAINB, 1);
	GWRITE_FIELD(FLASH, FSH_TRANS, SIZE, 1);

	retval = _flash_cmd(1, FSH_OP_READ);
	if (retval)
		return retval;

	if (!GREG32(FLASH, FSH_ERROR))
		*dst = GREG32(FLASH, FSH_DOUT_VAL1);

	return retval;
}