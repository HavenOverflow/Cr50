/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "debug_printf.h"
#include "setup.h"
#include "rom_flash.h"

static int _flash_error(void)
{
	int retval = GREG32(FLASH, FSH_ERROR);

	if (!retval)
		return 0;

	retval = GREG32(FLASH, FSH_ERROR);

	return retval;
}

/* Verify the flash controller is awake. */
static int _check_flash_is_awake(void)
{
	int retval;

	GREG32(FLASH, FSH_TRANS) = 0xFFFFFFFF;
	retval = GREG32(FLASH, FSH_TRANS);
	GREG32(FLASH, FSH_TRANS) =  0x0;

	if (retval == 0)
		return E_FL_NOT_AWAKE;

	return 0;
}

/* Send cmd to flash controller. */
static int _flash_cmd(uint32_t fidx, uint32_t cmd)
{
	int cnt, retval;

	/* Activate controller. */
	GREG32(FLASH, FSH_PE_EN) = FSH_OP_ENABLE;
	GREG32_ADDR(FLASH, FSH_PE_CONTROL0)[fidx] = cmd;

	/* wait on FSH_PE_EN (means the operation started) */
	cnt = 500;  /* TODO(mschilder): pick sane value. */

	do {
		retval = GREG32(FLASH, FSH_PE_EN);
	} while (retval && cnt--);

	if (retval)
		return E_FL_TIMEOUT;

	/*
	 * wait 100us before checking FSH_PE_CONTROL (means the operation
	 * ended)
	 */
	cnt = 1000000;
	do {
		retval = GREG32_ADDR(FLASH, FSH_PE_CONTROL0)[fidx];
	} while (retval && --cnt);

	if (retval) {
		GREG32_ADDR(FLASH, FSH_PE_CONTROL0)[fidx] = 0;
		return E_FL_TIMEOUT;
	}

	return 0;
}

int flash_erase(uint32_t fidx, uint32_t page)
{
    uint32_t check, i_1, i, result;
    GREG32(FLASH, FSH_TRANS) = 0xffffffff;
    check = GREG32(FLASH, FSH_TRANS);
    GREG32(FLASH, FSH_TRANS) = 0;

    if (check != 0x3fffff)
        return 0x3fffff ^ check;

    GREG32(FLASH, FSH_TRANS) = (page << 9) | (0 << 0x10 & 0x10000);
    i_1 = 0x2d;

    do {
        result = _flash_cmd(fidx, FSH_OP_ERASE);

        if (result || !GREG32(FLASH, FSH_ERROR))
            return result;

        i = i_1;
        i_1--;
    } while (i != 1);

    return 8;
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
	int retval;

	/* Make sure flash controller is awake. */
	retval = _check_flash_is_awake();
	if (retval)
		return retval;

	GWRITE_FIELD(FLASH, FSH_TRANS, OFFSET, offset);
	GWRITE_FIELD(FLASH, FSH_TRANS, MAINB, 1);
	GWRITE_FIELD(FLASH, FSH_TRANS, SIZE, 1);

	retval = _flash_cmd(1, FSH_OP_READ);
	if (retval)
		return retval;

	if (_flash_error())
		return E_FL_ERROR;

	if (!retval)
		*dst = GREG32(FLASH, FSH_DOUT_VAL1);

	return retval;
}