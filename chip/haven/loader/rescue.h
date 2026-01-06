/* Copyright 2015 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 * Decompiled by Hannah and re-integrated with the original software.
 */

#ifndef __EC_CHIP_G_LOADER_RESCUE_H
#define __EC_CHIP_G_LOADER_RESCUE_H

#include "setup.h"

struct rescue_pkt {
	uint8_t hash[SHA256_DIGEST_SIZE];
	uint32_t frame_num;
	uint32_t flash_offset;
	uint8_t data[0];
};

enum rescue_err {
	RESCUE_BAD_MAGIC = 1,
	RESCUE_OVERSIZED_IMAGE = 2,
	RESCUE_BAD_FLASH_OFFSET = 3,
	RESCUE_UNDERSIZED_IMAGE = 4,
	RESCUE_UNKNOWN_KEY = 5,
	RESCUE_ERASE_FAILURE = 6,
	RESCUE_ERASE_VERIFY_FAILURE = 7,
	RESCUE_ERR_EIGHT = 8,
	RESCUE_UNALIGNED_WRITE = 9,
	RESCUE_WRITE_HEADER_FAILURE = 10,
	RESCUE_OVERFLOW = 11,
	RESCUE_WRITE_BLOCK_FAILURE = 12,
	RESCUE_WRITE_LAST_FAILURE = 15
};

void rescue_sync(int enabled);

int rescue(void *hashes);

int check_engage_rescue(int allowed, void *hashes);

#endif